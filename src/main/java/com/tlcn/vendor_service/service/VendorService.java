package com.tlcn.vendor_service.service;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tlcn.vendor_service.dto.*;
import com.tlcn.vendor_service.enums.VendorStatus;
import com.tlcn.vendor_service.exception.BusinessException;
import com.tlcn.vendor_service.model.Vendor;
import com.tlcn.vendor_service.repository.VendorRepository;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.AccessTokenResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.HexFormat;

@Slf4j
@Service
public class VendorService {

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private VendorRepository vendorRepository;

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    @Autowired
    private Cloudinary cloudinary;

    @Autowired
    private KeycloakService keycloakService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private Keycloak keycloakAdmin;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${cloudinary.folder:vendors}")
    private String cloudinaryFolder;

    // ---------- TTL / Limits (minutes unless specified) ----------
    private static final long TTL_OTP_MINUTES = 3;          
    private static final long TTL_INIT_TOKEN_MINUTES = 15; 
    private static final long TTL_VERIFY_TOKEN_MINUTES = 15; 
    private static final int MAX_LOGIN_ATTEMPTS = 5;
    private static final long LOGIN_ATTEMPTS_WINDOW_MINUTES = 5;
    private static final int MAX_OTP_RESEND_ATTEMPTS = 3;
    private static final long OTP_RESEND_WINDOW_MINUTES = 15;

    private final SecureRandom secureRandom = new SecureRandom();

    // ---------- Redis key helpers ----------
    private String keyInit(String initToken) { return "vendor:init:" + initToken; }
    private String keyEmailInit(String email) { return "vendor:email:init:" + email; }
    private String keyOtp(String email) { return "vendor:otp:" + email; } 
    private String keyVerify(String email) { return "vendor:verify:" + email; } 
    private String keySession(String sessionId) { return "vendor:session:" + sessionId; }
    private String keyAccessMap(String accessTokenHash) { return "vendor:access:map:" + accessTokenHash; } 
    private String keyBlacklist(String accessTokenHash) { return "vendor:token:blacklist:" + accessTokenHash; }

    // reset password keys
    private String keyResetOtpMap(String otp) { return "vendor:reset:otp-map:" + otp; } 
    private String keyResetEmailMap(String email) { return "vendor:reset:email-map:" + email; } 

    // resend counters
    private String keyResendCounter(String prefix, String email) { return "vendor:" + prefix + ":resend-count:" + email; }

    // login attempts
    private String keyLoginAttempt(String username) { return "vendor:login:attempts:" + username; }

    // ---------- Utilities ----------
    private String generateOtp() {
        int number = secureRandom.nextInt(1_000_000);
        return String.format("%06d", number);
    }

    private void validateRegistrationRequest(VendorRequest request) {
        if (request.getPassword() == null || request.getPassword().length() < 8) {
            log.warn("Invalid password length");
            throw new BusinessException("INVALID_PASSWORD", "Password must be at least 8 characters");
        }

        RealmResource realmResource = keycloakAdmin.realm(realm);
        if (!realmResource.users().search(request.getUsername(), true).isEmpty() ||
            !realmResource.users().search(request.getEmail(), true).isEmpty()) {
            log.warn("Username or email already exists in Keycloak: username={}, email={}", request.getUsername(), request.getEmail());
            throw new BusinessException("Username or email already exists in Keycloak");
        }
    }

    private void validateLogo(MultipartFile logo) {
        String contentType = logo.getContentType();
        if (!Arrays.asList("image/jpeg", "image/png").contains(contentType)) {
            log.warn("Invalid logo format: {}", contentType);
            throw new BusinessException("Logo must be JPEG or PNG");
        }
        long maxSize = 2 * 1024 * 1024; // 2MB
        if (logo.getSize() > maxSize) {
            log.warn("Logo size exceeds limit: {} bytes", logo.getSize());
            throw new BusinessException("Logo size must not exceed 2MB");
        }
    }

    private void checkResendLimit(String email, String prefix) {
        String resendKey = keyResendCounter(prefix, email);
        Long attempts = redisTemplate.opsForValue().increment(resendKey, 1L);
        if (attempts == null) attempts = 1L;
        if (attempts == 1) {
            redisTemplate.expire(resendKey, OTP_RESEND_WINDOW_MINUTES, TimeUnit.MINUTES);
        }
        if (attempts > MAX_OTP_RESEND_ATTEMPTS) {
            log.warn("Too many resend attempts for email: {}", email);
            throw new BusinessException("Too many resend attempts. Please try again after " + OTP_RESEND_WINDOW_MINUTES + " minutes.");
        }
    }

    // ---------- Registration flow ----------

    /**
     * Initialize registration.
     * Stores request JSON + optional logo public id and sends OTP to email.
     * Returns initToken.
     */
    @Transactional
    public String registerInit(VendorRequest request, MultipartFile logo) {
        if (vendorRepository.existsByUsernameOrEmail(request.getUsername(), request.getEmail())) {
            log.warn("Username or email already exists: username={}, email={}", request.getUsername(), request.getEmail());
            throw new BusinessException("Username or email already exists");
        }

        validateRegistrationRequest(request); // Đảm bảo kiểm tra trong Keycloak

        String initToken = UUID.randomUUID().toString();
        String initKey = keyInit(initToken);
        String logoPublicId = null;

        try {
            String requestJson = objectMapper.writeValueAsString(request);
            redisTemplate.opsForHash().put(initKey, "request", requestJson);

            if (logo != null && !logo.isEmpty()) {
                validateLogo(logo);
                try {
                    Map uploadResult = cloudinary.uploader().upload(logo.getBytes(), ObjectUtils.asMap("folder", cloudinaryFolder));
                    logoPublicId = (String) uploadResult.get("public_id");
                    redisTemplate.opsForHash().put(initKey, "logoPublicId", logoPublicId);
                } catch (IOException e) {
                    log.error("Failed to upload logo to Cloudinary: {}", e.getMessage());
                    throw new BusinessException("Failed to upload logo: " + e.getMessage());
                }
            }

            // set init key TTL and map email -> initToken
            redisTemplate.expire(initKey, TTL_INIT_TOKEN_MINUTES, TimeUnit.MINUTES);
            redisTemplate.opsForValue().set(keyEmailInit(request.getEmail()), initToken, TTL_INIT_TOKEN_MINUTES, TimeUnit.MINUTES);

            // create OTP for registration and send email
            String otp = generateOtp();
            redisTemplate.opsForValue().set(keyOtp(request.getEmail()), otp, TTL_OTP_MINUTES, TimeUnit.MINUTES);
            emailService.sendRegistrationOtp(request.getEmail(), otp);

            log.info("Registration initialized: email={}, initToken={}", request.getEmail(), initToken);
            return initToken;
        } catch (Exception e) {
            // cleanup cloudinary if uploaded
            if (logoPublicId != null) {
                try {
                    cloudinary.uploader().destroy(logoPublicId, ObjectUtils.emptyMap());
                } catch (IOException ex) {
                    log.error("Failed to delete logo from Cloudinary during cleanup: {}", ex.getMessage());
                }
            }
            // cleanup redis
            redisTemplate.delete(initKey);
            redisTemplate.delete(keyEmailInit(request.getEmail()));
            redisTemplate.delete(keyOtp(request.getEmail()));
            log.error("Registration init failed: {}", e.getMessage());
            throw new BusinessException("Registration init failed: " + e.getMessage());
        }
    }

    /**
     * Resend OTP for registration. Requires correct initToken for that email.
     */
    public void resendOtp(String email, String initToken) {
        String storedToken = redisTemplate.opsForValue().get(keyEmailInit(email));
        if (storedToken == null || !storedToken.equals(initToken)) {
            log.warn("Invalid or missing init token for email: {}", email);
            throw new BusinessException("Invalid init token");
        }

        checkResendLimit(email, "otp");

        String otp = generateOtp();
        redisTemplate.opsForValue().set(keyOtp(email), otp, TTL_OTP_MINUTES, TimeUnit.MINUTES);
        emailService.sendRegistrationOtp(email, otp);
        log.info("OTP resent: email={}", email);
    }

    /**
     * Verify registration OTP. Returns verification token or auto-registers (returns Vendor).
     */
    public Object verifyOtp(String email, String otp, String initToken, boolean autoRegister) {
        String storedOtp = redisTemplate.opsForValue().get(keyOtp(email));
        if (storedOtp == null || !storedOtp.equals(otp)) {
            log.warn("Invalid OTP for email: {}", email);
            throw new BusinessException("Invalid OTP");
        }

        String storedInitToken = redisTemplate.opsForValue().get(keyEmailInit(email));
        if (storedInitToken == null || !storedInitToken.equals(initToken)) {
            log.warn("Invalid init token for email: {}", email);
            throw new BusinessException("Invalid init token");
        }

        // delete OTP after successful verification to prevent reuse
        redisTemplate.delete(keyOtp(email));

        String verificationToken = UUID.randomUUID().toString();
        redisTemplate.opsForValue().set(keyVerify(email), verificationToken, TTL_VERIFY_TOKEN_MINUTES, TimeUnit.MINUTES);

        if (autoRegister) {
            Vendor vendor = registerVendor(email, verificationToken);
            log.info("OTP verified and vendor registered: email={}", email);
            return vendor;
        }

        log.info("OTP verified: email={}, verificationToken={}", email, verificationToken);
        return verificationToken;
    }

    /**
     * Finalize registration (create vendor). Requires verificationToken.
     */
    @Transactional
    public Vendor registerVendor(String email, String verificationToken) {
        String storedToken = redisTemplate.opsForValue().get(keyVerify(email));
        if (storedToken == null || !storedToken.equals(verificationToken)) {
            log.warn("Invalid verification token for email: {}", email);
            throw new BusinessException("Invalid verification token");
        }

        String initToken = redisTemplate.opsForValue().get(keyEmailInit(email));
        if (initToken == null) {
            log.warn("Missing init token for email during register: {}", email);
            throw new BusinessException("Registration init expired or missing");
        }
        String initKey = keyInit(initToken);

        try {
            String requestJson = (String) redisTemplate.opsForHash().get(initKey, "request");
            if (requestJson == null) {
                log.warn("Registration request payload missing for initKey: {}", initKey);
                throw new BusinessException("Registration data missing");
            }
            
            VendorRequest request = objectMapper.readValue(requestJson, VendorRequest.class);            
            String logoPublicId = (String) redisTemplate.opsForHash().get(initKey, "logoPublicId");
            String keycloakId = keycloakService.createUser(request.getUsername(), request.getEmail(), request.getFirstName(), request.getLastName(), request.getPassword());

            Vendor vendor = new Vendor();
            vendor.setUsername(request.getUsername());
            vendor.setEmail(request.getEmail());
            vendor.setFirstName(request.getFirstName());
            vendor.setLastName(request.getLastName());
            vendor.setShopName(request.getShopName());
            vendor.setPhone(request.getPhone());
            vendor.setBankAccount(request.getBankAccount());
            vendor.setPaymentInfo(request.getPaymentInfo());
            vendor.setStatus(VendorStatus.ACTIVE);
            vendor.setCreatedAt(LocalDateTime.now());
            vendor.setKeycloakId(keycloakId);
            if (logoPublicId != null) {
                vendor.setLogoPublicId(logoPublicId);
                vendor.setLogoUrl((String) cloudinary.url().generate(logoPublicId));
            }

            Vendor savedVendor = vendorRepository.save(vendor);

            // cleanup all registration related keys
            redisTemplate.delete(initKey);
            redisTemplate.delete(keyVerify(email));
            redisTemplate.delete(keyEmailInit(email));
            redisTemplate.delete(keyOtp(email));

            log.info("Vendor registered: email={}, keycloakId={}", email, savedVendor.getKeycloakId());
            return savedVendor;
        } catch (Exception e) {
            log.error("Registration failed for email: {}, error: {}", email, e.getMessage());
            throw new BusinessException("Registration failed: " + e.getMessage());
        }
    }

    // ---------- Authentication & Session ----------

    /**
     * Login: authenticate via Keycloak, create short sessionId stored in Redis,
     * map hashed access token to sessionId (avoid using full token as key).
     */
    public LoginResponse login(String username, String password) {
        String loginAttemptKey = keyLoginAttempt(username);
        Long attempts = redisTemplate.opsForValue().increment(loginAttemptKey, 1L);
        if (attempts == null) attempts = 1L;
        if (attempts == 1) {
            redisTemplate.expire(loginAttemptKey, LOGIN_ATTEMPTS_WINDOW_MINUTES, TimeUnit.MINUTES);
        }
        if (attempts > MAX_LOGIN_ATTEMPTS) {
            log.warn("Too many login attempts for username: {}", username);
            throw new BusinessException("Too many login attempts. Please try again later.");
        }

        try {
            AccessTokenResponse token = keycloakService.authenticateUser(username, password);
            Vendor vendor = vendorRepository.findByUsername(username)
                    .orElseThrow(() -> new BusinessException("Vendor not found after authentication"));

            // CHECK STATUS: Prevent login if vendor is not ACTIVE
            if (vendor.getStatus() != VendorStatus.ACTIVE) {
                log.warn("Login denied for vendor: {} - Status: {}", username, vendor.getStatus());
                throw new BusinessException("Account is " + vendor.getStatus().name().toLowerCase() + ". Contact support.");
            }

            // create a sessionId and store minimal info. Use token.getExpiresIn() to set TTL.
            String sessionId = UUID.randomUUID().toString();
            String sessionKey = keySession(sessionId);

            Map<String, String> sessionData = new HashMap<>();
            sessionData.put("keycloakId", vendor.getKeycloakId());
            sessionData.put("username", username);
            // NOTE: Tokens are not stored in session for security - only identifiers

            redisTemplate.opsForHash().putAll(sessionKey, sessionData);
            long expiresIn = token.getExpiresIn() > 0 ? token.getExpiresIn() : 300L;
            redisTemplate.expire(sessionKey, expiresIn, TimeUnit.SECONDS);

            // map hash(accessToken) -> sessionId so we can lookup session by access token (without storing raw token as key)
            if (token.getToken() != null) {
                String tokenHash = hashToken(token.getToken());
                redisTemplate.opsForValue().set(keyAccessMap(tokenHash), sessionId, expiresIn, TimeUnit.SECONDS);
            }

            // clear login attempts counter
            redisTemplate.delete(loginAttemptKey);
            log.info("Login successful: username={}", username);
            return com.tlcn.vendor_service.dto.LoginResponse.builder()
                    .accessToken(token.getToken())
                    .refreshToken(token.getRefreshToken())
                    .tokenType(token.getTokenType())
                    .expiresIn(token.getExpiresIn())
                    .scope(token.getScope())
                    .build();
        } catch (Exception e) {
            log.warn("Login failed for username: {}, error: {}", username, e.getMessage());
            throw new BusinessException("Invalid username or password");
        }
    }

    /**
     * Logout: blacklist access token by its hash, call Keycloak logout by refresh token,
     * and cleanup session mapping.
     * Controller provides raw accessToken & refreshToken.
     */
    public void logout(String accessToken, String refreshToken) {
        if (accessToken == null) {
            log.warn("Access token is missing");
            throw new BusinessException("Access token is required");
        }

        // Hash token for security - never use raw token as Redis key
        String tokenHash = hashToken(accessToken);
        String accessMapKey = keyAccessMap(tokenHash);
        String sessionId = redisTemplate.opsForValue().get(accessMapKey);

        // determine TTL to set blacklist expiry
        Long ttlSeconds = null;
        if (sessionId != null) {
            ttlSeconds = redisTemplate.getExpire(keySession(sessionId), TimeUnit.SECONDS);
        }
        if (ttlSeconds == null || ttlSeconds <= 0) {
            ttlSeconds = 300L; // default 5 minutes
        }

        try {
            // blacklist by hash so raw token isn't being used as key
            redisTemplate.opsForValue().set(keyBlacklist(tokenHash), "blacklisted", ttlSeconds, TimeUnit.SECONDS);

            // if refreshToken is present, logout from Keycloak
            if (refreshToken != null) {
                try {
                    keycloakService.logoutUser(accessToken, refreshToken);
                } catch (Exception e) {
                    log.warn("Keycloak logout failed: {}", e.getMessage());
                    // don't fail whole request because of Keycloak logout problem
                }
            }

            // cleanup session and token mapping
            if (sessionId != null) {
                redisTemplate.delete(keySession(sessionId));
                redisTemplate.delete(accessMapKey);
            }

            log.info("Logout successful for token hash: {}...", tokenHash.substring(0, 10));
        } catch (Exception e) {
            log.error("Logout failed: {}", e.getMessage());
            throw new BusinessException("Logout failed: " + e.getMessage());
        }
    }

    // ---------- Forget Password (Reset) flow ----------

    /**
     * Send password reset email with token
     */
    public void forgetPassword(ForgetPasswordRequest request) {
        Vendor vendor = vendorRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> {
                    log.warn("Email not found for forget password: {}", request.getEmail());
                    throw new BusinessException("Email not found");
                });

        checkResendLimit(request.getEmail(), "reset");

        // Generate reset token
        String resetToken = UUID.randomUUID().toString();
        tokenService.storeResetToken(resetToken, request.getEmail());

        emailService.sendPasswordResetEmail(request.getEmail(), vendor.getShopName(), resetToken);
        log.info("Password reset token sent: email={}", request.getEmail());
    }

    /**
     * Resend password reset OTP - issues new OTP and invalidates the old one.
     */
    public void resendForgetPasswordOtp(String email) {
        Vendor vendor = vendorRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("Email not found for password reset resend: {}", email);
                    throw new BusinessException("Email not found");
                });

        checkResendLimit(email, "reset");

        String emailKey = keyResetEmailMap(email);
        String oldOtp = redisTemplate.opsForValue().get(emailKey);
        if (oldOtp != null) {
            redisTemplate.delete(keyResetOtpMap(oldOtp));
        }

        String otp = generateOtp();
        redisTemplate.opsForValue().set(keyResetOtpMap(otp), email, TTL_OTP_MINUTES, TimeUnit.MINUTES);
        redisTemplate.opsForValue().set(emailKey, otp, TTL_OTP_MINUTES, TimeUnit.MINUTES);

        emailService.sendPasswordResetOtp(email, otp);
        log.info("Resend password reset OTP: email={}", email);
    }

    /**
     * Reset password using token
     */
    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        // Get email from reset token
        String email = tokenService.getResetTokenEmail(request.getToken());
        if (email == null) {
            log.warn("Invalid or expired reset token");
            throw new BusinessException("Invalid or expired reset token");
        }

        Vendor vendor = vendorRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("Vendor not found for email: {}", email);
                    throw new BusinessException("Vendor not found");
                });

        try {
            // update password in Keycloak
            keycloakService.updatePassword(vendor.getKeycloakId(), request.getPassword());
            tokenService.removeResetToken(request.getToken());

            emailService.sendPasswordChangedNotification(email, vendor.getShopName());
            log.info("Password reset successful: email={}", email);
        } catch (Exception e) {
            log.error("Password reset failed: {}", e.getMessage());
            throw new BusinessException("Password reset failed: " + e.getMessage());
        }
    }

    // ---------- Profile & Account updates (unchanged logic but consolidated) ----------

    @Transactional
    public Vendor updateProfile(String keycloakId, VendorUpdateProfileRequest request, MultipartFile logo) {
        Vendor vendor = vendorRepository.findByKeycloakId(keycloakId)
                .orElseThrow(() -> {
                    log.warn("Vendor not found: keycloakId={}", keycloakId);
                    return new BusinessException("Vendor not found");
                });

        if (request.getFirstName() != null) vendor.setFirstName(request.getFirstName());
        if (request.getLastName() != null) vendor.setLastName(request.getLastName());
        if (request.getShopName() != null) vendor.setShopName(request.getShopName());
        if (request.getPhone() != null) vendor.setPhone(request.getPhone());
        if (request.getBankAccount() != null) vendor.setBankAccount(request.getBankAccount());
        if (request.getPaymentInfo() != null) vendor.setPaymentInfo(request.getPaymentInfo());

        if (logo != null && !logo.isEmpty()) {
            validateLogo(logo);
            if (vendor.getLogoPublicId() != null) {
                try {
                    cloudinary.uploader().destroy(vendor.getLogoPublicId(), ObjectUtils.emptyMap());
                } catch (Exception e) {
                    log.error("Failed to delete old logo from Cloudinary: {}", e.getMessage());
                }
            }
            try {
                Map uploadResult = cloudinary.uploader().upload(logo.getBytes(), ObjectUtils.asMap("folder", cloudinaryFolder));
                String publicId = (String) uploadResult.get("public_id");
                vendor.setLogoPublicId(publicId);
                vendor.setLogoUrl((String) cloudinary.url().generate(publicId));
            } catch (IOException e) {
                log.error("Failed to upload logo to Cloudinary: {}", e.getMessage());
                throw new BusinessException("Failed to upload logo: " + e.getMessage());
            }
        }

        Vendor updatedVendor = vendorRepository.save(vendor);

        if (vendor.getKeycloakId() != null && (request.getFirstName() != null || request.getLastName() != null)) {
            String currentFirstName = request.getFirstName() != null ? request.getFirstName() : vendor.getFirstName();
            String currentLastName = request.getLastName() != null ? request.getLastName() : vendor.getLastName();
            keycloakService.updateUser(vendor.getKeycloakId(),
                    vendor.getUsername(),
                    vendor.getEmail(),
                    currentFirstName,
                    currentLastName);
        }

        log.info("Profile updated: keycloakId={}", keycloakId);
        return updatedVendor;
    }

    @Transactional
    public Vendor updateAccount(String keycloakId, VendorUpdateAccountRequest request) {
        Vendor vendor = vendorRepository.findByKeycloakId(keycloakId)
                .orElseThrow(() -> {
                    log.warn("Vendor not found: keycloakId={}", keycloakId);
                    return new BusinessException("Vendor not found");
                });

        if (!keycloakService.verifyPassword(vendor.getUsername(), request.getCurrentPassword())) {
            log.warn("Incorrect current password for keycloakId={}", keycloakId);
            throw new BusinessException("Current password incorrect");
        }

        if (request.getUsername() != null && !request.getUsername().equals(vendor.getUsername())) {
            if (vendorRepository.existsByUsername(request.getUsername())) {
                log.warn("Username already exists: {}", request.getUsername());
                throw new BusinessException("Username already exists");
            }
            vendor.setUsername(request.getUsername());
        }

        if (request.getEmail() != null && !request.getEmail().equals(vendor.getEmail())) {
            if (vendorRepository.existsByEmail(request.getEmail())) {
                log.warn("Email already exists: {}", request.getEmail());
                throw new BusinessException("Email already exists");
            }
            vendor.setEmail(request.getEmail());
        }

        keycloakService.updateUser(vendor.getKeycloakId(), vendor.getUsername(), vendor.getEmail(), vendor.getFirstName(), vendor.getLastName());

        if (request.getPassword() != null) {
            keycloakService.updatePassword(vendor.getKeycloakId(), request.getPassword());
        }

        Vendor updatedVendor = vendorRepository.save(vendor);
        log.info("Account updated: keycloakId={}", keycloakId);
        return updatedVendor;
    }

    public Vendor getVendorByKeycloakId(String keycloakId) {
        Vendor vendor = vendorRepository.findByKeycloakId(keycloakId)
                .orElseThrow(() -> {
                    log.warn("Vendor not found: keycloakId={}", keycloakId);
                    return new BusinessException("Vendor not found");
                });
        return vendor;
    }

    // ---------- Token utilities ----------
    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new RuntimeException("Token hashing failed", e);
        }
    }
}
