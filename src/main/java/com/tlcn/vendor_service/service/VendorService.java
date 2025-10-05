package com.tlcn.vendor_service.service;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import com.tlcn.vendor_service.dto.*;
import com.tlcn.vendor_service.enums.VendorStatus;
import com.tlcn.vendor_service.model.Vendor;
import com.tlcn.vendor_service.repository.VendorRepository;
import org.keycloak.representations.AccessTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import jakarta.annotation.PostConstruct;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.Authenticator;
import jakarta.mail.PasswordAuthentication;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
public class VendorService {
    private static final Logger logger = LoggerFactory.getLogger(VendorService.class);

    @Autowired
    private VendorRepository vendorRepository;

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    @Autowired
    private Cloudinary cloudinary;

    @Autowired
    private KeycloakService keycloakService;

    @Value("${email.username}")
    private String emailUsername;

    @Value("${email.password}")
    private String emailPassword;

    @Value("${cloudinary.folder}")
    private String cloudinaryFolder = "vendors";

    private static final int MAX_LOGIN_ATTEMPTS = 5;
    private static final long LOGIN_ATTEMPTS_WINDOW = 5; // 5 minutes

    private Session mailSession;

    public static class CustomException extends RuntimeException {
        public CustomException(String message) {
            super(message);
        }
    }

    @PostConstruct
    public void init() {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");

        mailSession = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(emailUsername, emailPassword);
            }
        });
    }

    @Transactional
    public String registerInit(VendorRequest request, MultipartFile logo) {
        validateRegistrationRequest(request);
        if (vendorRepository.existsByUsernameOrEmail(request.getUsername(), request.getEmail())) {
            logger.warn("Username or email already exists: username={}, email={}", request.getUsername(), request.getEmail());
            throw new CustomException("Username or email already exists");
        }

        String initToken = UUID.randomUUID().toString();
        String initKey = "vendor:init:" + initToken;
        String logoPublicId = null;

        try {
            String requestJson = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(request);
            redisTemplate.opsForHash().put(initKey, "request", requestJson);

            if (logo != null && !logo.isEmpty()) {
                validateLogo(logo);
                try {
                    Map uploadResult = cloudinary.uploader().upload(logo.getBytes(), ObjectUtils.asMap("folder", cloudinaryFolder));
                    logoPublicId = (String) uploadResult.get("public_id");
                    redisTemplate.opsForHash().put(initKey, "logoPublicId", logoPublicId);
                } catch (IOException e) {
                    logger.error("Failed to upload logo to Cloudinary: {}", e.getMessage());
                    throw new CustomException("Failed to upload logo: " + e.getMessage());
                }
            }

            redisTemplate.expire(initKey, 10, TimeUnit.MINUTES);
            redisTemplate.opsForValue().set("vendor:email:init:" + request.getEmail(), initToken, 10, TimeUnit.MINUTES);

            String otp = generateOtp();
            redisTemplate.opsForValue().set("vendor:otp:" + request.getEmail(), otp, 5, TimeUnit.MINUTES);
            sendEmail(request.getEmail(), "OTP for Registration", "Your OTP is: " + otp);

            logger.info("Registration initialized: email={}, initToken={}", request.getEmail(), initToken);
            return initToken;
        } catch (Exception e) {
            if (logoPublicId != null) {
                try {
                    cloudinary.uploader().destroy(logoPublicId, ObjectUtils.emptyMap());
                } catch (IOException ex) {
                    logger.error("Failed to delete logo from Cloudinary during cleanup: {}", ex.getMessage());
                }
            }
            redisTemplate.delete(initKey);
            logger.error("Registration init failed: {}", e.getMessage());
            throw new CustomException("Registration init failed: " + e.getMessage());
        }
    }

    public void resendOtp(String email, String initToken) {
        String storedToken = redisTemplate.opsForValue().get("vendor:email:init:" + email);
        if (!initToken.equals(storedToken)) {
            logger.warn("Invalid init token for email: {}", email);
            throw new CustomException("Invalid init token");
        }

        String otp = generateOtp();
        redisTemplate.opsForValue().set("vendor:otp:" + email, otp, 5, TimeUnit.MINUTES);
        sendEmail(email, "OTP Resent", "Your new OTP is: " + otp);
        logger.info("OTP resent: email={}", email);
    }

    public Object verifyOtp(String email, String otp, String initToken, boolean autoRegister) {
        String storedOtp = redisTemplate.opsForValue().get("vendor:otp:" + email);
        if (!otp.equals(storedOtp)) {
            logger.warn("Invalid OTP for email: {}", email);
            throw new CustomException("Invalid OTP");
        }

        String initKey = "vendor:init:" + initToken;
        if (!redisTemplate.hasKey(initKey)) {
            logger.warn("Invalid init token for email: {}", email);
            throw new CustomException("Invalid init token");
        }

        String verificationToken = UUID.randomUUID().toString();
        redisTemplate.opsForValue().set("vendor:verify:" + email, verificationToken, 10, TimeUnit.MINUTES);

        if (autoRegister) {
            Vendor vendor = registerVendor(email, verificationToken);
            logger.info("OTP verified and vendor registered: email={}", email);
            return vendor;
        }
        logger.info("OTP verified: email={}, verificationToken={}", email, verificationToken);
        return verificationToken;
    }

    @Transactional
    public Vendor registerVendor(String email, String verificationToken) {
        String storedToken = redisTemplate.opsForValue().get("vendor:verify:" + email);
        if (!verificationToken.equals(storedToken)) {
            logger.warn("Invalid verification token for email: {}", email);
            throw new CustomException("Invalid verification token");
        }

        String initToken = redisTemplate.opsForValue().get("vendor:email:init:" + email);
        String initKey = "vendor:init:" + initToken;

        try {
            String requestJson = (String) redisTemplate.opsForHash().get(initKey, "request");
            VendorRequest request = new com.fasterxml.jackson.databind.ObjectMapper().readValue(requestJson, VendorRequest.class);
            String logoPublicId = (String) redisTemplate.opsForHash().get(initKey, "logoPublicId");

            String keycloakId = keycloakService.createUser(request.getUsername(), request.getEmail(), request.getPassword());

            Vendor vendor = new Vendor();
            vendor.setUsername(request.getUsername());
            vendor.setEmail(request.getEmail());
            vendor.setShopName(request.getShopName());
            vendor.setAddress(request.getAddress());
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
            redisTemplate.delete(initKey);
            redisTemplate.delete("vendor:verify:" + email);
            redisTemplate.delete("vendor:email:init:" + email);

            logger.info("Vendor registered: email={}, vendorId={}", email, savedVendor.getId());
            return savedVendor;
        } catch (Exception e) {
            logger.error("Registration failed for email: {}, error: {}", email, e.getMessage());
            throw new CustomException("Registration failed: " + e.getMessage());
        }
    }

    public AccessTokenResponse login(String username, String password) {
        String loginAttemptKey = "vendor:login:attempts:" + username;
        Long attempts = redisTemplate.opsForValue().increment(loginAttemptKey);

        if (attempts == 1) {
            redisTemplate.expire(loginAttemptKey, LOGIN_ATTEMPTS_WINDOW, TimeUnit.MINUTES);
        }

        if (attempts > MAX_LOGIN_ATTEMPTS) {
            logger.warn("Too many login attempts for username: {}", username);
            throw new CustomException("Too many login attempts. Please try again later.");
        }

        try {
            AccessTokenResponse token = keycloakService.authenticateUser(username, password);
            Vendor vendor = vendorRepository.findByUsername(username)
                    .orElseThrow(() -> new CustomException("Vendor not found after authentication"));
            redisTemplate.opsForHash().put("vendor:session:" + token.getToken(), "vendorId", vendor.getId().toString());
            redisTemplate.opsForHash().put("vendor:session:" + token.getToken(), "username", username);
            redisTemplate.opsForValue().set("vendor:token:expires:" + token.getToken(), String.valueOf(token.getExpiresIn()), token.getExpiresIn(), TimeUnit.SECONDS);
            redisTemplate.expire("vendor:session:" + token.getToken(), token.getExpiresIn(), TimeUnit.SECONDS);
            redisTemplate.delete(loginAttemptKey);
            logger.info("Login successful: username={}", username);
            return token;
        } catch (Exception e) {
            logger.warn("Login failed for username: {}, error: {}", username, e.getMessage());
            throw new CustomException("Invalid username or password");
        }
    }

    public void logout(String accessToken, String refreshToken) {
        if (accessToken == null || refreshToken == null) {
            logger.warn("Access token or refresh token is missing");
            throw new CustomException("Access token and refresh token are required");
        }

        try {
            // Blacklist access token in Redis until it expires
            long expiresInSeconds = 300; // Default to 5 minutes if token expiration not provided
            redisTemplate.opsForValue().set("vendor:token:blacklist:" + accessToken, "blacklisted", expiresInSeconds, TimeUnit.SECONDS);

            // Call Keycloak to logout user (invalidate refresh token)
            keycloakService.logoutUser(refreshToken);

            // Delete any session-related data in Redis (if applicable)
            redisTemplate.delete("vendor:session:" + accessToken);

            logger.info("Logout successful for access token: {}", accessToken);
        } catch (Exception e) {
            logger.error("Logout failed: {}", e.getMessage());
            throw new CustomException("Logout failed: " + e.getMessage());
        }
    }

    public void forgetPassword(ForgetPasswordRequest request) {
        Vendor vendor = vendorRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> {
                    logger.warn("Email not found for forget password: {}", request.getEmail());
                    return new CustomException("Email not found");
                });

        String otp = generateOtp();
        redisTemplate.opsForValue().set("vendor:reset:otp:" + request.getEmail(), otp, 5, TimeUnit.MINUTES);

        sendEmail(request.getEmail(), "Password Reset OTP", "Your OTP for password reset is: " + otp);
        logger.info("Password reset OTP sent: email={}", request.getEmail());
    }

    public void resetPassword(ResetPasswordRequest request) {
        String email = getEmailFromResetOtp(request.getOtp());
        if (email == null) {
            logger.warn("Invalid reset OTP");
            throw new CustomException("Invalid reset OTP");
        }

        Vendor vendor = vendorRepository.findByEmail(email)
                .orElseThrow(() -> {
                    logger.warn("Vendor not found for email: {}", email);
                    return new CustomException("Vendor not found");
                });

        keycloakService.updatePassword(vendor.getKeycloakId(), request.getPassword());
        redisTemplate.delete("vendor:reset:otp:" + email);
        logger.info("Password reset successful: email={}", email);
    }

    private String getEmailFromResetOtp(String otp) {
        Set<String> keys = redisTemplate.keys("vendor:reset:otp:*");
        for (String key : keys) {
            if (otp.equals(redisTemplate.opsForValue().get(key))) {
                return key.replace("vendor:reset:otp:", "");
            }
        }
        return null;
    }

    @Transactional
    public Vendor updateProfile(Long vendorId, VendorUpdateProfileRequest request, MultipartFile logo) {
        Vendor vendor = vendorRepository.findById(vendorId)
                .orElseThrow(() -> {
                    logger.warn("Vendor not found: vendorId={}", vendorId);
                    return new CustomException("Vendor not found");
                });

        if (request.getShopName() != null) vendor.setShopName(request.getShopName());
        if (request.getAddress() != null) vendor.setAddress(request.getAddress());
        if (request.getPhone() != null) vendor.setPhone(request.getPhone());
        if (request.getBankAccount() != null) vendor.setBankAccount(request.getBankAccount());
        if (request.getPaymentInfo() != null) vendor.setPaymentInfo(request.getPaymentInfo());

        if (logo != null && !logo.isEmpty()) {
            validateLogo(logo);
            if (vendor.getLogoPublicId() != null) {
                try {
                    cloudinary.uploader().destroy(vendor.getLogoPublicId(), ObjectUtils.emptyMap());
                } catch (IOException e) {
                    logger.error("Failed to delete old logo from Cloudinary: {}", e.getMessage());
                    throw new CustomException("Failed to delete old logo: " + e.getMessage());
                }
            }
            try {
                Map uploadResult = cloudinary.uploader().upload(logo.getBytes(), ObjectUtils.asMap("folder", cloudinaryFolder));
                String publicId = (String) uploadResult.get("public_id");
                vendor.setLogoPublicId(publicId);
                vendor.setLogoUrl((String) cloudinary.url().generate(publicId));
            } catch (IOException e) {
                logger.error("Failed to upload logo to Cloudinary: {}", e.getMessage());
                throw new CustomException("Failed to upload logo: " + e.getMessage());
            }
        }

        Vendor updatedVendor = vendorRepository.save(vendor);
        logger.info("Profile updated: vendorId={}", vendorId);
        return updatedVendor;
    }

    @Transactional
    public Vendor updateAccount(Long vendorId, VendorUpdateAccountRequest request) {
        Vendor vendor = vendorRepository.findById(vendorId)
                .orElseThrow(() -> {
                    logger.warn("Vendor not found: vendorId={}", vendorId);
                    return new CustomException("Vendor not found");
                });

        if (!keycloakService.verifyPassword(vendor.getUsername(), request.getCurrentPassword())) {
            logger.warn("Incorrect current password for vendorId={}", vendorId);
            throw new CustomException("Current password incorrect");
        }

        if (request.getUsername() != null && !request.getUsername().equals(vendor.getUsername())) {
            if (vendorRepository.existsByUsername(request.getUsername())) {
                logger.warn("Username already exists: {}", request.getUsername());
                throw new CustomException("Username already exists");
            }
            vendor.setUsername(request.getUsername());
        }

        if (request.getEmail() != null && !request.getEmail().equals(vendor.getEmail())) {
            if (vendorRepository.existsByEmail(request.getEmail())) {
                logger.warn("Email already exists: {}", request.getEmail());
                throw new CustomException("Email already exists");
            }
            vendor.setEmail(request.getEmail());
        }

        keycloakService.updateUser(vendor.getKeycloakId(), vendor.getUsername(), vendor.getEmail());

        if (request.getPassword() != null) {
            keycloakService.updatePassword(vendor.getKeycloakId(), request.getPassword());
        }

        Vendor updatedVendor = vendorRepository.save(vendor);
        logger.info("Account updated: vendorId={}", vendorId);
        return updatedVendor;
    }

    public Vendor getVendorById(Long vendorId) {
        Vendor vendor = vendorRepository.findById(vendorId)
                .orElseThrow(() -> {
                    logger.warn("Vendor not found: vendorId={}", vendorId);
                    return new CustomException("Vendor not found");
                });
        return vendor;
    }

    private void validateRegistrationRequest(VendorRequest request) {
        if (request.getPassword() == null || request.getPassword().length() < 8) {
            logger.warn("Invalid password length: {}", request.getPassword());
            throw new CustomException("Password must be at least 8 characters");
        }
    }

    private void validateLogo(MultipartFile logo) {
        String contentType = logo.getContentType();
        if (!Arrays.asList("image/jpeg", "image/png").contains(contentType)) {
            logger.warn("Invalid logo format: {}", contentType);
            throw new CustomException("Logo must be JPEG or PNG");
        }

        long maxSize = 2 * 1024 * 1024; // 2MB
        if (logo.getSize() > maxSize) {
            logger.warn("Logo size exceeds limit: {} bytes", logo.getSize());
            throw new CustomException("Logo size must not exceed 2MB");
        }
    }

    private String generateOtp() {
        return String.format("%06d", new Random().nextInt(999999));
    }

    private void sendEmail(String to, String subject, String content) {
        try {
            MimeMessage message = new MimeMessage(mailSession);
            message.setFrom(new InternetAddress(emailUsername));
            message.setRecipients(jakarta.mail.Message.RecipientType.TO, InternetAddress.parse(to));
            message.setSubject(subject);
            message.setText(content);
            Transport.send(message);
            logger.info("Email sent successfully: to={}", to);
        } catch (MessagingException e) {
            logger.error("Failed to send email to {}: {}", to, e.getMessage());
            throw new CustomException("Email sending failed: " + e.getMessage());
        }
    }
}