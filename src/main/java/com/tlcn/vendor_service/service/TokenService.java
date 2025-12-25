package com.tlcn.vendor_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * TokenService - Handles JWT token operations like blacklisting and password reset tokens
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {

    private static final String BLACKLIST_KEY_PREFIX = "vendor:token:blacklist:";
    private static final String RESET_TOKEN_PREFIX = "vendor:reset:";

    private final RedisTemplate<String, String> redisTemplate;

    /**
     * Blacklist a JWT token
     * @param token The JWT token to blacklist
     * @param expirationTimeSeconds Time until token expires (for cleanup)
     */
    public void blacklistToken(String token, long expirationTimeSeconds) {
        // Hash token for security
        String tokenHash = DigestUtils.sha256Hex(token);
        String blacklistKey = BLACKLIST_KEY_PREFIX + tokenHash;

        // Store in Redis with expiration
        redisTemplate.opsForValue().set(blacklistKey, "blacklisted", Duration.ofSeconds(expirationTimeSeconds));

        log.info("Token blacklisted successfully. Hash: {}", tokenHash);
    }

    /**
     * Check if a token is blacklisted
     * @param token The JWT token to check
     * @return true if blacklisted, false otherwise
     */
    public boolean isTokenBlacklisted(String token) {
        String tokenHash = DigestUtils.sha256Hex(token);
        String blacklistKey = BLACKLIST_KEY_PREFIX + tokenHash;
        return redisTemplate.hasKey(blacklistKey);
    }

    /**
     * Store password reset token
     * @param token Reset token
     * @param email User email
     */
    public void storeResetToken(String token, String email) {
        String key = RESET_TOKEN_PREFIX + token;
        redisTemplate.opsForValue().set(key, email, Duration.ofMinutes(15)); // 15 minutes expiry
        log.debug("Password reset token stored for email: {}", email);
    }

    /**
     * Get email from reset token
     * @param token Reset token
     * @return Email or null if not found/expired
     */
    public String getResetTokenEmail(String token) {
        String key = RESET_TOKEN_PREFIX + token;
        return redisTemplate.opsForValue().get(key);
    }

    /**
     * Remove reset token
     * @param token Reset token
     */
    public void removeResetToken(String token) {
        String key = RESET_TOKEN_PREFIX + token;
        redisTemplate.delete(key);
        log.debug("Password reset token removed");
    }
}