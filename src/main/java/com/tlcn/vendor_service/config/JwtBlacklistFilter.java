package com.tlcn.vendor_service.config;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * JWT Blacklist Filter - Checks if a token has been blacklisted during logout
 * Tokens are stored as SHA-256 hashes in Redis for security
 */
@Slf4j
public class JwtBlacklistFilter extends OncePerRequestFilter {

    private static final String BLACKLIST_KEY_PREFIX = "vendor:token:blacklist:";
    private final RedisTemplate<String, String> redisTemplate;

    public JwtBlacklistFilter(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String accessToken = authHeader.replace("Bearer ", "").trim();
            
            // Hash token for security (don't use raw token as Redis key)
            String tokenHash = DigestUtils.sha256Hex(accessToken);
            String blacklistKey = BLACKLIST_KEY_PREFIX + tokenHash;
            
            // Check if token is blacklisted
            if (redisTemplate.hasKey(blacklistKey)) {
                log.warn("Attempt to use blacklisted token: {}...", accessToken.substring(0, Math.min(20, accessToken.length())));
                
                // Set proper response headers
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json; charset=UTF-8");
                
                // Write error response
                try {
                    response.getWriter().write(
                        "{\"success\": false, \"message\": \"Token is blacklisted\", \"errorCode\": \"INVALID_TOKEN\", \"data\": null}"
                    );
                } catch (IOException e) {
                    log.error("Failed to write blacklist error response", e);
                }
                return;
            }
        }
        
        filterChain.doFilter(request, response);
    }
}