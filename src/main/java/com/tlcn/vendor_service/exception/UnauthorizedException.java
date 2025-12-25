package com.tlcn.vendor_service.exception;

/**
 * Exception for authentication/authorization errors (401/403)
 */
public class UnauthorizedException extends BusinessException {
    public UnauthorizedException(String message) {
        super("UNAUTHORIZED", message, 401);
    }

    public static UnauthorizedException invalidToken() {
        return new UnauthorizedException("Invalid or expired token");
    }

    public static UnauthorizedException tokenMissing() {
        return new UnauthorizedException("Authorization token is missing");
    }
}
