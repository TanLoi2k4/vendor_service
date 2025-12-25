package com.tlcn.vendor_service.exception;

/**
 * Exception for forbidden operations (403)
 */
public class ForbiddenException extends BusinessException {
    public ForbiddenException(String message) {
        super("FORBIDDEN", message, 403);
    }

    public static ForbiddenException insufficientPermissions() {
        return new ForbiddenException("Insufficient permissions for this operation");
    }
}
