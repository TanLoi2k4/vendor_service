package com.tlcn.vendor_service.exception;

/**
 * Base exception for business logic errors
 */
public class BusinessException extends RuntimeException {
    private final String errorCode;
    private final int statusCode;

    // Constructor with just message (for compatibility)
    public BusinessException(String message) {
        this("BUSINESS_ERROR", message);
    }

    // Constructor with error code and message
    public BusinessException(String errorCode, String message) {
        this(errorCode, message, 400);
    }

    // Constructor with error code, message, and status code
    public BusinessException(String errorCode, String message, int statusCode) {
        super(message);
        this.errorCode = errorCode;
        this.statusCode = statusCode;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public int getStatusCode() {
        return statusCode;
    }
}
