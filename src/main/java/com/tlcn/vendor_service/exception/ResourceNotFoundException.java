package com.tlcn.vendor_service.exception;

/**
 * Exception for resource not found (404)
 */
public class ResourceNotFoundException extends BusinessException {
    public ResourceNotFoundException(String resourceType, String identifier) {
        super(
            "RESOURCE_NOT_FOUND",
            String.format("%s not found: %s", resourceType, identifier),
            404
        );
    }
}
