package com.tlcn.vendor_service.exception;

/**
 * Exception for Keycloak-related errors
 */
public class KeycloakException extends BusinessException {
    private static final String ERROR_CODE = "KEYCLOAK_ERROR";

    public KeycloakException(String message) {
        super(ERROR_CODE, message, 500);
    }

    public KeycloakException(String message, Throwable cause) {
        super(ERROR_CODE, message, 500);
        initCause(cause);
    }

    // Factory methods for specific scenarios
    public static KeycloakException failedToCreateUser(String reason) {
        return new KeycloakException("Failed to create user in Keycloak: " + reason);
    }

    public static KeycloakException failedToAssignRole(String username, String reason) {
        return new KeycloakException("Failed to assign role to user " + username + ": " + reason);
    }

    public static KeycloakException failedToDeleteUser(String reason) {
        return new KeycloakException("Failed to delete user in Keycloak: " + reason);
    }

    public static KeycloakException invalidUser(String username) {
        return new KeycloakException("User not found in Keycloak: " + username);
    }

    public static KeycloakException accountNotSetUp(String username) {
        return new KeycloakException("Account is not fully set up for user: " + username);
    }

    public static KeycloakException invalidCredentials() {
        return new KeycloakException("Invalid username or password");
    }

    public static KeycloakException logoutFailed(String reason) {
        return new KeycloakException("Failed to logout user from Keycloak: " + reason);
    }
}
