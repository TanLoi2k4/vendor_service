package com.tlcn.vendor_service.service;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.Response;
import java.util.Collections;
import java.util.List;

@Service
public class KeycloakService {
    private static final Logger logger = LoggerFactory.getLogger(KeycloakService.class);

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.resource}")
    private String clientId;

    @Value("${keycloak.credentials.secret}")
    private String clientSecret;

    @Value("${keycloak.auth-server-url}")
    private String serverUrl;

    @Autowired
    @Qualifier("keycloakAdmin")
    private Keycloak keycloak;

    public String createUser(String username, String email, String firstName, String lastName, String password) {
        logger.debug("Creating user in Keycloak: username={}, email={}, firstName={}, lastName={}", 
                    username, email, firstName, lastName);

        // 1. Tạo user representation
        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setEnabled(true);
        user.setEmailVerified(true);

        // 2. Set mật khẩu
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(password);
        credential.setTemporary(false);
        user.setCredentials(Collections.singletonList(credential));

        UsersResource usersResource = keycloak.realm(realm).users();
        Response response = usersResource.create(user);

        // 3. Check kết quả tạo user
        if (response.getStatus() != 201) {
            String errorMessage = response.readEntity(String.class);
            logger.error("Failed to create user: status={}, message={}", response.getStatus(), errorMessage);
            throw new RuntimeException("Failed to create user in Keycloak: " + errorMessage);
        }

        // 4. Lấy userId từ response
        String keycloakId = response.getLocation().getPath().replaceAll(".*/users/", "");
        logger.info("User created: keycloakId={}, firstName={}, lastName={}", keycloakId, firstName, lastName);

        // 5. Assign role VENDOR
        try {
            RoleRepresentation vendorRole = keycloak.realm(realm).roles().get("VENDOR").toRepresentation();
            usersResource.get(keycloakId).roles().realmLevel().add(Collections.singletonList(vendorRole));
            logger.info("Assigned role VENDOR to user: {}", username);
        } catch (Exception e) {
            logger.error("Failed to assign role VENDOR to user {}: {}", username, e.getMessage());
            throw new RuntimeException("User created but failed to assign role VENDOR: " + e.getMessage());
        }

        // 6. Verify user setup
        UserRepresentation createdUser = usersResource.get(keycloakId).toRepresentation();
        if (!createdUser.isEnabled() || !createdUser.isEmailVerified()) {
            logger.error("User created but not fully set up: enabled={}, emailVerified={}", 
                        createdUser.isEnabled(), createdUser.isEmailVerified());
            throw new RuntimeException("User created but not fully set up in Keycloak");
        }

        return keycloakId;
    }

    public void deleteUser(String keycloakId) {
        logger.debug("Deleting user: keycloakId={}", keycloakId);
        Response response = keycloak.realm(realm).users().delete(keycloakId);
        if (response.getStatus() != 204) {
            String errorMessage = response.readEntity(String.class);
            logger.error("Failed to delete user: status={}, message={}", response.getStatus(), errorMessage);
            throw new RuntimeException("Failed to delete user in Keycloak: " + errorMessage);
        }
        logger.info("User deleted: keycloakId={}", keycloakId);
    }

    public AccessTokenResponse authenticateUser(String username, String password) {
        logger.debug("Authenticating user: username={}", username);

        String keycloakId = getKeycloakIdByUsername(username);
        if (keycloakId == null) {
            logger.error("User not found in Keycloak: username={}", username);
            throw new RuntimeException("User not found in Keycloak");
        }
        UserRepresentation user = keycloak.realm(realm).users().get(keycloakId).toRepresentation();
        if (!user.isEnabled() || !user.isEmailVerified()) {
            logger.error("Account is not fully set up: username={}, enabled={}, emailVerified={}", 
                         username, user.isEnabled(), user.isEmailVerified());
            throw new RuntimeException("Account is not fully set up. Check Keycloak user settings.");
        }
        if (!user.getRequiredActions().isEmpty()) {
            logger.error("Account has required actions: username={}, requiredActions={}", 
                         username, user.getRequiredActions());
            throw new RuntimeException("Account has required actions: " + user.getRequiredActions());
        }

        try {
            Keycloak keycloakInstance = Keycloak.getInstance(serverUrl, realm, username, password, clientId, clientSecret);
            AccessTokenResponse tokenResponse = keycloakInstance.tokenManager().getAccessToken();
            logger.info("User authenticated: username={}", username);
            return tokenResponse;
        } catch (Exception e) {
            logger.error("Authentication failed: username={}, error={}", username, e.getMessage());
            if (e.getMessage().contains("Account is not fully set up")) {
                throw new RuntimeException("Account is not fully set up. Check Keycloak user settings or required actions.");
            }
            if (e.getMessage().contains("invalid_grant")) {
                throw new RuntimeException("Invalid username or password");
            }
            throw new RuntimeException("Authentication failed: " + e.getMessage());
        }
    }

    public void updatePassword(String keycloakId, String newPassword) {
        logger.debug("Updating password for keycloakId={}", keycloakId);
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(newPassword);
        credential.setTemporary(false);
        keycloak.realm(realm).users().get(keycloakId).resetPassword(credential);
        logger.info("Password updated for keycloakId={}", keycloakId);
    }

    public void updateUser(String keycloakId, String username, String email, String firstName, String lastName) {
        logger.debug("Updating user: keycloakId={}, username={}, email={}, firstName={}, lastName={}", 
                     keycloakId, username, email, firstName, lastName);
        UserRepresentation user = keycloak.realm(realm).users().get(keycloakId).toRepresentation();
        user.setUsername(username);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setEmailVerified(true);
        user.setRequiredActions(Collections.emptyList());
        keycloak.realm(realm).users().get(keycloakId).update(user);
        logger.info("User updated: keycloakId={}, firstName={}, lastName={}", keycloakId, firstName, lastName);
    }

    public String getKeycloakIdByUsername(String username) {
        try {
            List<UserRepresentation> users = keycloak.realm(realm).users().search(username, true);
            if (users.isEmpty()) {
                logger.warn("No user found for username: {}", username);
                return null;
            }
            return users.get(0).getId();
        } catch (Exception e) {
            logger.error("Failed to search user: username={}, error={}", username, e.getMessage());
            return null;
        }
    }

    public boolean verifyPassword(String username, String password) {
        try {
            authenticateUser(username, password);
            return true;
        } catch (Exception e) {
            logger.warn("Password verification failed: username={}, error={}", username, e.getMessage());
            return false;
        }
    }

    public void logoutUser(String refreshToken) {
        logger.debug("Logging out user with refresh token");
        try {
            Client client = ClientBuilder.newClient();
            String logoutUrl = serverUrl + "/realms/" + realm + "/protocol/openid-connect/logout";

            Form form = new Form();
            form.param("client_id", clientId);
            form.param("client_secret", clientSecret);
            form.param("refresh_token", refreshToken);

            Response response = client.target(logoutUrl)
                    .request()
                    .post(Entity.form(form));

            if (response.getStatus() != 204) {
                String errorMessage = response.readEntity(String.class);
                logger.error("Failed to logout user: status={}, message={}", response.getStatus(), errorMessage);
                throw new RuntimeException("Failed to logout user in Keycloak: " + errorMessage);
            }

            logger.info("User logged out successfully");
            client.close();
        } catch (Exception e) {
            logger.error("Logout failed: error={}", e.getMessage());
            throw new RuntimeException("Logout failed: " + e.getMessage());
        }
    }
}