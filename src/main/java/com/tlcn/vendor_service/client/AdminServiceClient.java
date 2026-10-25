package com.tlcn.vendor_service.client;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.RestClientException;
import org.springframework.web.util.UriComponentsBuilder;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminServiceClient {

    private final RestTemplate restTemplate;

    @Value("${admin-service.url:http://localhost:8086}")
    private String adminServiceUrl;

    @Value("${admin-service.internal-log-token}")
    private String internalLogToken;

    /**
     * Log admin action asynchronously to admin-service
     */
    @Async
    public void logAdminAction(Long userId, String username, String action, String resourceType,
                              String resourceId, String level, String message,
                              String additionalData, String ipAddress, String userAgent) {
        try {
            UriComponentsBuilder builder = UriComponentsBuilder
                    .fromHttpUrl(adminServiceUrl)
                    .path("/admin/logs/external-action")
                    .queryParam("action", action)
                    .queryParam("resourceType", resourceType)
                    .queryParam("resourceId", resourceId)
                    .queryParam("level", level != null ? level : "INFO")
                    .queryParam("message", message);

            if (userId != null) {
                builder.queryParam("userId", userId);
            }
            if (username != null && !username.isBlank()) {
                builder.queryParam("username", username);
            }
            if (additionalData != null && !additionalData.isBlank()) {
                builder.queryParam("additionalData", additionalData);
            }
            if (ipAddress != null && !ipAddress.isBlank()) {
                builder.queryParam("ipAddress", ipAddress);
            }
            if (userAgent != null && !userAgent.isBlank()) {
                builder.queryParam("userAgent", userAgent);
            }

            HttpHeaders headers = new HttpHeaders();
            headers.set("X-Internal-Token", internalLogToken);
            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<String> response = restTemplate.postForEntity(builder.build(true).toUri(), entity, String.class);

            if (response.getStatusCode().is2xxSuccessful()) {
                log.debug("Successfully logged admin action: {} - {}", action, message);
            } else {
                log.warn("Failed to log admin action: HTTP {}", response.getStatusCode());
            }

        } catch (RestClientException e) {
            log.warn("Failed to log admin action to admin-service: {}", e.getMessage());
        } catch (Exception e) {
            log.warn("Unexpected error while logging admin action: {}", e.getMessage());
        }
    }
}