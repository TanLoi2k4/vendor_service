package com.tlcn.vendor_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.RestClientException;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminServiceClient {

    private final RestTemplate restTemplate;

    @Value("${admin-service.url:http://localhost:8086}")
    private String adminServiceUrl;

    /**
     * Log admin action asynchronously to admin-service
     */
    @Async
    public void logAdminAction(Long userId, String username, String action, String resourceType,
                              String resourceId, String level, String message,
                              String additionalData, String ipAddress, String userAgent) {
        try {
            String url = adminServiceUrl + "/admin/logs/external-action";

            // Build query parameters
            StringBuilder urlBuilder = new StringBuilder(url);
            urlBuilder.append("?userId=").append(userId);
            urlBuilder.append("&username=").append(username != null ? username : "");
            urlBuilder.append("&action=").append(action != null ? action : "");
            urlBuilder.append("&resourceType=").append(resourceType != null ? resourceType : "");
            urlBuilder.append("&resourceId=").append(resourceId != null ? resourceId : "");
            urlBuilder.append("&level=").append(level != null ? level : "INFO");
            urlBuilder.append("&message=").append(message != null ? message : "");

            if (additionalData != null) {
                urlBuilder.append("&additionalData=").append(additionalData);
            }
            if (ipAddress != null) {
                urlBuilder.append("&ipAddress=").append(ipAddress);
            }
            if (userAgent != null) {
                urlBuilder.append("&userAgent=").append(userAgent);
            }

            ResponseEntity<String> response = restTemplate.postForEntity(urlBuilder.toString(), null, String.class);

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