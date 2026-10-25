package com.tlcn.vendor_service.client;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class ProductServiceClient {

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @Value("${product-service.url:http://localhost:8082}")
    private String productServiceUrl;

    public Map<String, ProductVendorRatingStats> getVendorRatings(List<String> keycloakIds) {
        if (keycloakIds == null || keycloakIds.isEmpty()) {
            return Map.of();
        }

        String idsParam = keycloakIds.stream()
            .filter(id -> id != null && !id.isBlank())
            .map(String::trim)
            .distinct()
            .limit(100)
            .collect(Collectors.joining(","));

        if (idsParam.isEmpty()) {
            return Map.of();
        }

        try {
            String url = UriComponentsBuilder
                .fromHttpUrl(productServiceUrl)
                .path("/products/vendors/ratings")
                .queryParam("ids", idsParam)
                .build(true)
                .toUriString();

            Map<String, Object> body = restTemplate.getForObject(url, Map.class);
            Object data = body != null ? body.get("data") : null;
            if (data == null) {
                return Map.of();
            }

            Map<String, ProductVendorRatingStats> parsed = objectMapper.convertValue(
                data,
                new TypeReference<Map<String, ProductVendorRatingStats>>() {}
            );
            return parsed != null ? parsed : Map.of();
        } catch (RestClientException ex) {
            log.warn("Failed to fetch vendor ratings from product-service: {}", ex.getMessage());
            return Map.of();
        }
    }

    public List<ProductVendorRatingStats> getTopRatedVendors(int size) {
        int limit = Math.min(Math.max(size, 1), 50);
        try {
            String url = UriComponentsBuilder
                .fromHttpUrl(productServiceUrl)
                .path("/products/vendors/top-rated")
                .queryParam("size", limit)
                .build(true)
                .toUriString();

            Map<String, Object> body = restTemplate.getForObject(url, Map.class);
            Object data = body != null ? body.get("data") : null;
            if (data == null) {
                return List.of();
            }

            List<ProductVendorRatingStats> parsed = objectMapper.convertValue(
                data,
                new TypeReference<List<ProductVendorRatingStats>>() {}
            );
            return parsed != null ? parsed : List.of();
        } catch (RestClientException ex) {
            log.warn("Failed to fetch top-rated vendors from product-service: {}", ex.getMessage());
            return List.of();
        }
    }

    public List<String> getTopRatedVendorKeycloakIds(int size) {
        return getTopRatedVendors(size).stream()
            .map(ProductVendorRatingStats::getKeycloakId)
            .filter(id -> id != null && !id.isBlank())
            .distinct()
            .collect(Collectors.toList());
    }
}
