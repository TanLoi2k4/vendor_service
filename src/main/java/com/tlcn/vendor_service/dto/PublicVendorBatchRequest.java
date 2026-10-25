package com.tlcn.vendor_service.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.List;

@Data
public class PublicVendorBatchRequest {
    @NotEmpty(message = "keycloakIds must not be empty")
    @Size(max = 100, message = "keycloakIds must not exceed 100 items")
    private List<String> keycloakIds;
}
