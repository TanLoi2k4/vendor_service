package com.tlcn.vendor_service.dto;

import com.tlcn.vendor_service.enums.VendorStatus;
import com.tlcn.vendor_service.model.Vendor;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class VendorResponse {
    private Long id;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private String shopName;
    private String logoUrl;
    private String logoPublicId;
    private String phone;
    private VendorStatus status;
    private String keycloakId;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public static VendorResponse fromEntity(Vendor vendor) {
        if (vendor == null) {
            return null;
        }

        return VendorResponse.builder()
                .id(vendor.getId())
                .username(vendor.getUsername())
                .email(vendor.getEmail())
                .firstName(vendor.getFirstName())
                .lastName(vendor.getLastName())
                .shopName(vendor.getShopName())
                .logoUrl(vendor.getLogoUrl())
                .logoPublicId(vendor.getLogoPublicId())
                .phone(vendor.getPhone())
                .status(vendor.getStatus())
                .keycloakId(vendor.getKeycloakId())
                .createdAt(vendor.getCreatedAt())
                .updatedAt(vendor.getUpdatedAt())
                .build();
    }
}
