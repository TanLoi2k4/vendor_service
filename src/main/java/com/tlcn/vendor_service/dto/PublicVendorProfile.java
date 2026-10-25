package com.tlcn.vendor_service.dto;

import com.tlcn.vendor_service.enums.VendorStatus;
import com.tlcn.vendor_service.model.Vendor;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * Sanitized vendor profile for customer storefront — no email/phone/bank/PII.
 */
@Data
@Builder
public class PublicVendorProfile {
    private Long id;
    private String keycloakId;
    private String shopName;
    private String logoUrl;
    private VendorStatus status;
    private LocalDateTime createdAt;
    private Double rating;
    private Long reviewCount;

    public static PublicVendorProfile fromEntity(Vendor vendor) {
        return fromEntity(vendor, 0.0, 0L);
    }

    public static PublicVendorProfile fromEntity(Vendor vendor, Double rating, Long reviewCount) {
        if (vendor == null) {
            return null;
        }

        return PublicVendorProfile.builder()
                .id(vendor.getId())
                .keycloakId(vendor.getKeycloakId())
                .shopName(vendor.getShopName())
                .logoUrl(vendor.getLogoUrl())
                .status(vendor.getStatus())
                .createdAt(vendor.getCreatedAt())
                .rating(rating != null ? rating : 0.0)
                .reviewCount(reviewCount != null ? reviewCount : 0L)
                .build();
    }
}
