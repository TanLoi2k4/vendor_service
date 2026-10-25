package com.tlcn.vendor_service.client;

import lombok.Data;

@Data
public class ProductVendorRatingStats {
    private String keycloakId;
    private Double rating;
    private Long reviewCount;
}
