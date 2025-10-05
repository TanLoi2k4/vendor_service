package com.tlcn.vendor_service.dto;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class VendorUpdateProfileRequest {
    @Size(min = 3, max = 100, message = "Shop name must be between 3 and 100 characters")
    private String shopName;

    @Size(max = 255, message = "Address must not exceed 255 characters")
    private String address;

    @Pattern(regexp = "^\\d{10}$", message = "Phone must be 10 digits")
    private String phone;

    @Size(max = 50, message = "Bank account must not exceed 50 characters")
    private String bankAccount;

    @Size(max = 100, message = "Payment info must not exceed 100 characters")
    private String paymentInfo;
}
