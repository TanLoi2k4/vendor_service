package com.tlcn.vendor_service.dto;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class VendorUpdateProfileRequest {
    @Size(min = 1, max = 50, message = "First name must be between 1 and 50 characters")
    private String firstName;

    @Size(min = 1, max = 50, message = "Last name must be between 1 and 50 characters")
    private String lastName;

    @Size(min = 3, max = 100, message = "Shop name must be between 3 and 100 characters")
    private String shopName;

    @Pattern(regexp = "^\\d{10}$", message = "Phone must be 10 digits")
    private String phone;

    @Size(max = 50, message = "Bank account must not exceed 50 characters")
    private String bankAccount;

    @Size(max = 100, message = "Payment info must not exceed 100 characters")
    private String paymentInfo;
}