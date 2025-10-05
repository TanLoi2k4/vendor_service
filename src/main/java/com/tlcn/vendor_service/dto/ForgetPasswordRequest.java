package com.tlcn.vendor_service.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ForgetPasswordRequest {
    @Email(message = "Invalid email")
    @NotBlank(message = "Email is required")
    private String email;
}