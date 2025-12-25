package com.tlcn.vendor_service.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LogoutRequest {
    @NotBlank
    private String accessToken;

    @NotBlank
    private String refreshToken;
}
