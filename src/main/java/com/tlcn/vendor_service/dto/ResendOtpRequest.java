package com.tlcn.vendor_service.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ResendOtpRequest {
    private String email;
    private String initToken;

    public ResendOtpRequest() {}
}
