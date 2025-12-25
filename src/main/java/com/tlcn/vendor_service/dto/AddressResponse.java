package com.tlcn.vendor_service.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AddressResponse {
    private Long id;
    private String street;
    private String city;
    private String country;
    private String label;
}