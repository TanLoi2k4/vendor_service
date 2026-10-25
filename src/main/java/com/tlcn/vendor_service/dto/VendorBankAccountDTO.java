package com.tlcn.vendor_service.dto;

import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VendorBankAccountDTO {
    
    private Long id;
    
    private String vendorKeycloakId;
    
    private String accountNumber;
    
    private String accountName;
    
    private String bankCode;
    
    private String bankName;
    
    private String accountType;
    
    private Boolean isVerified;
    
    private String verificationStatus;
    
    private LocalDateTime verifiedAt;
    
    private String verificationNotes;
}
