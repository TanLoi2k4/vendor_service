package com.tlcn.vendor_service.dto;

import com.tlcn.vendor_service.enums.AccountVerificationStatus;
import lombok.Data;

@Data
public class VendorBankAccountSearchDTO {
    private String bankCode;
    private String vendorName;
    private String accountName;
    private String bankName;
    private AccountVerificationStatus verificationStatus;
}