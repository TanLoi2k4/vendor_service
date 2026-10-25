package com.tlcn.vendor_service.enums;

public enum AccountVerificationStatus {
    PENDING,      // Chờ xác thực
    VERIFIED,     // Đã xác thực
    FAILED,       // Xác thực thất bại
    REJECTED      // Bị từ chối
}
