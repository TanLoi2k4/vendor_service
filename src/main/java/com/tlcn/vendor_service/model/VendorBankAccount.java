package com.tlcn.vendor_service.model;

import com.tlcn.vendor_service.enums.AccountVerificationStatus;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(
    name = "vendor_bank_accounts",
    uniqueConstraints = {
        @UniqueConstraint(
            name = "uk_vendor_bank_account_vendor",
            columnNames = "vendor_id"
        )
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VendorBankAccount {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Mỗi vendor chỉ có một tài khoản ngân hàng
     */
    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
        name = "vendor_id",
        nullable = false,
        unique = true,
        foreignKey = @ForeignKey(name = "fk_vendor_bank_account_vendor")
    )
    private Vendor vendor;

    /**
     * Số tài khoản
     */
    @Column(name = "account_number", nullable = false, length = 50)
    private String accountNumber;

    /**
     * Tên chủ tài khoản
     */
    @Column(name = "account_name", nullable = false, length = 100)
    private String accountName;

    /**
     * Mã ngân hàng
     */
    @Column(name = "bank_code", nullable = false, length = 20)
    private String bankCode;

    /**
     * Tên ngân hàng
     */
    @Column(name = "bank_name", nullable = false, length = 100)
    private String bankName;

    /**
     * SAVINGS, CHECKING,...
     */
    @Column(name = "account_type", length = 20)
    private String accountType;

    /**
     * Đã xác thực chưa
     */
    @Builder.Default
    @Column(name = "is_verified", nullable = false)
    private Boolean isVerified = false;

    /**
     * Trạng thái xác thực
     */
    @Builder.Default
    @Enumerated(EnumType.STRING)
    @Column(name = "verification_status", nullable = false, length = 20)
    private AccountVerificationStatus verificationStatus =
            AccountVerificationStatus.PENDING;

    /**
     * Thời gian tạo
     */
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /**
     * Thời gian cập nhật
     */
    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    /**
     * Thời gian xác thực
     */
    @Column(name = "verified_at")
    private LocalDateTime verifiedAt;

    /**
     * Ghi chú xác thực
     */
    @Column(name = "verification_notes", columnDefinition = "TEXT")
    private String verificationNotes;
}