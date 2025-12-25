package com.tlcn.vendor_service.model;

import com.tlcn.vendor_service.enums.VendorStatus;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(name = "vendors")
public class Vendor {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Column(unique = true, nullable = false, length = 50)
    private String username;

    @Email(message = "Invalid email")
    @NotBlank(message = "Email is required")
    @Size(max = 100, message = "Email must not exceed 100 characters")
    @Column(unique = true, nullable = false, length = 100)
    private String email;

    @NotBlank(message = "First name is required")
    @Size(min = 1, max = 50, message = "First name must be between 1 and 50 characters")
    @Column(nullable = false, length = 50)
    private String firstName;

    @NotBlank(message = "Last name is required")
    @Size(min = 1, max = 50, message = "Last name must be between 1 and 50 characters")
    @Column(nullable = false, length = 50)
    private String lastName;

    @NotBlank(message = "Shop name is required")
    @Size(min = 3, max = 100, message = "Shop name must be between 3 and 100 characters")
    @Column(nullable = false, length = 100)
    private String shopName;

    @Size(max = 255, message = "Logo URL must not exceed 255 characters")
    @Column(length = 255)
    private String logoUrl;

    @Size(max = 255, message = "Logo Public ID must not exceed 255 characters")  
    @Column(length = 255)
    private String logoPublicId;

    @Pattern(regexp = "^\\d{10}$", message = "Phone must be 10 digits")
    @Column(length = 10)
    private String phone;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private VendorStatus status = VendorStatus.ACTIVE;

    @Column(updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(updatable = true)
    private LocalDateTime updatedAt;

    @Size(max = 50, message = "Bank account must not exceed 50 characters")
    @Column(length = 50)
    private String bankAccount;

    @Size(max = 100, message = "Payment info must not exceed 100 characters")
    @Column(length = 100)
    private String paymentInfo;

    @Size(max = 255, message = "Keycloak ID must not exceed 255 characters")
    @Column(length = 255)
    private String keycloakId; 
}