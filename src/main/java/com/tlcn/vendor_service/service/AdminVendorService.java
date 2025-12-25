package com.tlcn.vendor_service.service;

import com.tlcn.vendor_service.dto.ResponseDTO;
import com.tlcn.vendor_service.enums.VendorStatus;
import com.tlcn.vendor_service.model.Vendor;
import com.tlcn.vendor_service.repository.VendorRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminVendorService {

    private final VendorRepository vendorRepository;
    private final AdminServiceClient adminServiceClient;

    /**
     * Lấy danh sách vendor (admin)
     */
    public ResponseDTO<?> getAllVendors(VendorStatus status, String search, int page, int size, String sortBy) {

        Pageable pageable = PageRequest.of(page, size, Sort.by(sortBy).descending());

        Page<Vendor> vendors;

        if (status != null && search != null && !search.isBlank()) {
            vendors = vendorRepository.findByStatusAndUsernameContainingIgnoreCase(status, search, pageable);
        } else if (status != null) {
            vendors = vendorRepository.findByStatus(status, pageable);
        } else if (search != null && !search.isBlank()) {
            vendors = vendorRepository.findByUsernameContainingIgnoreCase(search, pageable);
        } else {
            vendors = vendorRepository.findAll(pageable);
        }

        return new ResponseDTO<>(true, "Vendor list loaded", vendors);
    }

    /**
     * Lấy vendor theo ID (admin)
     */
    public ResponseDTO<Vendor> getVendorById(Long id) {
        Optional<Vendor> vendorOpt = vendorRepository.findById(id);

        if (vendorOpt.isEmpty()) {
            return new ResponseDTO<>(false, "Vendor not found", null);
        }

        return new ResponseDTO<>(true, "Vendor found", vendorOpt.get());
    }

    /**
     * Admin thay đổi trạng thái vendor - FIXED: Added status transition validation
     */
    @Transactional
    public ResponseDTO<Vendor> updateVendorStatus(Long id, VendorStatus newStatus) {
        Optional<Vendor> vendorOpt = vendorRepository.findById(id);

        if (vendorOpt.isEmpty()) {
            return new ResponseDTO<>(false, "Vendor not found", null);
        }

        Vendor vendor = vendorOpt.get();
        VendorStatus oldStatus = vendor.getStatus();

        // Validate state transitions
        if (!isValidStatusTransition(oldStatus, newStatus)) {
            log.warn("Invalid status transition: {} -> {} for vendorId={}", oldStatus, newStatus, id);
            return new ResponseDTO<>(false, 
                "Cannot transition from " + oldStatus + " to " + newStatus, null);
        }

        vendor.setStatus(newStatus);
        vendor.setUpdatedAt(java.time.LocalDateTime.now());
        vendorRepository.save(vendor);

        log.info("ADMIN updated vendor status: vendorId={}, from {} to {}", id, oldStatus, newStatus);

        // Log admin action to admin-service
        adminServiceClient.logAdminAction(
            null, // userId - will be extracted from security context in admin-service
            null, // username - will be extracted from security context in admin-service
            "UPDATE_VENDOR_STATUS",
            "VENDOR",
            id.toString(),
            "INFO",
            "Updated vendor status from " + oldStatus + " to " + newStatus,
            "{\"oldStatus\":\"" + oldStatus + "\",\"newStatus\":\"" + newStatus + "\"}",
            null, // ipAddress - will be extracted from request in admin-service
            null  // userAgent - will be extracted from request in admin-service
        );

        return new ResponseDTO<>(true, "Vendor status updated", vendor);
    }

    /**
     * Admin cập nhật thông tin vendor - FIXED: Added email/username uniqueness
     */
    @Transactional
    public ResponseDTO<Vendor> updateVendorInfo(Long id, Vendor request) {
        Optional<Vendor> vendorOpt = vendorRepository.findById(id);

        if (vendorOpt.isEmpty()) {
            return new ResponseDTO<>(false, "Vendor not found", null);
        }

        Vendor vendor = vendorOpt.get();

        // Check email uniqueness if changing
        if (request.getEmail() != null && !vendor.getEmail().equals(request.getEmail())) {
            if (vendorRepository.existsByEmail(request.getEmail())) {
                log.warn("Email already in use: {}", request.getEmail());
                return new ResponseDTO<>(false, "Email already in use", null);
            }
            vendor.setEmail(request.getEmail());
        }

        // Check username uniqueness if changing
        if (request.getUsername() != null && !vendor.getUsername().equals(request.getUsername())) {
            if (vendorRepository.existsByUsername(request.getUsername())) {
                log.warn("Username already in use: {}", request.getUsername());
                return new ResponseDTO<>(false, "Username already in use", null);
            }
            vendor.setUsername(request.getUsername());
        }

        // Update other fields
        if (request.getFirstName() != null) vendor.setFirstName(request.getFirstName());
        if (request.getLastName() != null) vendor.setLastName(request.getLastName());
        if (request.getShopName() != null) vendor.setShopName(request.getShopName());
        if (request.getPhone() != null) vendor.setPhone(request.getPhone());
        if (request.getBankAccount() != null) vendor.setBankAccount(request.getBankAccount());
        if (request.getPaymentInfo() != null) vendor.setPaymentInfo(request.getPaymentInfo());

        vendor.setUpdatedAt(java.time.LocalDateTime.now());
        vendorRepository.save(vendor);

        log.info("ADMIN updated vendor info: vendorId={}", id);

        // Log admin action to admin-service
        adminServiceClient.logAdminAction(
            null, // userId - will be extracted from security context in admin-service
            null, // username - will be extracted from security context in admin-service
            "UPDATE_VENDOR_INFO",
            "VENDOR",
            id.toString(),
            "INFO",
            "Updated vendor information",
            "{\"vendorId\":" + id + ",\"updatedFields\":[\"email\",\"username\",\"firstName\",\"lastName\",\"shopName\",\"phone\",\"bankAccount\",\"paymentInfo\"]}",
            null, // ipAddress - will be extracted from request in admin-service
            null  // userAgent - will be extracted from request in admin-service
        );

        return new ResponseDTO<>(true, "Vendor info updated", vendor);
    }

    /**
     * Xóa mềm vendor (DELETED)
     */
    @Transactional
    public ResponseDTO<String> softDeleteVendor(Long id) {
        Optional<Vendor> vendorOpt = vendorRepository.findById(id);

        if (vendorOpt.isEmpty()) {
            return new ResponseDTO<>(false, "Vendor not found", null);
        }

        Vendor vendor = vendorOpt.get();
        vendor.setStatus(VendorStatus.DELETED);
        vendor.setUpdatedAt(java.time.LocalDateTime.now());
        vendorRepository.save(vendor);

        log.warn("ADMIN soft-deleted vendor: vendorId={}", id);

        // Log admin action to admin-service
        adminServiceClient.logAdminAction(
            null, // userId - will be extracted from security context in admin-service
            null, // username - will be extracted from security context in admin-service
            "DELETE_VENDOR",
            "VENDOR",
            id.toString(),
            "WARN",
            "Soft deleted vendor account",
            "{\"vendorId\":" + id + ",\"action\":\"SOFT_DELETE\"}",
            null, // ipAddress - will be extracted from request in admin-service
            null  // userAgent - will be extracted from request in admin-service
        );

        return new ResponseDTO<>(true, "Vendor deleted", "DELETED");
    }

    // Status transition validation helper
    private boolean isValidStatusTransition(VendorStatus from, VendorStatus to) {
        // DELETED vendors cannot be restored
        if (from == VendorStatus.DELETED) {
            return false;
        }
        
        // Allow normal transitions
        if (from == VendorStatus.ACTIVE) {
            return to == VendorStatus.INACTIVE || to == VendorStatus.SUSPENDED || to == VendorStatus.DELETED;
        }
        
        if (from == VendorStatus.INACTIVE || from == VendorStatus.SUSPENDED) {
            return to == VendorStatus.ACTIVE || to == VendorStatus.DELETED;
        }
        
        return false;
    }
}