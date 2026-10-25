package com.tlcn.vendor_service.service;

import com.tlcn.vendor_service.dto.VendorBankAccountDTO;
import com.tlcn.vendor_service.dto.VendorBankAccountSearchDTO;
import com.tlcn.vendor_service.enums.AccountVerificationStatus;
import com.tlcn.vendor_service.model.Vendor;
import com.tlcn.vendor_service.model.VendorBankAccount;
import com.tlcn.vendor_service.repository.VendorBankAccountRepository;
import com.tlcn.vendor_service.repository.VendorRepository;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class VendorBankAccountService {
    
    private final VendorBankAccountRepository bankAccountRepository;
    private final VendorRepository vendorRepository;
    
    /**
     * Lấy tài khoản bank đã xác thực của vendor
     */
    public VendorBankAccountDTO getBankAccount(String vendorKeycloakId) {
        log.info("Fetching verified bank account for vendor: {}", vendorKeycloakId);
        
        Vendor vendor = vendorRepository.findByKeycloakId(vendorKeycloakId)
                .orElseThrow(() -> new RuntimeException("Vendor not found: " + vendorKeycloakId));
        
        VendorBankAccount account = bankAccountRepository.findFirstByVendorIdAndIsVerifiedTrue(vendor.getId())
                .orElseThrow(() -> new RuntimeException("No verified bank account for vendor: " + vendorKeycloakId));
        
        return mapToDTO(account, vendor.getKeycloakId());
    }
    
    /**
     * Lấy tài khoản bank theo số tài khoản
     */
    public VendorBankAccountDTO getBankAccountByNumber(String accountNumber) {
        log.info("Fetching bank account by number: {}", maskAccountNumber(accountNumber));
        
        VendorBankAccount account = bankAccountRepository.findByAccountNumber(accountNumber)
                .orElseThrow(() -> new RuntimeException("Bank account not found: " + maskAccountNumber(accountNumber)));
        
        return mapToDTO(account, account.getVendor().getKeycloakId());
    }
    
    /**
     * Thêm hoặc cập nhật tài khoản bank.
     * Nếu tài khoản đã tồn tại, nó sẽ được cập nhật và đặt lại trạng thái PENDING.
     * Nếu chưa, một tài khoản mới sẽ được tạo.
     */
    public VendorBankAccountDTO addOrUpdateBankAccount(String vendorKeycloakId, VendorBankAccountDTO dto) {
        log.info("Adding or updating bank account for vendor: {}", vendorKeycloakId);
        
        Vendor vendor = vendorRepository.findByKeycloakId(vendorKeycloakId)
                .orElseThrow(() -> new RuntimeException("Vendor not found: " + vendorKeycloakId));
        
        // Tìm tài khoản hiện có của vendor. Vì mỗi vendor chỉ có 1, chúng ta có thể dùng findFirst.
        VendorBankAccount account = bankAccountRepository.findFirstByVendorId(vendor.getId())
                .orElseGet(() -> VendorBankAccount.builder().vendor(vendor).build());

        // Cập nhật thông tin và reset trạng thái xác thực
        account.setAccountNumber(dto.getAccountNumber());
        account.setAccountName(dto.getAccountName());
        account.setBankCode(dto.getBankCode());
        account.setBankName(dto.getBankName());
        account.setAccountType(dto.getAccountType());
        account.setIsVerified(false);
        account.setVerificationStatus(AccountVerificationStatus.PENDING);
        account.setVerifiedAt(null); // Reset thời gian xác thực
        account.setVerificationNotes(null); // Reset ghi chú
        
        VendorBankAccount saved = bankAccountRepository.save(account);
        log.info("Bank account added/updated successfully: {}", maskAccountNumber(saved.getAccountNumber()));
        
        return mapToDTO(saved, vendor.getKeycloakId());
    }
    
    /**
     * Xác thực tài khoản bank
     */
    public VendorBankAccountDTO verifyBankAccount(String vendorKeycloakId, boolean isValid) {
        log.info("Verifying bank account for vendor: {}", vendorKeycloakId);
        
        Vendor vendor = vendorRepository.findByKeycloakId(vendorKeycloakId)
                .orElseThrow(() -> new RuntimeException("Vendor not found"));
        
        VendorBankAccount account = bankAccountRepository.findFirstByVendorId(vendor.getId())
                .orElseThrow(() -> new RuntimeException("Bank account not found"));
        
        // Logic để đảm bảo chỉ có một tài khoản được xác thực
        if (isValid) {
            // Vô hiệu hóa các tài khoản đã xác thực khác (mặc dù logic mới là 1-1, nhưng để an toàn)
            bankAccountRepository.findByVendorIdAndIsVerified(vendor.getId(), true)
                    .forEach(oldVerifiedAccount -> {
                        if (!oldVerifiedAccount.getId().equals(account.getId())) {
                            oldVerifiedAccount.setIsVerified(false);
                            bankAccountRepository.save(oldVerifiedAccount);
                        }
                    });
            account.setIsVerified(true);
            account.setVerificationStatus(AccountVerificationStatus.VERIFIED);
            account.setVerifiedAt(LocalDateTime.now());
            log.info("Bank account verified successfully: {}", maskAccountNumber(account.getAccountNumber()));
        } else {
            account.setIsVerified(false); // Đảm bảo isVerified là false nếu không hợp lệ
            account.setVerificationStatus(AccountVerificationStatus.FAILED);
            log.warn("Bank account verification failed: {}", maskAccountNumber(account.getAccountNumber()));
        }
        
        VendorBankAccount updated = bankAccountRepository.save(account);
        return mapToDTO(updated, vendor.getKeycloakId());
    }
    
    /**
     * Lấy tài khoản bank của vendor (vì mỗi vendor chỉ có 1)
     */
    public VendorBankAccountDTO getMyBankAccount(String vendorKeycloakId) {
        log.info("Fetching bank account for vendor: {}", vendorKeycloakId);
        
        Vendor vendor = vendorRepository.findByKeycloakId(vendorKeycloakId)
                .orElseThrow(() -> new RuntimeException("Vendor not found"));
        
        return bankAccountRepository.findFirstByVendorId(vendor.getId())
                .map(acc -> mapToDTO(acc, vendor.getKeycloakId()))
                .orElse(null); // Trả về null nếu vendor chưa có tài khoản nào
    }
    
    /**
     * Xóa tài khoản bank
     */
    public void deleteBankAccount(String vendorKeycloakId, Long accountId) {
        log.info("Deleting bank account {} for vendor with keycloakId: {}", accountId, vendorKeycloakId);

        VendorBankAccount account = bankAccountRepository.findByIdAndVendorKeycloakId(accountId, vendorKeycloakId)
                .orElseThrow(() -> new RuntimeException("Bank account not found or you do not have permission to delete it."));
        
        bankAccountRepository.delete(account);
        log.info("Bank account deleted: {}", maskAccountNumber(account.getAccountNumber()));
    }
    
    /**
     * Map entity to DTO
     */
    private VendorBankAccountDTO mapToDTO(VendorBankAccount account, String vendorKeycloakId) {
        return VendorBankAccountDTO.builder()
                .id(account.getId())
                .vendorKeycloakId(vendorKeycloakId)
                .accountNumber(account.getAccountNumber())
                .accountName(account.getAccountName())
                .bankCode(account.getBankCode())
                .bankName(account.getBankName())
                .accountType(account.getAccountType())
                .isVerified(account.getIsVerified())
                .verificationStatus(account.getVerificationStatus().toString())
                .verifiedAt(account.getVerifiedAt())
                .verificationNotes(account.getVerificationNotes())
                .build();
    }
    
    /**
     * Mask số tài khoản cho logging an toàn
     */
    private String maskAccountNumber(String accountNumber) {
        if (accountNumber == null || accountNumber.length() < 4) {
            return "****";
        }
        return "****" + accountNumber.substring(accountNumber.length() - 4);
    }

    /**
     * Tìm kiếm tài khoản ngân hàng với các tiêu chí khác nhau.
     */
    public Page<VendorBankAccountDTO> searchBankAccounts(VendorBankAccountSearchDTO searchDTO, Pageable pageable) {
        log.info("Searching for bank accounts with criteria: {}", searchDTO);

        Specification<VendorBankAccount> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            // Join với bảng Vendor để tìm kiếm theo tên vendor
            Join<VendorBankAccount, Vendor> vendorJoin = root.join("vendor");

            if (searchDTO.getBankCode() != null && !searchDTO.getBankCode().isBlank()) {
                predicates.add(cb.equal(root.get("bankCode"), searchDTO.getBankCode()));
            }
            if (searchDTO.getAccountName() != null && !searchDTO.getAccountName().isBlank()) {
                predicates.add(cb.like(cb.lower(root.get("accountName")), "%" + searchDTO.getAccountName().toLowerCase() + "%"));
            }
            if (searchDTO.getBankName() != null && !searchDTO.getBankName().isBlank()) {
                predicates.add(cb.like(cb.lower(root.get("bankName")), "%" + searchDTO.getBankName().toLowerCase() + "%"));
            }
            if (searchDTO.getVerificationStatus() != null) {
                predicates.add(cb.equal(root.get("verificationStatus"), searchDTO.getVerificationStatus()));
            }
            if (searchDTO.getVendorName() != null && !searchDTO.getVendorName().isBlank()) {
                String searchTerm = "%" + searchDTO.getVendorName().toLowerCase() + "%";
                Predicate shopNameLike = cb.like(cb.lower(vendorJoin.get("shopName")), searchTerm);
                // Có thể tìm theo tên vendor hoặc tên shop
                Predicate firstNameLike = cb.like(cb.lower(vendorJoin.get("firstName")), searchTerm);
                Predicate lastNameLike = cb.like(cb.lower(vendorJoin.get("lastName")), searchTerm);
                predicates.add(cb.or(shopNameLike, firstNameLike, lastNameLike));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };

        Page<VendorBankAccount> results = bankAccountRepository.findAll(spec, pageable);
        return results.map(account -> mapToDTO(account, account.getVendor().getKeycloakId()));
    }
}
