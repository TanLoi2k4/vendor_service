package com.tlcn.vendor_service.controller;

import com.tlcn.vendor_service.dto.ResponseDTO;
import com.tlcn.vendor_service.dto.VendorBankAccountDTO;
import com.tlcn.vendor_service.dto.VendorBankAccountSearchDTO;
import com.tlcn.vendor_service.enums.AccountVerificationStatus;
import com.tlcn.vendor_service.service.VendorBankAccountService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/vendors")
@RequiredArgsConstructor
@Slf4j
public class VendorBankAccountController {
    
    private final VendorBankAccountService bankAccountService;
    
    /**
     * [VENDOR] Lấy tài khoản bank đã xác thực của mình.
     * GET /vendors/bank-account/my-verified
     */
    @GetMapping("/bank-account/my-verified")
    @PreAuthorize("hasRole('VENDOR')")
    public ResponseEntity<ResponseDTO<VendorBankAccountDTO>> getMyVerifiedBankAccount(Authentication authentication) {
        String vendorId = authentication.getName();
        VendorBankAccountDTO dto = bankAccountService.getBankAccount(vendorId);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Verified bank account retrieved", dto));
    }
    
    /**
     * Lấy tài khoản bank theo số tài khoản
     * GET /vendors/bank-account/{accountNumber}
     */
    @GetMapping("/bank-account/{accountNumber}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPER_ADMIN')")
    public ResponseEntity<ResponseDTO<VendorBankAccountDTO>> getBankAccountByNumber(@PathVariable String accountNumber) {
        VendorBankAccountDTO dto = bankAccountService.getBankAccountByNumber(accountNumber);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Bank account retrieved by number", dto));
    }
    
    /**
     * [VENDOR] Thêm hoặc cập nhật tài khoản bank của mình.
     * POST /vendors/bank-account
     */
    @PostMapping("/bank-account")
    @PreAuthorize("hasRole('VENDOR')")
    public ResponseEntity<ResponseDTO<VendorBankAccountDTO>> addOrUpdateBankAccount(
            @RequestBody VendorBankAccountDTO dto, Authentication authentication) {
        String vendorId = authentication.getName();
        VendorBankAccountDTO updated = bankAccountService.addOrUpdateBankAccount(vendorId, dto);
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseDTO<>(true, "Bank account saved successfully", updated));
    }
    
    /**
     * [VENDOR] Lấy thông tin tài khoản bank của mình.
     * GET /vendors/bank-account
     */
    @GetMapping("/bank-account")
    @PreAuthorize("hasRole('VENDOR')")
    public ResponseEntity<ResponseDTO<VendorBankAccountDTO>> getMyBankAccount(Authentication authentication) {
        String vendorId = authentication.getName();
        VendorBankAccountDTO account = bankAccountService.getMyBankAccount(vendorId);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Bank account retrieved", account));
    }

    /**
     * [ADMIN] Lấy tài khoản bank đã xác thực của một vendor theo keycloakId.
     * GET /vendors/{vendorKeycloakId}/bank-account/verified
     */
    @GetMapping("/{vendorKeycloakId}/bank-account/verified")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPER_ADMIN')")
    public ResponseEntity<ResponseDTO<VendorBankAccountDTO>> getVerifiedBankAccountByVendorKeycloakId(
            @PathVariable String vendorKeycloakId) {
        VendorBankAccountDTO dto = bankAccountService.getBankAccount(vendorKeycloakId);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Verified bank account retrieved", dto));
    }
    
    /**
     * [ADMIN] Xác thực tài khoản bank của một vendor.
     * POST /vendors/{vendorKeycloakId}/bank-account/verify
     */
    @PostMapping("/{vendorKeycloakId}/bank-account/verify")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPER_ADMIN')")
    public ResponseEntity<ResponseDTO<VendorBankAccountDTO>> verifyBankAccount(
            @PathVariable String vendorKeycloakId,
            @RequestParam(defaultValue = "true") Boolean isValid) {
        VendorBankAccountDTO verified = bankAccountService.verifyBankAccount(vendorKeycloakId, isValid);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Bank account verification updated", verified));
    }
    
    /**
     * [VENDOR] Xóa tài khoản bank của mình.
     * DELETE /vendors/bank-account/{accountId}
     */
    @DeleteMapping("/bank-account/{accountId}")
    @PreAuthorize("hasRole('VENDOR')")
    public ResponseEntity<ResponseDTO<Void>> deleteBankAccount(
            @PathVariable Long accountId, Authentication authentication) {
        String vendorId = authentication.getName();
        bankAccountService.deleteBankAccount(vendorId, accountId);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Bank account deleted", null));
    }

    /**
     * [ADMIN] Lấy danh sách các tài khoản ngân hàng theo các tiêu chí tìm kiếm.
     * GET /vendors/admin/bank-accounts
     */
    @GetMapping("/bank-accounts")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPER_ADMIN')")
    public ResponseEntity<ResponseDTO<Page<VendorBankAccountDTO>>> searchBankAccounts(
            @RequestParam(required = false) String bankCode,
            @RequestParam(required = false) String vendorName,
            @RequestParam(required = false) String accountName,
            @RequestParam(required = false) String bankName,
            @RequestParam(required = false) AccountVerificationStatus verificationStatus,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {

        VendorBankAccountSearchDTO searchDTO = new VendorBankAccountSearchDTO();
        searchDTO.setBankCode(bankCode);
        searchDTO.setVendorName(vendorName);
        searchDTO.setAccountName(accountName);
        searchDTO.setBankName(bankName);
        searchDTO.setVerificationStatus(verificationStatus);

        Page<VendorBankAccountDTO> resultPage = bankAccountService.searchBankAccounts(searchDTO, pageable);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Bank accounts retrieved successfully", resultPage));
    }
}
