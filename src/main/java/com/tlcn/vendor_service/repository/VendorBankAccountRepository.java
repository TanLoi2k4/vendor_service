package com.tlcn.vendor_service.repository;

import com.tlcn.vendor_service.model.VendorBankAccount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface VendorBankAccountRepository extends JpaRepository<VendorBankAccount, Long>, JpaSpecificationExecutor<VendorBankAccount> {
    Optional<VendorBankAccount> findFirstByVendorIdAndIsVerifiedTrue(Long vendorId);
    Optional<VendorBankAccount> findByAccountNumber(String accountNumber);
    Optional<VendorBankAccount> findFirstByVendorId(Long vendorId);
    List<VendorBankAccount> findByVendorIdAndIsVerified(Long vendorId, boolean isVerified);

    @Query("SELECT vba FROM VendorBankAccount vba JOIN vba.vendor v WHERE vba.id = :accountId AND v.keycloakId = :vendorKeycloakId")
    Optional<VendorBankAccount> findByIdAndVendorKeycloakId(@Param("accountId") Long accountId, @Param("vendorKeycloakId") String vendorKeycloakId);
}