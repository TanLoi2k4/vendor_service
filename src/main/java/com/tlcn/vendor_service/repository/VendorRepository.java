package com.tlcn.vendor_service.repository;

import com.tlcn.vendor_service.enums.VendorStatus;
import com.tlcn.vendor_service.model.Vendor;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface VendorRepository extends JpaRepository<Vendor, Long> {
    boolean existsByUsernameOrEmail(String username, String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
    Optional<Vendor> findByEmail(String email);
    Optional<Vendor> findByUsername(String username);
    Optional<Vendor> findByKeycloakId(String keycloakId);
    Page<Vendor> findByStatus(VendorStatus status, Pageable pageable);
    Page<Vendor> findByUsernameContainingIgnoreCase(String username, Pageable pageable);
    Page<Vendor> findByStatusAndUsernameContainingIgnoreCase(VendorStatus status, String username, Pageable pageable);
}