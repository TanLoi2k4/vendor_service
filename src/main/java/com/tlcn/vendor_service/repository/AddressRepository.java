package com.tlcn.vendor_service.repository;

import com.tlcn.vendor_service.model.Address;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AddressRepository extends JpaRepository<Address, Long> {
    List<Address> findByVendorId(Long vendorId);
}