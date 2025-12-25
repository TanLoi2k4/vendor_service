package com.tlcn.vendor_service.controller;

import com.tlcn.vendor_service.dto.AddressResponse;
import com.tlcn.vendor_service.dto.AddressRequest;
import com.tlcn.vendor_service.dto.ResponseDTO;
import com.tlcn.vendor_service.model.Vendor;
import com.tlcn.vendor_service.service.AddressService;
import com.tlcn.vendor_service.service.VendorService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/vendors/addresses")
@RequiredArgsConstructor
public class AddressController {

    private final AddressService addressService;
    private final VendorService vendorService;

    @GetMapping
    @PreAuthorize("hasRole('VENDOR')")
    public ResponseEntity<ResponseDTO<List<AddressResponse>>> getVendorAddresses(Authentication authentication) {
        String keycloakId = authentication.getName();
        Vendor vendor = vendorService.getVendorByKeycloakId(keycloakId);
        List<AddressResponse> addresses = addressService.getVendorAddresses(vendor.getId());
        return ResponseEntity.ok(new ResponseDTO<>(true, "Addresses retrieved successfully", addresses));
    }

    @PostMapping
    @PreAuthorize("hasRole('VENDOR')")
    public ResponseEntity<ResponseDTO<AddressResponse>> addAddress(
            @RequestBody AddressRequest request,
            Authentication authentication) {
        String keycloakId = authentication.getName();
        Vendor vendor = vendorService.getVendorByKeycloakId(keycloakId);
        AddressResponse address = addressService.addAddress(vendor.getId(), request);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Address added successfully", address));
    }

    @PutMapping("/{addressId}")
    @PreAuthorize("hasRole('VENDOR')")
    public ResponseEntity<ResponseDTO<AddressResponse>> updateAddress(
            @PathVariable Long addressId,
            @RequestBody AddressRequest request,
            Authentication authentication) {
        String keycloakId = authentication.getName();
        Vendor vendor = vendorService.getVendorByKeycloakId(keycloakId);
        AddressResponse address = addressService.updateAddress(addressId, request, vendor.getId());
        return ResponseEntity.ok(new ResponseDTO<>(true, "Address updated successfully", address));
    }

    @DeleteMapping("/{addressId}")
    @PreAuthorize("hasRole('VENDOR')")
    public ResponseEntity<ResponseDTO<Void>> deleteAddress(
            @PathVariable Long addressId,
            Authentication authentication) {
        String keycloakId = authentication.getName();
        Vendor vendor = vendorService.getVendorByKeycloakId(keycloakId);
        addressService.deleteAddress(addressId, vendor.getId());
        return ResponseEntity.ok(new ResponseDTO<>(true, "Address deleted successfully", null));
    }
}