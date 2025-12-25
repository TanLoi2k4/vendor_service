package com.tlcn.vendor_service.controller;

import com.tlcn.vendor_service.dto.ResponseDTO;
import com.tlcn.vendor_service.model.Vendor;
import com.tlcn.vendor_service.service.AdminVendorService;
import com.tlcn.vendor_service.enums.VendorStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/vendors/admin")
@RequiredArgsConstructor
public class AdminVendorController {

    private final AdminVendorService adminVendorService;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ResponseDTO<?>> listVendors(
            @RequestParam(required = false) VendorStatus status,
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy
    ) {
        ResponseDTO<?> resp = adminVendorService.getAllVendors(status, search, page, size, sortBy);
        return ResponseEntity.ok(resp);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ResponseDTO<Vendor>> getVendor(@PathVariable Long id) {
        ResponseDTO<Vendor> resp = adminVendorService.getVendorById(id);
        return ResponseEntity.ok(resp);
    }

    @PutMapping("/{id}/status")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ResponseDTO<Vendor>> updateStatus(@PathVariable Long id, @RequestParam VendorStatus status) {
        ResponseDTO<Vendor> resp = adminVendorService.updateVendorStatus(id, status);
        return ResponseEntity.ok(resp);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ResponseDTO<Vendor>> updateVendorInfo(@PathVariable Long id, @RequestBody Vendor request) {
        ResponseDTO<Vendor> resp = adminVendorService.updateVendorInfo(id, request);
        return ResponseEntity.ok(resp);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ResponseDTO<String>> deleteVendor(@PathVariable Long id) {
        ResponseDTO<String> resp = adminVendorService.softDeleteVendor(id);
        return ResponseEntity.ok(resp);
    }
}
