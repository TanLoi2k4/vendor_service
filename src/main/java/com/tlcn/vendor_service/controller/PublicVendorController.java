package com.tlcn.vendor_service.controller;

import com.tlcn.vendor_service.dto.PublicVendorBatchRequest;
import com.tlcn.vendor_service.dto.PublicVendorProfile;
import com.tlcn.vendor_service.dto.ResponseDTO;
import com.tlcn.vendor_service.service.PublicVendorService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/vendors/public")
@RequiredArgsConstructor
public class PublicVendorController {

    private final PublicVendorService publicVendorService;

    @GetMapping("/ids")
    public ResponseEntity<ResponseDTO<List<String>>> getActiveVendorIds() {
        return ResponseEntity.ok(publicVendorService.getActiveVendorKeycloakIds());
    }

    @GetMapping("/{keycloakId}")
    public ResponseEntity<ResponseDTO<PublicVendorProfile>> getByKeycloakId(
            @PathVariable String keycloakId
    ) {
        return ResponseEntity.ok(publicVendorService.getByKeycloakId(keycloakId));
    }

    @GetMapping
    public ResponseEntity<ResponseDTO<Page<PublicVendorProfile>>> list(
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "createdAt") String sort
    ) {
        return ResponseEntity.ok(publicVendorService.list(search, page, size, sort));
    }

    @PostMapping("/batch")
    public ResponseEntity<ResponseDTO<List<PublicVendorProfile>>> batch(
            @Valid @RequestBody PublicVendorBatchRequest request
    ) {
        return ResponseEntity.ok(publicVendorService.batchByKeycloakIds(request.getKeycloakIds()));
    }
}