// VendorController.java
package com.tlcn.vendor_service.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tlcn.vendor_service.dto.*;
import com.tlcn.vendor_service.model.Vendor;
import com.tlcn.vendor_service.service.VendorService;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/vendors")
public class VendorController {

    @Autowired
    private VendorService vendorService;

    @PostMapping(value = "/register-init", consumes = "multipart/form-data")
    public ResponseEntity<ResponseDTO<String>> registerInit(@RequestPart("request") String requestJson, @RequestPart(required = false) MultipartFile logo) {
        try {
            VendorRequest request = new ObjectMapper().readValue(requestJson, VendorRequest.class);
            String initToken = vendorService.registerInit(request, logo);
            return ResponseEntity.ok(new ResponseDTO<>(true, "Registration initialized", initToken));
        } catch (JsonProcessingException e) {
            throw new VendorService.CustomException("Invalid request format: " + e.getMessage());
        }
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<ResponseDTO<Void>> resendOtp(@RequestParam String email, @RequestParam String initToken) {
        vendorService.resendOtp(email, initToken);
        return ResponseEntity.ok(new ResponseDTO<>(true, "OTP resent", null));
    }

    @PostMapping("/forget-password/resend-otp")
    public ResponseEntity<ResponseDTO<Void>> resendForgetPasswordOtp(@RequestParam String email) {
        vendorService.resendForgetPasswordOtp(email);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Reset OTP resent", null));
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<ResponseDTO<?>> verifyOtp(@RequestParam String email, @RequestParam String otp, @RequestParam String initToken, @RequestParam(defaultValue = "false") boolean autoRegister) {
        Object result = vendorService.verifyOtp(email, otp, initToken, autoRegister);
        if (result instanceof Vendor vendor) {
            return ResponseEntity.ok(new ResponseDTO<>(true, "Registered successfully", vendor));
        } else {
            return ResponseEntity.ok(new ResponseDTO<>(true, "OTP verified", result));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<ResponseDTO<AccessTokenResponse>> login(@RequestParam String username, @RequestParam String password) {
        AccessTokenResponse token = vendorService.login(username, password);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Login successful", token));
    }

    @PostMapping("/forget-password")
    public ResponseEntity<ResponseDTO<Void>> forgetPassword(@Valid @RequestBody ForgetPasswordRequest request) {
        vendorService.forgetPassword(request);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Reset OTP sent", null));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ResponseDTO<Void>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        vendorService.resetPassword(request);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Password reset successful", null));
    }

    @PutMapping(value = "/{id}/profile", consumes = "multipart/form-data")
    public ResponseEntity<ResponseDTO<Vendor>> updateProfile(
            @PathVariable Long id,
            @RequestPart("request") String requestJson,
            @RequestPart(value = "logo", required = false) MultipartFile logo
    ) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            VendorUpdateProfileRequest request = mapper.readValue(requestJson, VendorUpdateProfileRequest.class);
            Vendor updated = vendorService.updateProfile(id, request, logo);
            return ResponseEntity.ok(new ResponseDTO<>(true, "Profile updated", updated));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ResponseDTO<>(false, "Invalid request: " + e.getMessage(), null));
        }
    }

    @PutMapping("/{id}/account")
    public ResponseEntity<ResponseDTO<Vendor>> updateAccount(@PathVariable Long id, @Valid @RequestBody VendorUpdateAccountRequest request) {
        Vendor updated = vendorService.updateAccount(id, request);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Account updated", updated));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ResponseDTO<Vendor>> getVendorById(@PathVariable Long id) {
        Vendor vendor = vendorService.getVendorById(id);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Vendor retrieved", vendor));
    }

    @PostMapping("/logout")
    public ResponseEntity<ResponseDTO<Void>> logout(@RequestHeader("Authorization") String authorizationHeader, @RequestParam String refreshToken) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new VendorService.CustomException("Invalid or missing Authorization header");
        }
        String accessToken = authorizationHeader.replace("Bearer ", "");
        vendorService.logout(accessToken, refreshToken);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Logout successful", null));
    }
}