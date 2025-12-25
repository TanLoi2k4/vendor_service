package com.tlcn.vendor_service.controller;

import com.tlcn.vendor_service.dto.*;
import com.tlcn.vendor_service.model.Vendor;
import com.tlcn.vendor_service.service.VendorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/vendors")
public class VendorController {

    @Autowired
    private VendorService vendorService;

    @PostMapping(value = "/register-init", consumes = "multipart/form-data")
    public ResponseEntity<ResponseDTO<String>> registerInit(
            @RequestPart("request") VendorRequest request,
            @RequestPart(required = false) MultipartFile logo
    ) {
        String initToken = vendorService.registerInit(request, logo);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Registration initialized", initToken));
    }

    @PostMapping("/verify-otp/resend-otp")
    public ResponseEntity<ResponseDTO<Void>> resendOtp(@RequestBody ResendOtpRequest request) {
        vendorService.resendOtp(request.getEmail(), request.getInitToken());
        return ResponseEntity.ok(new ResponseDTO<>(true, "OTP resent", null));
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<ResponseDTO<?>> verifyOtp(@Valid @RequestBody VerifyOtpRequest request) {
        Object result = vendorService.verifyOtp(
                request.getEmail(),
                request.getOtp(),
                request.getInitToken(),
                request.isAutoRegister()
        );
        if (result instanceof Vendor vendor) {
            return ResponseEntity.ok(new ResponseDTO<>(true, "Registered successfully", vendor));
        } else {
            return ResponseEntity.ok(new ResponseDTO<>(true, "OTP verified", result));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<ResponseDTO<LoginResponse>> login(@Valid @RequestBody LoginRequest request) {
        LoginResponse token = vendorService.login(request.getUsername(), request.getPassword());
        return ResponseEntity.ok(new ResponseDTO<>(true, "Login successful", token));
    }

    @PostMapping("/forget-password")
    public ResponseEntity<ResponseDTO<Void>> forgetPassword(@Valid @RequestBody ForgetPasswordRequest request) {
        vendorService.forgetPassword(request);
        return ResponseEntity.ok(new ResponseDTO<>(true, "If the email exists in our system, you will receive a password reset link.", null));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ResponseDTO<Void>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        vendorService.resetPassword(request);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Password reset successful", null));
    }

    @PutMapping(value = "/profile", consumes = "multipart/form-data")
    @PreAuthorize("hasRole('VENDOR')")
    public ResponseEntity<ResponseDTO<Vendor>> updateProfile(
            @RequestPart("request") VendorUpdateProfileRequest request,
            @RequestPart(value = "logo", required = false) MultipartFile logo,
            Authentication authentication
    ) {
        String keycloakId = authentication.getName();
        Vendor updated = vendorService.updateProfile(keycloakId, request, logo);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Profile updated", updated));
    }

    @PutMapping("/account")
    @PreAuthorize("hasRole('VENDOR')")
    public ResponseEntity<ResponseDTO<Vendor>> updateAccount(
            @Valid @RequestBody VendorUpdateAccountRequest request,
            Authentication authentication
    ) {
        String keycloakId = authentication.getName();
        Vendor updated = vendorService.updateAccount(keycloakId, request);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Account updated", updated));
    }

    @GetMapping
    @PreAuthorize("hasRole('VENDOR')")
    public ResponseEntity<ResponseDTO<Vendor>> getVendorByKeycloakId(Authentication authentication) {
        String keycloakId = authentication.getName(); 
        Vendor vendor = vendorService.getVendorByKeycloakId(keycloakId);
        return ResponseEntity.ok(new ResponseDTO<>(true, "Vendor retrieved", vendor));
    }

    @PostMapping("/logout")
    @PreAuthorize("hasRole('VENDOR')")
    public ResponseEntity<ResponseDTO<Void>> logout(@Valid @RequestBody LogoutRequest request) {
        vendorService.logout(request.getAccessToken(), request.getRefreshToken());
        return ResponseEntity.ok(new ResponseDTO<>(true, "Logout successful", null));
    }
}