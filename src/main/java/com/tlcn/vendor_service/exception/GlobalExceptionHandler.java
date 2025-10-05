package com.tlcn.vendor_service.exception;

import com.tlcn.vendor_service.dto.ResponseDTO;
import com.tlcn.vendor_service.service.VendorService;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(VendorService.CustomException.class)
    public ResponseEntity<ResponseDTO<Void>> handleCustomException(VendorService.CustomException ex) {
        return ResponseEntity.badRequest().body(new ResponseDTO<>(false, ex.getMessage(), null));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ResponseDTO<Void>> handleValidationException(MethodArgumentNotValidException ex) {
        StringBuilder errorMsg = new StringBuilder();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            if (error instanceof FieldError) {
                errorMsg.append(((FieldError) error).getField()).append(": ").append(error.getDefaultMessage()).append("; ");
            }
        });
        return ResponseEntity.badRequest().body(new ResponseDTO<>(false, errorMsg.toString(), null));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ResponseDTO<Void>> handleGeneralException(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ResponseDTO<>(false, "Internal error: " + ex.getMessage(), null));
    }
}