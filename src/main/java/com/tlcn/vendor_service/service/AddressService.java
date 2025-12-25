package com.tlcn.vendor_service.service;

import com.tlcn.vendor_service.dto.AddressResponse;
import com.tlcn.vendor_service.dto.AddressRequest;
import com.tlcn.vendor_service.model.Address;
import com.tlcn.vendor_service.repository.AddressRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AddressService {

    private final AddressRepository addressRepository;

    public List<AddressResponse> getVendorAddresses(Long vendorId) {
        List<Address> addresses = addressRepository.findByVendorId(vendorId);
        return addresses.stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    @Transactional
    public AddressResponse addAddress(Long vendorId, AddressRequest request) {
        Address address = new Address();
        address.setVendorId(vendorId);
        address.setStreet(request.getStreet());
        address.setCity(request.getCity());
        address.setCountry(request.getCountry());
        address.setLabel(request.getLabel());

        Address savedAddress = addressRepository.save(address);
        return convertToDTO(savedAddress);
    }

    @Transactional
    public AddressResponse updateAddress(Long addressId, AddressRequest request, Long vendorId) {
        Address address = addressRepository.findById(addressId)
                .orElseThrow(() -> new RuntimeException("Address not found"));

        if (!address.getVendorId().equals(vendorId)) {
            throw new RuntimeException("Address does not belong to vendor");
        }

        address.setStreet(request.getStreet());
        address.setCity(request.getCity());
        address.setCountry(request.getCountry());
        address.setLabel(request.getLabel());

        Address savedAddress = addressRepository.save(address);
        return convertToDTO(savedAddress);
    }

    @Transactional
    public void deleteAddress(Long addressId, Long vendorId) {
        Address address = addressRepository.findById(addressId)
                .orElseThrow(() -> new RuntimeException("Address not found"));

        if (!address.getVendorId().equals(vendorId)) {
            throw new RuntimeException("Address does not belong to vendor");
        }

        addressRepository.delete(address);
    }

    private AddressResponse convertToDTO(Address address) {
        AddressResponse dto = new AddressResponse();
        dto.setId(address.getId());
        dto.setStreet(address.getStreet());
        dto.setCity(address.getCity());
        dto.setCountry(address.getCountry());
        dto.setLabel(address.getLabel());
        return dto;
    }
}