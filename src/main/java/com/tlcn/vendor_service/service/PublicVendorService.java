package com.tlcn.vendor_service.service;

import com.tlcn.vendor_service.client.ProductServiceClient;
import com.tlcn.vendor_service.client.ProductVendorRatingStats;
import com.tlcn.vendor_service.dto.PublicVendorProfile;
import com.tlcn.vendor_service.dto.ResponseDTO;
import com.tlcn.vendor_service.enums.VendorStatus;
import com.tlcn.vendor_service.exception.ResourceNotFoundException;
import com.tlcn.vendor_service.model.Vendor;
import com.tlcn.vendor_service.repository.VendorRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class PublicVendorService {

    private static final Set<String> ALLOWED_SORT = Set.of("createdAt", "shopName", "rating");

    private final VendorRepository vendorRepository;
    private final ProductServiceClient productServiceClient;

    @Transactional(readOnly = true)
    public ResponseDTO<PublicVendorProfile> getByKeycloakId(String keycloakId) {
        Vendor vendor = vendorRepository
                .findByKeycloakIdAndStatus(keycloakId, VendorStatus.ACTIVE)
                .orElseThrow(() -> new ResourceNotFoundException("Vendor", keycloakId));

        return new ResponseDTO<>(true, "Vendor found", enrichProfiles(List.of(vendor)).get(0));
    }

    @Transactional(readOnly = true)
    public ResponseDTO<Page<PublicVendorProfile>> list(String search, int page, int size, String sortBy) {
        String safeSort = ALLOWED_SORT.contains(sortBy) ? sortBy : "createdAt";
        if ("rating".equals(safeSort)) {
            return listByRating(search, page, size);
        }

        Pageable pageable = PageRequest.of(Math.max(0, page), Math.min(Math.max(size, 1), 50),
                Sort.by(safeSort).descending());

        Page<Vendor> vendors;
        if (search != null && !search.isBlank()) {
            vendors = vendorRepository.findByStatusAndShopNameContainingIgnoreCase(
                    VendorStatus.ACTIVE, search.trim(), pageable);
        } else {
            vendors = vendorRepository.findByStatus(VendorStatus.ACTIVE, pageable);
        }

        List<PublicVendorProfile> profiles = enrichProfiles(vendors.getContent());
        Page<PublicVendorProfile> mapped = new PageImpl<>(profiles, pageable, vendors.getTotalElements());
        return new ResponseDTO<>(true, "Vendor list loaded", mapped);
    }

    /** Keycloak IDs of every active vendor. Used by communication-service to broadcast notifications. */
    @Transactional(readOnly = true)
    public ResponseDTO<List<String>> getActiveVendorKeycloakIds() {
        return new ResponseDTO<>(true, "OK", vendorRepository.findKeycloakIdByStatus(VendorStatus.ACTIVE));
    }

    @Transactional(readOnly = true)
    public ResponseDTO<List<PublicVendorProfile>> batchByKeycloakIds(List<String> keycloakIds) {
        List<String> ids = keycloakIds.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .distinct()
                .limit(100)
                .collect(Collectors.toList());

        if (ids.isEmpty()) {
            return new ResponseDTO<>(true, "No vendors", List.of());
        }

        List<PublicVendorProfile> profiles = enrichProfiles(
                vendorRepository.findByKeycloakIdInAndStatus(ids, VendorStatus.ACTIVE)
        );

        return new ResponseDTO<>(true, "Vendors loaded", profiles);
    }

    private ResponseDTO<Page<PublicVendorProfile>> listByRating(String search, int page, int size) {
        int pageIndex = Math.max(0, page);
        int pageSize = Math.min(Math.max(size, 1), 50);
        String searchTerm = search != null ? search.trim() : "";

        List<String> rankedIds = productServiceClient.getTopRatedVendorKeycloakIds(100);
        List<PublicVendorProfile> rankedProfiles = loadProfilesInOrder(rankedIds, searchTerm);

        if (rankedProfiles.isEmpty()) {
            return list(search, page, size, "createdAt");
        }

        int from = pageIndex * pageSize;
        if (from >= rankedProfiles.size()) {
            return new ResponseDTO<>(true, "Vendor list loaded",
                    new PageImpl<>(List.of(), PageRequest.of(pageIndex, pageSize), rankedProfiles.size()));
        }

        int to = Math.min(from + pageSize, rankedProfiles.size());
        List<PublicVendorProfile> pageContent = rankedProfiles.subList(from, to);
        Page<PublicVendorProfile> result = new PageImpl<>(pageContent, PageRequest.of(pageIndex, pageSize), rankedProfiles.size());
        return new ResponseDTO<>(true, "Vendor list loaded", result);
    }

    private List<PublicVendorProfile> loadProfilesInOrder(List<String> keycloakIds, String searchTerm) {
        if (keycloakIds.isEmpty()) {
            return List.of();
        }

        Map<String, Vendor> vendorsById = vendorRepository
                .findByKeycloakIdInAndStatus(keycloakIds, VendorStatus.ACTIVE)
                .stream()
                .collect(Collectors.toMap(Vendor::getKeycloakId, Function.identity(), (a, b) -> a, LinkedHashMap::new));

        List<Vendor> orderedVendors = new ArrayList<>();
        for (String keycloakId : keycloakIds) {
            Vendor vendor = vendorsById.get(keycloakId);
            if (vendor == null) {
                continue;
            }
            if (!searchTerm.isEmpty()
                    && (vendor.getShopName() == null
                    || !vendor.getShopName().toLowerCase().contains(searchTerm.toLowerCase()))) {
                continue;
            }
            orderedVendors.add(vendor);
        }

        return enrichProfiles(orderedVendors);
    }

    private List<PublicVendorProfile> enrichProfiles(List<Vendor> vendors) {
        if (vendors.isEmpty()) {
            return List.of();
        }

        List<String> keycloakIds = vendors.stream()
                .map(Vendor::getKeycloakId)
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(id -> !id.isEmpty())
                .distinct()
                .collect(Collectors.toList());

        Map<String, ProductVendorRatingStats> ratings = productServiceClient.getVendorRatings(keycloakIds);

        return vendors.stream()
                .map(vendor -> enrichProfile(vendor, ratings))
                .collect(Collectors.toList());
    }

    private PublicVendorProfile enrichProfile(Vendor vendor, Map<String, ProductVendorRatingStats> ratings) {
        ProductVendorRatingStats stats = ratings.get(vendor.getKeycloakId());
        double rating = stats != null && stats.getRating() != null ? stats.getRating() : 0.0;
        long reviewCount = stats != null && stats.getReviewCount() != null ? stats.getReviewCount() : 0L;
        return PublicVendorProfile.fromEntity(vendor, rating, reviewCount);
    }
}
