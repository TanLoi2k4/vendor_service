package com.tlcn.vendor_service.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Keycloak JWT to Spring GrantedAuthority converter
 * Extracts roles from JWT realm_access claims
 */
@Slf4j
public class KeycloakConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    @SuppressWarnings("unchecked")
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().get("realm_access");
        if (realmAccess == null || realmAccess.isEmpty()) {
            log.debug("No realm_access found in JWT claims");
            return Collections.emptyList();
        }
        List<String> roles = (List<String>) realmAccess.get("roles");
        if (roles == null) {
            log.debug("No roles found in realm_access");
            return Collections.emptyList();
        }
        log.info("Converted roles: {}", roles);
        return roles.stream()
                .map(roleName -> new SimpleGrantedAuthority("ROLE_" + roleName)) 
                .collect(Collectors.toList());
    }
}
