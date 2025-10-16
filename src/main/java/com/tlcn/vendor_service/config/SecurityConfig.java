package com.tlcn.vendor_service.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus; // ADD THIS
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy; // ADD THIS
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint; // ADD THIS
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    // Remove the publicSecurityFilterChain and apiSecurityFilterChain beans
    // and use a single, consolidated SecurityFilterChain.

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // 1. JWT Converter Setup
        JwtAuthenticationConverter jwtAuthConverter = new JwtAuthenticationConverter();
        jwtAuthConverter.setJwtGrantedAuthoritiesConverter(new KeycloakConverter());

        http
            .csrf(csrf -> csrf.disable())
            
            // 2. Authorization Rules
            .authorizeHttpRequests(auth -> auth
                // Public Endpoints (Order is important here: specific to general)
                .requestMatchers(
                    "/api/vendors/register-init",
                    "/api/vendors/verify-otp",
                    "/api/vendors/resend-otp",
                    "/api/vendors/forget-password",
                    "/api/vendors/forget-password/resend-otp", 
                    "/api/vendors/reset-password",
                    "/api/vendors/login",
                    "/actuator/**"
                ).permitAll()
                
                // All other /api/vendors/** endpoints require authentication, 
                // and the @PreAuthorize on the controller methods will handle the 'VENDOR' role check.
                .requestMatchers("/api/vendors/**").authenticated() 
                
                // Any other request outside /api/vendors requires authentication too
                .anyRequest().authenticated()
            )
            
            // 3. Resource Server (JWT/Keycloak) Configuration
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter))
            )
            
            // 4. Session Management (Stateless for REST API)
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            
            // 5. CRITICAL FIX: Exception Handling
            // This prevents Spring from trying to find a static resource and returns a 401 instead.
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            )
            
            // 6. Custom Filter for JWT Blacklisting (Logout)
            .addFilterBefore(new JwtBlacklistFilter(redisTemplate), BasicAuthenticationFilter.class);

        return http.build();
    }
}