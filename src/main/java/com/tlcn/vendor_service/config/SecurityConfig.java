package com.tlcn.vendor_service.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus; 
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy; 
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint; 
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private RedisTemplate<String, String> redisTemplate;


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
                    "/vendors/register-init",
                    "/vendors/verify-otp/**",
                    "/vendors/resend-otp",
                    "/vendors/forget-password/**",
                    "/vendors/reset-password",
                    "/vendors/login",
                    "/actuator/**"
                ).permitAll()
                
                // All other /api/vendors/** endpoints require authentication, 
                // and the @PreAuthorize on the controller methods will handle the 'VENDOR' role check.
                .requestMatchers("/vendors/**").authenticated() 
                
                // Any other request outside /api/vendors requires authentication too
                .anyRequest().authenticated()
            )
            
            .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter))
            .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
        )
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .exceptionHandling(exceptions -> exceptions
            .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
        )
        .addFilterBefore(new JwtBlacklistFilter(redisTemplate), BasicAuthenticationFilter.class);

    return http.build();
    }
}