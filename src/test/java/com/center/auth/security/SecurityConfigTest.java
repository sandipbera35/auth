package com.center.auth.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityConfigTest {

    @Test
    void mapsRolesClaimToRoleAuthorities() {
        JwtAuthenticationConverter converter = new SecurityConfig().jwtAuthenticationConverter();

        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .subject("1")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .claim("roles", List.of("USER", "ADMIN"))
                .build();

        List<GrantedAuthority> authorities = List.copyOf(converter.convert(jwt).getAuthorities());

        // JwtAuthenticationConverter also adds its own FACTOR_BEARER authority (Spring Security's
        // authentication-factor marker for bearer tokens) independent of our roles-claim mapping.
        assertThat(authorities)
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    void userWithNoRolesGetsNoRoleAuthorities() {
        JwtAuthenticationConverter converter = new SecurityConfig().jwtAuthenticationConverter();

        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .subject("1")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .claim("roles", List.<String>of())
                .build();

        List<GrantedAuthority> authorities = List.copyOf(converter.convert(jwt).getAuthorities());

        assertThat(authorities)
                .extracting(GrantedAuthority::getAuthority)
                .noneMatch(authority -> authority.startsWith("ROLE_"));
    }
}
