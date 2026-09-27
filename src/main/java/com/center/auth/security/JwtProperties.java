package com.center.auth.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

import java.time.Duration;

@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(
        Resource privateKeyLocation,
        Resource publicKeyLocation,
        String privateKey,
        String publicKey,
        String issuer,
        Duration accessTokenTtl,
        Duration refreshTokenTtl
) {
}
