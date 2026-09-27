package com.center.auth.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.util.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
public class JwtConfig {

    private final JwtProperties jwtProperties;

    public JwtConfig(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    /**
     * {@code jwt.private-key} (raw PEM content, e.g. from a JWT_PRIVATE_KEY env var) wins over
     * {@code jwt.private-key-location} when set - the private key is gitignored and won't exist
     * in any built image/container, so cloud deploys need to inject it as an env var rather than
     * a file on the classpath.
     */
    @Bean
    public RSAPrivateKey rsaPrivateKey() throws IOException {
        if (StringUtils.hasText(jwtProperties.privateKey())) {
            return RsaKeyConverters.pkcs8().convert(pemContentStream(jwtProperties.privateKey()));
        }
        try (InputStream in = jwtProperties.privateKeyLocation().getInputStream()) {
            return RsaKeyConverters.pkcs8().convert(in);
        }
    }

    @Bean
    public RSAPublicKey rsaPublicKey() throws IOException {
        if (StringUtils.hasText(jwtProperties.publicKey())) {
            return RsaKeyConverters.x509().convert(pemContentStream(jwtProperties.publicKey()));
        }
        try (InputStream in = jwtProperties.publicKeyLocation().getInputStream()) {
            return RsaKeyConverters.x509().convert(in);
        }
    }

    private static InputStream pemContentStream(String pemContent) {
        // Tolerates a literal "\n"-escaped single-line value (common when pasting a multi-line
        // secret into a UI that doesn't preserve real newlines), alongside real newlines.
        String normalized = pemContent.replace("\\n", "\n");
        return new ByteArrayInputStream(normalized.getBytes(StandardCharsets.UTF_8));
    }

    @Bean
    public JwtEncoder jwtEncoder(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSource<SecurityContext> jwkSource = (selector, context) -> selector.select(new JWKSet(rsaKey));
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * Built from the same {@code rsaPublicKey()} bean the encoder uses - not Spring Boot's
     * autoconfigured JwtDecoder (driven by spring.security.oauth2.resourceserver.jwt.public-key-location,
     * which only reads a location, never raw content) - so verification always matches whichever
     * public key was actually used to sign, regardless of whether it came from JWT_PUBLIC_KEY or
     * the classpath file. This is what makes rotating to a real (non-dev, non-committed) key pair
     * in production possible via env vars alone.
     */
    @Bean
    public JwtDecoder jwtDecoder(RSAPublicKey publicKey) {
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }
}
