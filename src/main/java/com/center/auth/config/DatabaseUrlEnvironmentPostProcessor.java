package com.center.auth.config;

import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Translates a single Postgres connection URI - {@code postgres(ql)://user:pass@host:port/db},
 * the format Railway (and Heroku before it) hands out as DATABASE_URL/DATABASE_PRIVATE_URL -
 * into the discrete spring.datasource.* properties Spring actually needs. spring.datasource.url
 * requires a jdbc:postgresql:// URL with username/password as separate properties; Spring has no
 * built-in support for parsing a bare postgres:// URI, so without this, a platform that only
 * offers one combined connection variable can't be wired in directly.
 * <p>
 * Only takes effect if a DATABASE_URL env var is present (registered via
 * META-INF/spring.factories); local dev and the existing DB_URL/DB_USERNAME/DB_PASSWORD
 * properties are unaffected either way.
 */
public class DatabaseUrlEnvironmentPostProcessor implements EnvironmentPostProcessor {

    private static final String SOURCE_PROPERTY = "DATABASE_URL";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        String databaseUrl = environment.getProperty(SOURCE_PROPERTY);
        if (!StringUtils.hasText(databaseUrl)) {
            return;
        }

        URI uri;
        try {
            uri = new URI(databaseUrl);
        } catch (URISyntaxException ex) {
            throw new IllegalStateException("Malformed " + SOURCE_PROPERTY, ex);
        }

        StringBuilder jdbcUrl = new StringBuilder("jdbc:postgresql://")
                .append(uri.getHost()).append(':').append(uri.getPort()).append(uri.getPath());
        if (uri.getQuery() != null) {
            jdbcUrl.append('?').append(uri.getQuery());
        }

        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("spring.datasource.url", jdbcUrl.toString());

        if (uri.getUserInfo() != null) {
            String[] userInfo = uri.getUserInfo().split(":", 2);
            properties.put("spring.datasource.username", userInfo[0]);
            if (userInfo.length > 1) {
                properties.put("spring.datasource.password", userInfo[1]);
            }
        }

        environment.getPropertySources().addFirst(new MapPropertySource("databaseUrl", properties));
    }
}
