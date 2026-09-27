# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project state

This is a Spring Boot 4.1.1 (Java 21) Maven project named `auth`, intended to become an OAuth2/OIDC authorization server (Spring Authorization Server) plus a custom user/role domain. Package root: `com.center.auth`. Currently implemented: the persistence layer, and a custom (non-Spring-Authorization-Server) email/password registration + login API that issues RS256-signed JWT access/refresh tokens. The `oauth2_registered_client`/`oauth2_authorization`/`oauth2_authorization_consent` tables exist in the schema but nothing uses them yet — no `RegisteredClientRepository`/authorization-code/client-credentials flow is wired up.

## Commands

Use the Maven wrapper (`./mvnw`), not a system-installed Maven.

- Build: `./mvnw clean package`
- Run the app: `./mvnw spring-boot:run`
- Run all tests: `./mvnw test`
- Run a single test class: `./mvnw test -Dtest=AuthApplicationTests`
- Run a single test method: `./mvnw test -Dtest=AuthApplicationTests#contextLoads`

Requires a running PostgreSQL instance (Flyway runs migrations on startup; `spring.jpa.hibernate.ddl-auto=validate` means Hibernate never generates schema — all schema changes go through Flyway migrations). Connection is configured via `DB_URL`/`DB_USERNAME`/`DB_PASSWORD` env vars (see `application.properties` for local defaults). Locally, Postgres runs via a docker-compose service (`rag-postgres`, `pgvector/pgvector:pg18` image, shared with an unrelated RAG project) exposing port 5432 with role `vectorda`/`vectorda`; a dedicated `auth` database was created inside that same instance (`CREATE DATABASE auth OWNER vectorda;`) so this app's schema doesn't mix with the RAG project's tables.

## Architecture notes

- Domain-driven package structure under `com.center.auth` (not layered by technical role):
  - `user` — `User` entity, `UserStatus` enum, `UserRepository`
  - `role` — `Role` entity
  - `auth` — registration/login/refresh: `AuthController` (`POST /api/auth/register|login|refresh`), `AuthService`, request/response DTOs
  - `security` — JWT plumbing shared across domains: `JwtProperties` (`@ConfigurationProperties(prefix = "jwt")`), `JwtConfig` (loads the RSA key pair, builds the `JwtEncoder` bean), `TokenService` (issues/verifies access & refresh JWTs), `SecurityConfig` (`SecurityFilterChain`, `PasswordEncoder`), `InvalidTokenException`
  - `common/audit` — `Auditable` `@MappedSuperclass` (`createdAt`/`updatedAt` via Spring Data JPA auditing)
  - `config` — cross-cutting Spring config (`JpaAuditingConfig` enables `@EnableJpaAuditing`)
  - New domains should follow the `user`/`role`/`auth` pattern: one package per domain containing that domain's entity, repository, service, controller, and DTOs together, rather than global `controller`/`service`/`repository` packages.
- `User` and `Role` are linked many-to-many through the `user_roles` join table (mapped via `@JoinTable` on `User.roles`).
- `User.provider`/`providerId` support future social login (Google/GitHub/etc.) alongside local password auth; `(provider, provider_id)` is unique together, as is `email`.
- Flyway migrations live in `src/main/resources/db/migration` (`V1__init_schema.sql`). This first migration defines the custom `users`/`roles`/`user_roles` tables *and* the standard Spring Authorization Server JDBC schema (`oauth2_registered_client`, `oauth2_authorization`, `oauth2_authorization_consent`) so that `JdbcRegisteredClientRepository`/`JdbcOAuth2AuthorizationService` can be wired in directly once the `security` package is built out. The token/metadata `blob` columns from the upstream default schema are `TEXT` here (Postgres has no `blob` type, and these columns hold base64/JSON strings, not binary data).
- **JWT auth**: RS256, asymmetric. Private key (`src/main/resources/certs/private_key.pem`, PKCS8) signs both access and refresh tokens via a manually-defined `JwtEncoder` bean (`JwtConfig`) — Spring Boot has no auto-configuration for token *issuing*, only for verification. Public key (`certs/public_key.pem`, X.509) verifies: it's wired into `spring.security.oauth2.resourceserver.jwt.public-key-location`, which auto-configures the `JwtDecoder` bean used both by `SecurityConfig`'s resource-server filter (protects every route except `/api/auth/**`) and by `TokenService` (to validate refresh tokens). Claims: `sub` = user ID (stable identifier, not email), plus `email`, `roles`, `token_type` (`access` or `refresh` — checked on refresh so an access token can't be replayed as a refresh token). TTLs and key/issuer locations are configurable via `jwt.*` properties / `JWT_*` env vars (see `application.properties`); defaults are 15m access / 7d refresh.
  - `certs/public_key.pem` is committed (not sensitive). `certs/private_key.pem` is gitignored and must be generated locally — it won't exist after a fresh clone. Regenerate the pair with:
    ```
    openssl genrsa -out temp_rsa.pem 2048
    openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in temp_rsa.pem -out src/main/resources/certs/private_key.pem
    openssl rsa -in temp_rsa.pem -pubout -out src/main/resources/certs/public_key.pem
    rm temp_rsa.pem
    ```
    This is a dev-only placeholder key pair regardless — regenerate and inject a real key pair via env vars (never commit) before any non-local deployment.
  - `AuthService` is `@Transactional`: `User.roles` is a lazy `@ManyToMany`, and with `spring.jpa.open-in-view=false` the Hibernate session closes as soon as a repository call returns, so `TokenService` reading `user.getRoles()` outside a transaction throws `LazyInitializationException`. Keep the whole login/refresh use case (repository fetch → token generation) inside one transaction rather than fetching roles eagerly.
- Dependencies added for auth: `spring-boot-starter-security`, `spring-boot-starter-oauth2-resource-server` (brings Nimbus JOSE/JWT, `JwtEncoder`/`JwtDecoder`), `spring-boot-starter-validation` (`@Valid` on request DTOs). `spring.mvc.problemdetails.enabled=true` gives RFC 7807 JSON bodies for both validation failures and `ResponseStatusException`s thrown from `AuthService`, with no custom `@ControllerAdvice` needed.
- Other dependencies: `spring-boot-starter-web` (embedded Tomcat on port 8080 — without a web/reactive starter the JVM exits right after context startup since nothing keeps it alive), `spring-boot-starter-data-jpa`, `postgresql` driver, `spring-boot-flyway` + `flyway-core` + `flyway-database-postgresql`.
- **Important Spring Boot 4.x gotcha**: unlike Spring Boot 3.x, having `flyway-core` on the classpath is *not* enough to get Flyway auto-configuration. Spring Boot 4 split its autoconfigure jar into many per-feature modules, and Flyway's (`FlywayAutoConfiguration`, package `org.springframework.boot.flyway.autoconfigure`) now lives in its own `org.springframework.boot:spring-boot-flyway` module, which must be added explicitly — otherwise Flyway silently never runs (no error, no log output) and Hibernate's schema validation fails with "missing table" on startup. Similarly, Flyway 10+ requires `flyway-database-postgresql` alongside `flyway-core` for Postgres support specifically.
