-- =========================================================================
-- Custom application schema
-- =========================================================================

CREATE TABLE users (
    id                  BIGSERIAL PRIMARY KEY,
    email               VARCHAR(255)  NOT NULL,
    password_hash       VARCHAR(255),
    provider            VARCHAR(50)   NOT NULL DEFAULT 'local',
    provider_id         VARCHAR(255),
    first_name          VARCHAR(100),
    last_name           VARCHAR(100),
    profile_photo_url   VARCHAR(500),
    cover_photo_url     VARCHAR(500),
    bio                 TEXT,
    email_verified      BOOLEAN       NOT NULL DEFAULT FALSE,
    status              VARCHAR(30)   NOT NULL DEFAULT 'ACTIVE',
    created_at          TIMESTAMP     NOT NULL DEFAULT now(),
    updated_at          TIMESTAMP     NOT NULL DEFAULT now(),

    CONSTRAINT uk_users_email UNIQUE (email),
    CONSTRAINT uk_users_provider_provider_id UNIQUE (provider, provider_id)
);

CREATE TABLE roles (
    id          BIGSERIAL PRIMARY KEY,
    name        VARCHAR(50)  NOT NULL,
    description VARCHAR(255),
    created_at  TIMESTAMP    NOT NULL DEFAULT now(),
    updated_at  TIMESTAMP    NOT NULL DEFAULT now(),

    CONSTRAINT uk_roles_name UNIQUE (name)
);

CREATE TABLE user_roles (
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,

    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);

-- =========================================================================
-- Spring Authorization Server JDBC schema
-- (mirrors the default schema shipped by spring-security-oauth2-authorization-server;
--  the "blob" columns from the upstream H2 script are TEXT here since they hold
--  base64/JSON string values rather than binary data)
-- =========================================================================

CREATE TABLE oauth2_registered_client (
    id                              VARCHAR(100)  NOT NULL,
    client_id                       VARCHAR(100)  NOT NULL,
    client_id_issued_at             TIMESTAMP     NOT NULL DEFAULT now(),
    client_secret                   VARCHAR(200)  DEFAULT NULL,
    client_secret_expires_at        TIMESTAMP     DEFAULT NULL,
    client_name                     VARCHAR(200)  NOT NULL,
    client_authentication_methods   VARCHAR(1000) NOT NULL,
    authorization_grant_types       VARCHAR(1000) NOT NULL,
    redirect_uris                   VARCHAR(1000) DEFAULT NULL,
    post_logout_redirect_uris       VARCHAR(1000) DEFAULT NULL,
    scopes                          VARCHAR(1000) NOT NULL,
    client_settings                 VARCHAR(2000) NOT NULL,
    token_settings                  VARCHAR(2000) NOT NULL,

    PRIMARY KEY (id)
);

CREATE TABLE oauth2_authorization (
    id                              VARCHAR(100)  NOT NULL,
    registered_client_id            VARCHAR(100)  NOT NULL,
    principal_name                  VARCHAR(200)  NOT NULL,
    authorization_grant_type        VARCHAR(100)  NOT NULL,
    authorized_scopes               VARCHAR(1000) DEFAULT NULL,
    attributes                      TEXT          DEFAULT NULL,
    state                           VARCHAR(500)  DEFAULT NULL,

    authorization_code_value        TEXT          DEFAULT NULL,
    authorization_code_issued_at    TIMESTAMP     DEFAULT NULL,
    authorization_code_expires_at   TIMESTAMP     DEFAULT NULL,
    authorization_code_metadata     TEXT          DEFAULT NULL,

    access_token_value              TEXT          DEFAULT NULL,
    access_token_issued_at          TIMESTAMP     DEFAULT NULL,
    access_token_expires_at         TIMESTAMP     DEFAULT NULL,
    access_token_metadata           TEXT          DEFAULT NULL,
    access_token_type               VARCHAR(100)  DEFAULT NULL,
    access_token_scopes             VARCHAR(1000) DEFAULT NULL,

    oidc_id_token_value             TEXT          DEFAULT NULL,
    oidc_id_token_issued_at         TIMESTAMP     DEFAULT NULL,
    oidc_id_token_expires_at        TIMESTAMP     DEFAULT NULL,
    oidc_id_token_metadata          TEXT          DEFAULT NULL,

    refresh_token_value             TEXT          DEFAULT NULL,
    refresh_token_issued_at         TIMESTAMP     DEFAULT NULL,
    refresh_token_expires_at        TIMESTAMP     DEFAULT NULL,
    refresh_token_metadata          TEXT          DEFAULT NULL,

    user_code_value                 TEXT          DEFAULT NULL,
    user_code_issued_at             TIMESTAMP     DEFAULT NULL,
    user_code_expires_at            TIMESTAMP     DEFAULT NULL,
    user_code_metadata              TEXT          DEFAULT NULL,

    device_code_value               TEXT          DEFAULT NULL,
    device_code_issued_at           TIMESTAMP     DEFAULT NULL,
    device_code_expires_at          TIMESTAMP     DEFAULT NULL,
    device_code_metadata            TEXT          DEFAULT NULL,

    PRIMARY KEY (id)
);

CREATE TABLE oauth2_authorization_consent (
    registered_client_id VARCHAR(100)  NOT NULL,
    principal_name        VARCHAR(200)  NOT NULL,
    authorities           VARCHAR(1000) NOT NULL,

    PRIMARY KEY (registered_client_id, principal_name)
);
