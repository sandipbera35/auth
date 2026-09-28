package com.center.auth.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.time.Instant;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {

    Optional<User> findByEmail(String email);

    Optional<User> findByProviderAndProviderId(String provider, String providerId);

    long countByStatus(UserStatus status);

    long countByRolesName(String roleName);

    long countByCreatedAtBetween(Instant from, Instant to);
}
