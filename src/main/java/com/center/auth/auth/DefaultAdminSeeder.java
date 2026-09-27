package com.center.auth.auth;

import com.center.auth.role.Role;
import com.center.auth.role.RoleRepository;
import com.center.auth.user.User;
import com.center.auth.user.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Creates a default admin account on startup if one doesn't already exist. The password is
 * hashed at runtime via the injected {@link PasswordEncoder} - never stored in source control,
 * unlike a hardcoded hash in a migration would be. Only ever creates the account; if it already
 * exists, its password/roles are left untouched (so a rotated password survives a restart).
 */
@Component
public class DefaultAdminSeeder implements ApplicationRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final String adminEmail;
    private final String adminPassword;

    public DefaultAdminSeeder(UserRepository userRepository,
                               RoleRepository roleRepository,
                               PasswordEncoder passwordEncoder,
                               @Value("${app.default-admin.email}") String adminEmail,
                               @Value("${app.default-admin.password}") String adminPassword) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.adminEmail = adminEmail;
        this.adminPassword = adminPassword;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (userRepository.findByEmail(adminEmail).isPresent()) {
            return;
        }

        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new IllegalStateException("Default role 'USER' is not seeded"));
        Role adminRole = roleRepository.findByName("ADMIN")
                .orElseThrow(() -> new IllegalStateException("Default role 'ADMIN' is not seeded"));

        User admin = new User(adminEmail, passwordEncoder.encode(adminPassword));
        admin.setFirstName("Admin");
        admin.setLastName("User");
        admin.getRoles().add(userRole);
        admin.getRoles().add(adminRole);

        userRepository.save(admin);
    }
}
