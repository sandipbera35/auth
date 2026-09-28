package com.center.auth.auth;

import com.center.auth.role.Role;
import com.center.auth.role.RoleRepository;
import com.center.auth.security.InvalidTokenException;
import com.center.auth.security.JwtProperties;
import com.center.auth.security.TokenService;
import com.center.auth.storage.StorageService;
import com.center.auth.storage.StoredObject;
import com.center.auth.user.User;
import com.center.auth.user.UserRepository;
import com.center.auth.user.UserStatus;
import jakarta.persistence.criteria.Predicate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.InputStreamSource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.unit.DataSize;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Function;

@Service
@Transactional
public class AuthService {

    private record DetectedImage(String extension, String contentType) {
    }

    private static final int[] JPEG_MAGIC = {0xFF, 0xD8, 0xFF};
    private static final int[] PNG_MAGIC = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    private static final int[] GIF_MAGIC = {0x47, 0x49, 0x46, 0x38};
    private static final int[] RIFF_MAGIC = {0x52, 0x49, 0x46, 0x46};
    private static final int[] WEBP_MAGIC = {0x57, 0x45, 0x42, 0x50};
    private static final int[] FTYP_MAGIC = {0x66, 0x74, 0x79, 0x70};
    private static final int[] AVIF_BRAND = {0x61, 0x76, 0x69, 0x66};

    private static final String PHOTO_PLACEHOLDER = "placeholders/profile-photo.png";
    private static final String COVER_PLACEHOLDER = "placeholders/cover-photo.png";
    private static final String DEFAULT_ROLE = "USER";
    private static final String ADMIN_ROLE = "ADMIN";
    private static final String MODERATOR_ROLE = "MODERATOR";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final JwtProperties jwtProperties;
    private final StorageService storageService;
    private final DataSize maxUploadSize;

    public AuthService(UserRepository userRepository,
                        RoleRepository roleRepository,
                        PasswordEncoder passwordEncoder,
                        TokenService tokenService,
                        JwtProperties jwtProperties,
                        StorageService storageService,
                        @Value("${spring.servlet.multipart.max-file-size}") DataSize maxUploadSize) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.jwtProperties = jwtProperties;
        this.storageService = storageService;
        this.maxUploadSize = maxUploadSize;
    }

    public RegisterResponse register(RegisterRequest request) {
        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email is already registered");
        }

        Role defaultRole = roleRepository.findByName(DEFAULT_ROLE)
                .orElseThrow(() -> new IllegalStateException("Default role '" + DEFAULT_ROLE + "' is not seeded"));

        User user = new User(request.email(), passwordEncoder.encode(request.password()));
        user.setFirstName(request.firstName());
        user.setLastName(request.lastName());
        user.setStatus(UserStatus.ACTIVE);
        user.getRoles().add(defaultRole);

        user = userRepository.save(user);
        return new RegisterResponse(user.getId(), user.getEmail(), user.getStatus().name());
    }

    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password"));

        if (user.getPasswordHash() == null || !passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password");
        }
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Account is not active");
        }

        return issueTokens(user);
    }

    public AuthResponse refresh(RefreshRequest request) {
        Jwt jwt;
        try {
            jwt = tokenService.verifyRefreshToken(request.refreshToken());
        } catch (JwtException | InvalidTokenException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token");
        }

        Long userId = Long.valueOf(jwt.getSubject());
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User no longer exists"));

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Account is not active");
        }

        return issueTokens(user);
    }

    public ProfileResponse getProfile(Jwt jwt) {
        User user = requireActiveUser(jwt);
        return toProfileResponse(user);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public PagedResponse<ProfileResponse> listUsers(Jwt jwt, String status, String role,
                                                      LocalDate joinedFrom, LocalDate joinedTo,
                                                      int page, int size) {
        requireActiveUser(jwt);
        validateDateRange(joinedFrom, joinedTo);
        UserStatus statusFilter = parseStatusFilter(status);

        int safePage = Math.max(page, 0);
        int safeSize = Math.min(Math.max(size, 1), 100);
        Pageable pageable = PageRequest.of(safePage, safeSize, Sort.by(Sort.Direction.DESC, "createdAt"));

        Page<User> result = userRepository.findAll(buildUserFilter(statusFilter, role, joinedFrom, joinedTo), pageable);

        return new PagedResponse<>(
                result.getContent().stream().map(this::toProfileResponse).toList(),
                result.getNumber(),
                result.getSize(),
                result.getTotalElements(),
                result.getTotalPages()
        );
    }

    @PreAuthorize("hasRole('ADMIN')")
    public DashboardStatsResponse getDashboardStats(Jwt jwt, LocalDate joinedFrom, LocalDate joinedTo) {
        requireActiveUser(jwt);
        validateDateRange(joinedFrom, joinedTo);

        long total = userRepository.count();
        long active = userRepository.countByStatus(UserStatus.ACTIVE);
        long inactive = userRepository.countByStatus(UserStatus.INACTIVE);
        long blocked = userRepository.countByStatus(UserStatus.BLOCKED);
        long admins = userRepository.countByRolesName(ADMIN_ROLE);

        Long joinedInRange = null;
        if (joinedFrom != null || joinedTo != null) {
            Instant from = joinedFrom != null ? startOfDayUtc(joinedFrom) : Instant.EPOCH;
            Instant to = joinedTo != null ? startOfDayUtc(joinedTo.plusDays(1)) : Instant.now();
            joinedInRange = userRepository.countByCreatedAtBetween(from, to);
        }

        return new DashboardStatsResponse(total, active, inactive, blocked, admins, joinedInRange);
    }

    private static UserStatus parseStatusFilter(String status) {
        if (status == null || status.isBlank() || status.equalsIgnoreCase("ALL")) {
            return null;
        }
        try {
            return UserStatus.valueOf(status.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid status filter: " + status);
        }
    }

    private static void validateDateRange(LocalDate from, LocalDate to) {
        if (from != null && to != null && from.isAfter(to)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "joinedFrom must not be after joinedTo");
        }
    }

    private static Instant startOfDayUtc(LocalDate date) {
        return date.atStartOfDay(ZoneOffset.UTC).toInstant();
    }

    private static Specification<User> buildUserFilter(UserStatus status, String role,
                                                         LocalDate joinedFrom, LocalDate joinedTo) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (status != null) {
                predicates.add(cb.equal(root.get("status"), status));
            }
            if (role != null && !role.isBlank()) {
                query.distinct(true);
                predicates.add(cb.equal(cb.upper(root.join("roles").get("name")), role.toUpperCase()));
            }
            if (joinedFrom != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("createdAt"), startOfDayUtc(joinedFrom)));
            }
            if (joinedTo != null) {
                predicates.add(cb.lessThan(root.get("createdAt"), startOfDayUtc(joinedTo.plusDays(1))));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    @PreAuthorize("hasRole('ADMIN')")
    public ProfileResponse promoteToModerator(Jwt jwt, Long userId) {
        requireActiveUser(jwt);
        User target = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        Role moderatorRole = roleRepository.findByName(MODERATOR_ROLE)
                .orElseThrow(() -> new IllegalStateException("Role '" + MODERATOR_ROLE + "' is not seeded"));
        target.getRoles().add(moderatorRole);

        return toProfileResponse(target);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public ProfileResponse removeModerator(Jwt jwt, Long userId) {
        requireActiveUser(jwt);
        User target = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        target.getRoles().removeIf(r -> r.getName().equals(MODERATOR_ROLE));

        return toProfileResponse(target);
    }

    @PreAuthorize("hasAnyRole('ADMIN', 'MODERATOR')")
    public ProfileResponse blockUser(Jwt jwt, Long userId) {
        User caller = requireActiveUser(jwt);
        User target = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        if (target.getId().equals(caller.getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Cannot block your own account");
        }
        if (hasRole(target, ADMIN_ROLE)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Cannot block an administrator");
        }

        target.setStatus(UserStatus.BLOCKED);
        return toProfileResponse(target);
    }

    @PreAuthorize("hasAnyRole('ADMIN', 'MODERATOR')")
    public ProfileResponse unblockUser(Jwt jwt, Long userId) {
        requireActiveUser(jwt);
        User target = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        if (target.getStatus() == UserStatus.BLOCKED) {
            target.setStatus(UserStatus.ACTIVE);
        }
        return toProfileResponse(target);
    }

    private static boolean hasRole(User user, String roleName) {
        return user.getRoles().stream().anyMatch(role -> role.getName().equals(roleName));
    }

    public ProfileResponse updateProfile(Jwt jwt, UpdateProfileRequest request) {
        User user = requireActiveUser(jwt);

        if (request.firstName() != null) {
            user.setFirstName(request.firstName());
        }
        if (request.lastName() != null) {
            user.setLastName(request.lastName());
        }
        if (request.bio() != null) {
            user.setBio(request.bio());
        }

        return toProfileResponse(user);
    }

    public ProfileResponse updateProfilePhoto(Jwt jwt, InputStreamSource source, long size) {
        return updateProfilePicture(jwt, source, size, "photo", User::getProfilePhotoUrl, User::setProfilePhotoUrl);
    }

    public ProfileResponse updateProfileCover(Jwt jwt, InputStreamSource source, long size) {
        return updateProfilePicture(jwt, source, size, "cover", User::getCoverPhotoUrl, User::setCoverPhotoUrl);
    }

    public void deleteProfilePhoto(Jwt jwt) {
        deleteProfilePicture(jwt, User::getProfilePhotoUrl, User::setProfilePhotoUrl);
    }

    public void deleteProfileCover(Jwt jwt) {
        deleteProfilePicture(jwt, User::getCoverPhotoUrl, User::setCoverPhotoUrl);
    }

    public StoredObject getProfilePhoto(Jwt jwt) {
        return getProfilePicture(jwt, User::getProfilePhotoUrl, PHOTO_PLACEHOLDER);
    }

    public StoredObject getProfileCover(Jwt jwt) {
        return getProfilePicture(jwt, User::getCoverPhotoUrl, COVER_PLACEHOLDER);
    }

    public StoredObject getUserPhoto(Jwt jwt, Long userId) {
        return getUserPicture(jwt, userId, User::getProfilePhotoUrl, PHOTO_PLACEHOLDER);
    }

    public StoredObject getUserCover(Jwt jwt, Long userId) {
        return getUserPicture(jwt, userId, User::getCoverPhotoUrl, COVER_PLACEHOLDER);
    }

    private ProfileResponse updateProfilePicture(Jwt jwt, InputStreamSource source, long size, String slot,
                                                  Function<User, String> getter, BiConsumer<User, String> setter) {
        if (size <= 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "File must not be empty");
        }
        if (size > maxUploadSize.toBytes()) {
            throw new ResponseStatusException(HttpStatus.CONTENT_TOO_LARGE,
                    "File exceeds maximum upload size of " + maxUploadSize);
        }

        byte[] content;
        try (InputStream in = source.getInputStream()) {
            content = in.readAllBytes();
        } catch (IOException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unable to read uploaded file");
        }

        // Clients (e.g. Postman's file picker on files it can't confidently type,
        // WhatsApp-exported images, etc.) frequently declare application/octet-stream
        // regardless of the actual format, so the declared Content-Type is never trusted -
        // the real type is sniffed from the file's magic bytes instead.
        DetectedImage detected = detectImageType(content);
        if (detected == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unrecognized or unsupported image format");
        }

        User user = requireActiveUser(jwt);
        String objectKey = "user/" + user.getId() + "/profile/" + slot + "/picture." + detected.extension();

        storageService.upload(objectKey, new ByteArrayInputStream(content), content.length, detected.contentType());

        String previousKey = getter.apply(user);
        if (previousKey != null && !previousKey.equals(objectKey)) {
            storageService.delete(previousKey);
        }
        setter.accept(user, objectKey);

        return toProfileResponse(user);
    }

    private static DetectedImage detectImageType(byte[] content) {
        if (matchesAt(content, 0, JPEG_MAGIC)) {
            return new DetectedImage("jpg", "image/jpeg");
        }
        if (matchesAt(content, 0, PNG_MAGIC)) {
            return new DetectedImage("png", "image/png");
        }
        if (matchesAt(content, 0, GIF_MAGIC)) {
            return new DetectedImage("gif", "image/gif");
        }
        if (matchesAt(content, 0, RIFF_MAGIC) && matchesAt(content, 8, WEBP_MAGIC)) {
            return new DetectedImage("webp", "image/webp");
        }
        if (matchesAt(content, 4, FTYP_MAGIC) && matchesAt(content, 8, AVIF_BRAND)) {
            return new DetectedImage("avif", "image/avif");
        }
        return null;
    }

    private static boolean matchesAt(byte[] content, int offset, int[] signature) {
        if (content.length < offset + signature.length) {
            return false;
        }
        for (int i = 0; i < signature.length; i++) {
            if ((content[offset + i] & 0xFF) != signature[i]) {
                return false;
            }
        }
        return true;
    }

    private void deleteProfilePicture(Jwt jwt, Function<User, String> getter, BiConsumer<User, String> setter) {
        User user = requireActiveUser(jwt);
        String key = getter.apply(user);
        if (key != null) {
            storageService.delete(key);
            setter.accept(user, null);
        }
    }

    private StoredObject getProfilePicture(Jwt jwt, Function<User, String> getter, String placeholderClasspath) {
        User user = requireActiveUser(jwt);
        return resolvePicture(user, getter, placeholderClasspath);
    }

    private StoredObject getUserPicture(Jwt jwt, Long userId, Function<User, String> getter,
                                         String placeholderClasspath) {
        requireActiveUser(jwt);
        User target = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        return resolvePicture(target, getter, placeholderClasspath);
    }

    private StoredObject resolvePicture(User user, Function<User, String> getter, String placeholderClasspath) {
        String key = getter.apply(user);
        if (key == null) {
            return loadPlaceholder(placeholderClasspath);
        }
        return storageService.get(key);
    }

    private StoredObject loadPlaceholder(String classpathLocation) {
        try {
            return new StoredObject(new ClassPathResource(classpathLocation).getInputStream(), "image/png");
        } catch (IOException ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Missing placeholder image");
        }
    }

    private User requireActiveUser(Jwt jwt) {
        try {
            tokenService.requireAccessToken(jwt);
        } catch (InvalidTokenException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired access token");
        }

        Long userId = Long.valueOf(jwt.getSubject());
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User no longer exists"));

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Account is not active");
        }

        return user;
    }

    private ProfileResponse toProfileResponse(User user) {
        List<String> roles = user.getRoles().stream().map(Role::getName).toList();
        return new ProfileResponse(
                user.getId(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.getBio(),
                user.isEmailVerified(),
                user.getStatus().name(),
                roles
        );
    }

    private AuthResponse issueTokens(User user) {
        String accessToken = tokenService.generateAccessToken(user);
        String refreshToken = tokenService.generateRefreshToken(user);
        return new AuthResponse(accessToken, refreshToken, "Bearer", jwtProperties.accessTokenTtl().toSeconds());
    }
}
