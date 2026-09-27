package com.center.auth.auth;

import com.center.auth.storage.StoredObject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public RegisterResponse register(@Valid @RequestBody RegisterRequest request) {
        return authService.register(request);
    }

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @PostMapping("/refresh")
    public AuthResponse refresh(@Valid @RequestBody RefreshRequest request) {
        return authService.refresh(request);
    }

    @GetMapping("/profile")
    public ProfileResponse profile(@AuthenticationPrincipal Jwt jwt) {
        return authService.getProfile(jwt);
    }

    @PatchMapping("/profile")
    public ProfileResponse updateProfile(@AuthenticationPrincipal Jwt jwt,
                                          @Valid @RequestBody UpdateProfileRequest request) {
        return authService.updateProfile(jwt, request);
    }

    @PutMapping(value = "/profile/photo", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ProfileResponse updateProfilePhoto(@AuthenticationPrincipal Jwt jwt,
                                               @RequestParam("file") MultipartFile file) {
        return authService.updateProfilePhoto(jwt, file, file.getSize());
    }

    @PutMapping("/profile/photo")
    public ProfileResponse updateProfilePhotoRaw(@AuthenticationPrincipal Jwt jwt, HttpServletRequest request) {
        return authService.updateProfilePhoto(jwt, request::getInputStream, request.getContentLengthLong());
    }

    @PutMapping(value = "/profile/cover", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ProfileResponse updateProfileCover(@AuthenticationPrincipal Jwt jwt,
                                               @RequestParam("file") MultipartFile file) {
        return authService.updateProfileCover(jwt, file, file.getSize());
    }

    @PutMapping("/profile/cover")
    public ProfileResponse updateProfileCoverRaw(@AuthenticationPrincipal Jwt jwt, HttpServletRequest request) {
        return authService.updateProfileCover(jwt, request::getInputStream, request.getContentLengthLong());
    }

    @DeleteMapping("/profile/photo")
    public ResponseEntity<Void> deleteProfilePhoto(@AuthenticationPrincipal Jwt jwt) {
        authService.deleteProfilePhoto(jwt);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/profile/cover")
    public ResponseEntity<Void> deleteProfileCover(@AuthenticationPrincipal Jwt jwt) {
        authService.deleteProfileCover(jwt);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/profile/photo")
    public ResponseEntity<StreamingResponseBody> streamProfilePhoto(@AuthenticationPrincipal Jwt jwt) {
        return streamImage(authService.getProfilePhoto(jwt));
    }

    @GetMapping("/profile/cover")
    public ResponseEntity<StreamingResponseBody> streamProfileCover(@AuthenticationPrincipal Jwt jwt) {
        return streamImage(authService.getProfileCover(jwt));
    }

    @GetMapping("/users/{id}/profile/photo")
    public ResponseEntity<StreamingResponseBody> streamUserPhoto(@AuthenticationPrincipal Jwt jwt,
                                                                  @PathVariable Long id) {
        return streamImage(authService.getUserPhoto(jwt, id));
    }

    @GetMapping("/users/{id}/profile/cover")
    public ResponseEntity<StreamingResponseBody> streamUserCover(@AuthenticationPrincipal Jwt jwt,
                                                                  @PathVariable Long id) {
        return streamImage(authService.getUserCover(jwt, id));
    }

    private ResponseEntity<StreamingResponseBody> streamImage(StoredObject image) {
        StreamingResponseBody body = out -> {
            try (image) {
                image.content().transferTo(out);
            }
        };
        MediaType mediaType = image.contentType() != null
                ? MediaType.parseMediaType(image.contentType())
                : MediaType.APPLICATION_OCTET_STREAM;
        return ResponseEntity.ok().contentType(mediaType).body(body);
    }
}
