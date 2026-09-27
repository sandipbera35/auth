package com.center.auth.auth;

import java.util.List;

public record ProfileResponse(
        Long id,
        String email,
        String firstName,
        String lastName,
        String profilePhotoUrl,
        String coverPhotoUrl,
        String bio,
        boolean emailVerified,
        String status,
        List<String> roles
) {
}
