package com.center.auth.auth;

import jakarta.validation.constraints.Size;

public record UpdateProfileRequest(
        @Size(max = 100) String firstName,
        @Size(max = 100) String lastName,
        @Size(max = 500) String profilePhotoUrl,
        @Size(max = 500) String coverPhotoUrl,
        String bio
) {
}
