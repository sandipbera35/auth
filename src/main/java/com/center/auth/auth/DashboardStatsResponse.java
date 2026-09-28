package com.center.auth.auth;

public record DashboardStatsResponse(
        long totalUsers,
        long activeUsers,
        long inactiveUsers,
        long blockedUsers,
        long adminUsers,
        Long joinedInRange
) {
}
