package com.thegamecellar.apigateway.security;

import com.thegamecellar.apigateway.support.GatewayTestBase;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// Its own context: the limits here are tiny so the 429 is reachable in a handful of requests,
// while the shared context leaves them wide open so the auth tests never trip them.
@TestPropertySource(properties = {
        "RATE_LIMIT_LOGIN_REQUESTS=2",
        "RATE_LIMIT_LOGIN_WINDOW_SECONDS=3600",
        "RATE_LIMIT_RECOMMENDATIONS_REQUESTS=2",
        "RATE_LIMIT_RECOMMENDATIONS_WINDOW_SECONDS=3600",
})
class RateLimitTest extends GatewayTestBase {

    @Test
    void startingALoginIsLimitedPerClientAddress() throws Exception {
        mvc.perform(get("/api/v1/auth/authorize").with(r -> { r.setRemoteAddr("198.51.100.7"); return r; }))
                .andExpect(status().isFound());
        mvc.perform(get("/api/v1/auth/authorize").with(r -> { r.setRemoteAddr("198.51.100.7"); return r; }))
                .andExpect(status().isFound());
        mvc.perform(get("/api/v1/auth/authorize").with(r -> { r.setRemoteAddr("198.51.100.7"); return r; }))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error").value("Too many login attempts. Please try again later."));

        // Another address has its own bucket.
        mvc.perform(get("/api/v1/auth/authorize").with(r -> { r.setRemoteAddr("198.51.100.8"); return r; }))
                .andExpect(status().isFound());
    }

    // No trusted proxies are configured here, so a forwarded header must not buy a fresh bucket.
    @Test
    void forwardedForHeaderCannotEscapeTheLoginBucket() throws Exception {
        for (int i = 0; i < 2; i++) {
            mvc.perform(get("/api/v1/auth/authorize")
                            .with(r -> { r.setRemoteAddr("198.51.100.9"); return r; })
                            .header("X-Forwarded-For", "10.0.0." + i))
                    .andExpect(status().isFound());
        }
        mvc.perform(get("/api/v1/auth/authorize")
                        .with(r -> { r.setRemoteAddr("198.51.100.9"); return r; })
                        .header("X-Forwarded-For", "10.0.0.99"))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void recommendationsAreLimitedPerUserNotPerAddress() throws Exception {
        issue("alice-token", "alice");
        issue("bob-token", "bob");

        for (int i = 0; i < 2; i++) {
            mvc.perform(get("/api/v1/recommendations/dashboard").cookie(accessCookie("alice-token")))
                    .andExpect(status().isOk());
        }
        mvc.perform(get("/api/v1/recommendations/dashboard").cookie(accessCookie("alice-token")))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error").value("Too many recommendation requests. Please slow down."));

        // Same address, different account: separate budget.
        mvc.perform(get("/api/v1/recommendations/dashboard").cookie(accessCookie("bob-token")))
                .andExpect(status().isOk());
    }

    @Test
    void theLimitSitsBehindAuthenticationSoAnonymousCallsAre401NotCounted() throws Exception {
        for (int i = 0; i < 5; i++) {
            mvc.perform(get("/api/v1/recommendations/dashboard"))
                    .andExpect(status().isUnauthorized());
        }
    }
}
