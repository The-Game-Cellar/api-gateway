package com.thegamecellar.apigateway.security;

import com.thegamecellar.apigateway.support.GatewayTestBase;
import com.thegamecellar.apigateway.support.StubHttpServer;
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
        "RATE_LIMIT_ACCOUNT_ACTION_REQUESTS=2",
        "RATE_LIMIT_ACCOUNT_ACTION_WINDOW_SECONDS=3600",
        "RATE_LIMIT_RECOMMENDATIONS_REQUESTS=2",
        "RATE_LIMIT_RECOMMENDATIONS_WINDOW_SECONDS=3600",
        "RATE_LIMIT_EXPORT_REQUESTS=2",
        "RATE_LIMIT_EXPORT_WINDOW_SECONDS=3600",
})
class RateLimitTest extends GatewayTestBase {

    private static final String EXPORT = "/api/v1/auth/account/export";

    private void exportSourcesAnswerFor(String userId) {
        String userPath = "/admin/realms/" + REALM + "/users/" + userId;
        keycloak.on("GET", userPath, StubHttpServer.StubResponse.json(200, "{\"username\":\"" + userId + "\"}"));
        keycloak.on("GET", userPath + "/credentials", StubHttpServer.StubResponse.json(200, "[]"));
        keycloak.on("GET", userPath + "/sessions", StubHttpServer.StubResponse.json(200, "[]"));
    }

    // One export fans out to Keycloak and both services, so each account gets a small budget of
    // its own: another account behind the same address is unaffected, and a caller with no
    // session is refused by the controller without spending anything.
    @Test
    void exportsAreLimitedPerUserAndAnonymousCallsAre401NotCounted() throws Exception {
        issue("alice-token", "alice");
        issue("bob-token", "bob");
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.StubResponse.json(200, "{\"access_token\":\"admin-token\",\"expires_in\":60}"));
        exportSourcesAnswerFor("alice");
        exportSourcesAnswerFor("bob");
        libraryService.on("GET", "/api/v1/library/account/export", StubHttpServer.StubResponse.json(200, "{\"games\":[]}"));
        recommendationService.on("GET", "/api/v1/recommendations/account/export", StubHttpServer.StubResponse.json(200, "{\"profile\":null}"));

        for (int i = 0; i < 5; i++) {
            mvc.perform(get(EXPORT).with(r -> { r.setRemoteAddr("198.51.100.30"); return r; }))
                    .andExpect(status().isUnauthorized());
        }
        for (int i = 0; i < 2; i++) {
            mvc.perform(get(EXPORT).cookie(accessCookie("alice-token"))
                            .with(r -> { r.setRemoteAddr("198.51.100.30"); return r; }))
                    .andExpect(status().isOk());
        }
        mvc.perform(get(EXPORT).cookie(accessCookie("alice-token"))
                        .with(r -> { r.setRemoteAddr("198.51.100.30"); return r; }))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error").value("Too many exports. Please try again later."));

        mvc.perform(get(EXPORT).cookie(accessCookie("bob-token"))
                        .with(r -> { r.setRemoteAddr("198.51.100.30"); return r; }))
                .andExpect(status().isOk());
    }

    // A user changing their password a few times must not spend the login budget of
    // everyone behind the same address, and another user on that address has their own.
    @Test
    void accountActionsHaveTheirOwnBudgetPerUserAndLeaveTheLoginBudgetAlone() throws Exception {
        issue("alice-token", "alice");
        issue("bob-token", "bob");

        for (int i = 0; i < 2; i++) {
            mvc.perform(get("/api/v1/auth/authorize").param("intent", "UPDATE_PASSWORD")
                            .cookie(accessCookie("alice-token"))
                            .with(r -> { r.setRemoteAddr("198.51.100.20"); return r; }))
                    .andExpect(status().isFound());
        }
        mvc.perform(get("/api/v1/auth/authorize").param("intent", "UPDATE_PASSWORD")
                        .cookie(accessCookie("alice-token"))
                        .with(r -> { r.setRemoteAddr("198.51.100.20"); return r; }))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error").value("Too many account changes. Please try again later."));

        mvc.perform(get("/api/v1/auth/authorize").param("intent", "DELETE_ACCOUNT")
                        .cookie(accessCookie("bob-token"))
                        .with(r -> { r.setRemoteAddr("198.51.100.20"); return r; }))
                .andExpect(status().isFound());
        mvc.perform(get("/api/v1/auth/authorize")
                        .with(r -> { r.setRemoteAddr("198.51.100.20"); return r; }))
                .andExpect(status().isFound());
    }

    // No cookie means no account to count against, so the address is the unit; an unknown
    // intent is a plain login and counts as one.
    @Test
    void anAccountActionWithoutASessionCountsAgainstTheAddressAndUnknownIntentsAreLogins() throws Exception {
        for (int i = 0; i < 2; i++) {
            mvc.perform(get("/api/v1/auth/authorize").param("intent", "DELETE_ACCOUNT")
                            .with(r -> { r.setRemoteAddr("198.51.100.21"); return r; }))
                    .andExpect(status().isFound());
        }
        mvc.perform(get("/api/v1/auth/authorize").param("intent", "DELETE_ACCOUNT")
                        .with(r -> { r.setRemoteAddr("198.51.100.21"); return r; }))
                .andExpect(status().isTooManyRequests());

        for (int i = 0; i < 2; i++) {
            mvc.perform(get("/api/v1/auth/authorize").param("intent", "garbage")
                            .with(r -> { r.setRemoteAddr("198.51.100.21"); return r; }))
                    .andExpect(status().isFound());
        }
        mvc.perform(get("/api/v1/auth/authorize")
                        .with(r -> { r.setRemoteAddr("198.51.100.21"); return r; }))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error").value("Too many login attempts. Please try again later."));
    }

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
