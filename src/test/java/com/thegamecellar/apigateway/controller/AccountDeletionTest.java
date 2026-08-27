package com.thegamecellar.apigateway.controller;

import com.thegamecellar.apigateway.support.GatewayTestBase;
import com.thegamecellar.apigateway.support.StubHttpServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AccountDeletionTest extends GatewayTestBase {

    private static final String USER = "6f1c2d3e-0000-4000-8000-000000000001";
    private static final String ADMIN_DELETE_PATH = "/admin/realms/" + REALM + "/users/" + USER;
    private static final String LIBRARY_PURGE_PATH = "/api/v1/library/account";

    @BeforeEach
    void keycloakAdminIsReachable() {
        // The admin token comes from the same token endpoint as user tokens, with a different grant.
        keycloak.on("POST", TOKEN_PATH, request -> request.body().contains("grant_type=client_credentials")
                ? StubHttpServer.StubResponse.json(200, "{\"access_token\":\"admin-token\",\"expires_in\":60}")
                : StubHttpServer.StubResponse.json(400, "{\"error\":\"unexpected grant\"}"));
        keycloak.on("DELETE", ADMIN_DELETE_PATH, StubHttpServer.StubResponse.empty(204));
        libraryService.on("DELETE", LIBRARY_PURGE_PATH, StubHttpServer.StubResponse.json(200, "{\"message\":\"purged\"}"));
    }

    private void freshlyAuthenticated(String token) {
        issue(token, USER, Map.of("auth_time", Instant.now().getEpochSecond()));
    }

    @Test
    void purgesTheLibraryFirstThenDeletesTheIdentityThenClearsCookies() throws Exception {
        freshlyAuthenticated("fresh");

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Account deleted"))
                .andExpect(header().stringValues("Set-Cookie", hasItems(
                        allOf(startsWith("access_token=;"), containsString("Max-Age=0;")),
                        allOf(startsWith("refresh_token=;"), containsString("Max-Age=0;")))));

        // Library before identity: a failure between them leaves an account that can retry,
        // never a dangling identity with its library already gone.
        StubHttpServer.RecordedRequest purge = libraryService.recorded("DELETE", LIBRARY_PURGE_PATH).get(0);
        assertThat(purge.header("Authorization")).isEqualTo("Bearer fresh");
        StubHttpServer.RecordedRequest identity = keycloak.recorded("DELETE", ADMIN_DELETE_PATH).get(0);
        assertThat(identity.header("Authorization")).isEqualTo("Bearer admin-token");
        assertThat(purge.seq()).isLessThan(identity.seq());
    }

    @Test
    void refusedWithoutACookieOrWithATokenTheDecoderRejects() throws Exception {
        mvc.perform(delete("/api/v1/auth/account"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Not authenticated"));

        // A cookie the decoder rejects never reaches the controller: the resource-server
        // filter reads the same cookie and answers 401 itself, with no body.
        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("forged")))
                .andExpect(status().isUnauthorized());

        assertThat(libraryService.recorded()).isEmpty();
        assertThat(keycloak.recorded()).isEmpty();
    }

    // Proof of identity is the auth_time claim, which survives refresh: a token that was
    // refreshed all day still says when the password was last entered.
    @Test
    void refusedWhenTheLastAuthenticationIsOlderThanFiveMinutesOrUnknown() throws Exception {
        issue("stale", USER, Map.of("auth_time", Instant.now().minusSeconds(20 * 60).getEpochSecond()));
        issue("no-auth-time", USER);

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("stale")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Re-authentication required"));
        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("no-auth-time")))
                .andExpect(status().isForbidden());

        assertThat(libraryService.recorded()).isEmpty();
        assertThat(keycloak.recorded()).isEmpty();
    }

    @Test
    void libraryPurgeFailingLeavesTheIdentityUntouchedAndIsRetryable() throws Exception {
        freshlyAuthenticated("fresh");
        libraryService.on("DELETE", LIBRARY_PURGE_PATH, StubHttpServer.StubResponse.json(500, "{\"error\":\"db down\"}"));

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.error").value("Could not purge library data, try again"))
                .andExpect(header().doesNotExist("Set-Cookie"));

        assertThat(keycloak.recorded("DELETE", ADMIN_DELETE_PATH)).isEmpty();
    }

    @Test
    void identityDeleteFailingAfterThePurgeIsReportedAsSuch() throws Exception {
        freshlyAuthenticated("fresh");
        keycloak.on("DELETE", ADMIN_DELETE_PATH, StubHttpServer.StubResponse.json(403, "{\"error\":\"forbidden\"}"));

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.error").value("Library data purged but Keycloak account remains. Contact support."))
                .andExpect(header().doesNotExist("Set-Cookie"));

        assertThat(libraryService.recorded("DELETE", LIBRARY_PURGE_PATH)).hasSize(1);
    }

    // A 401 from the admin API means the cached service-account token is dead, not that the
    // caller lacks rights: the token is fetched again and the call retried once.
    @Test
    void aRejectedAdminTokenIsRefreshedAndTheDeleteRetriedOnce() throws Exception {
        freshlyAuthenticated("fresh");
        List<Integer> answers = new java.util.concurrent.CopyOnWriteArrayList<>(List.of(401, 204));
        keycloak.on("DELETE", ADMIN_DELETE_PATH, request -> StubHttpServer.StubResponse.empty(answers.remove(0)));

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                .andExpect(status().isOk());

        assertThat(keycloak.recorded("DELETE", ADMIN_DELETE_PATH)).hasSize(2);
        assertThat(keycloak.recorded("POST", TOKEN_PATH).stream()
                .filter(r -> r.body().contains("client_credentials")).count()).isGreaterThanOrEqualTo(1);
    }
}
