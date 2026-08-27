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
    private static final String ADMIN_USER_PATH = "/admin/realms/" + REALM + "/users/" + USER;
    private static final String ADMIN_LOGOUT_PATH = ADMIN_USER_PATH + "/logout";
    private static final String LIBRARY_PURGE_PATH = "/api/v1/library/account";
    private static final String LEDGER_COMPLETE_PATH = "/internal/library/account-deletions/" + USER + "/complete";

    @BeforeEach
    void everyDownstreamAnswers() {
        // The admin token comes from the same token endpoint as user tokens, with a different grant.
        keycloak.on("POST", TOKEN_PATH, request -> request.body().contains("grant_type=client_credentials")
                ? StubHttpServer.StubResponse.json(200, "{\"access_token\":\"admin-token\",\"expires_in\":60}")
                : StubHttpServer.StubResponse.json(400, "{\"error\":\"unexpected grant\"}"));
        keycloak.on("PUT", ADMIN_USER_PATH, StubHttpServer.StubResponse.empty(204));
        keycloak.on("POST", ADMIN_LOGOUT_PATH, StubHttpServer.StubResponse.empty(204));
        keycloak.on("DELETE", ADMIN_USER_PATH, StubHttpServer.StubResponse.empty(204));
        libraryService.on("DELETE", LIBRARY_PURGE_PATH, StubHttpServer.StubResponse.json(200, "{\"message\":\"purged\"}"));
        libraryService.on("POST", LEDGER_COMPLETE_PATH, StubHttpServer.StubResponse.empty(204));
    }

    private void freshlyAuthenticated(String token) {
        issue(token, USER, Map.of("auth_time", Instant.now().getEpochSecond()));
    }

    @Test
    void shutsTheIdentityThenPurgesThenDeletesItThenClosesTheLedgerAndClearsCookies() throws Exception {
        freshlyAuthenticated("fresh");

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Account deleted"))
                .andExpect(header().stringValues("Set-Cookie", hasItems(
                        allOf(startsWith("access_token=;"), containsString("Max-Age=0;")),
                        allOf(startsWith("refresh_token=;"), containsString("Max-Age=0;")))));

        // Identity is shut before anything is destroyed, and the ledger is closed last.
        StubHttpServer.RecordedRequest disable = keycloak.recorded("PUT", ADMIN_USER_PATH).get(0);
        StubHttpServer.RecordedRequest logout = keycloak.recorded("POST", ADMIN_LOGOUT_PATH).get(0);
        StubHttpServer.RecordedRequest purge = libraryService.recorded("DELETE", LIBRARY_PURGE_PATH).get(0);
        StubHttpServer.RecordedRequest identity = keycloak.recorded("DELETE", ADMIN_USER_PATH).get(0);
        StubHttpServer.RecordedRequest complete = libraryService.recorded("POST", LEDGER_COMPLETE_PATH).get(0);

        assertThat(disable.body()).contains("\"enabled\":false");
        assertThat(disable.header("Authorization")).isEqualTo("Bearer admin-token");
        assertThat(purge.header("Authorization")).isEqualTo("Bearer fresh");
        assertThat(identity.header("Authorization")).isEqualTo("Bearer admin-token");
        assertThat(complete.header("X-Internal-Token")).isEqualTo("test-internal-token");
        assertThat(disable.seq()).isLessThan(logout.seq());
        assertThat(logout.seq()).isLessThan(purge.seq());
        assertThat(purge.seq()).isLessThan(identity.seq());
        assertThat(identity.seq()).isLessThan(complete.seq());
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

    // The admin credentials are exercised before anything is destroyed, so a service account
    // with no rights, or a Keycloak that is down, is a clean refusal with the account intact.
    @Test
    void identityProviderRefusingTheDisableDeletesNothing() throws Exception {
        freshlyAuthenticated("fresh");
        keycloak.on("PUT", ADMIN_USER_PATH, StubHttpServer.StubResponse.json(403, "{\"error\":\"forbidden\"}"));

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.error").value("Could not reach the identity provider. Nothing was deleted, try again."))
                .andExpect(header().doesNotExist("Set-Cookie"));

        assertThat(libraryService.recorded()).isEmpty();
        assertThat(keycloak.recorded("DELETE", ADMIN_USER_PATH)).isEmpty();
    }

    @Test
    void libraryPurgeFailingReEnablesTheIdentityAndLeavesItUntouched() throws Exception {
        freshlyAuthenticated("fresh");
        libraryService.on("DELETE", LIBRARY_PURGE_PATH, StubHttpServer.StubResponse.json(500, "{\"error\":\"db down\"}"));

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.error").value("Could not purge library data, try again"))
                .andExpect(header().doesNotExist("Set-Cookie"));

        List<StubHttpServer.RecordedRequest> updates = keycloak.recorded("PUT", ADMIN_USER_PATH);
        assertThat(updates).hasSize(2);
        assertThat(updates.get(0).body()).contains("\"enabled\":false");
        assertThat(updates.get(1).body()).contains("\"enabled\":true");
        assertThat(keycloak.recorded("DELETE", ADMIN_USER_PATH)).isEmpty();
        assertThat(libraryService.recorded("POST", LEDGER_COMPLETE_PATH)).isEmpty();
    }

    // The purge wrote the ledger row, so the request is accepted rather than failed: the user
    // is disabled and signed out, and the retry job finishes the identity delete.
    @Test
    void identityDeleteFailingAfterThePurgeIsAcceptedAndLeftToTheRetryJob() throws Exception {
        freshlyAuthenticated("fresh");
        keycloak.on("DELETE", ADMIN_USER_PATH, StubHttpServer.StubResponse.json(403, "{\"error\":\"forbidden\"}"));

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.message").value("Account deletion accepted and will finish shortly"))
                .andExpect(header().stringValues("Set-Cookie", hasItems(
                        allOf(startsWith("access_token=;"), containsString("Max-Age=0;")),
                        allOf(startsWith("refresh_token=;"), containsString("Max-Age=0;")))));

        assertThat(libraryService.recorded("DELETE", LIBRARY_PURGE_PATH)).hasSize(1);
        assertThat(libraryService.recorded("POST", LEDGER_COMPLETE_PATH)).isEmpty();
    }

    @Test
    void ledgerNotClosingAfterTheIdentityIsGoneStillCountsAsDeleted() throws Exception {
        freshlyAuthenticated("fresh");
        libraryService.on("POST", LEDGER_COMPLETE_PATH, StubHttpServer.StubResponse.json(500, "{\"error\":\"db down\"}"));

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Account deleted"))
                .andExpect(header().stringValues("Set-Cookie", hasItems(
                        allOf(startsWith("access_token=;"), containsString("Max-Age=0;")))));

        assertThat(keycloak.recorded("DELETE", ADMIN_USER_PATH)).hasSize(1);
    }

    // Roles are baked into a token when it is issued, so a 403 on a cached token may only mean
    // the grant is newer than the token: one fresh token and one retry, then the answer stands.
    @Test
    void aForbiddenAdminCallGetsOneFreshTokenBeforeItCounts() throws Exception {
        freshlyAuthenticated("fresh");
        List<Integer> answers = new java.util.concurrent.CopyOnWriteArrayList<>(List.of(403, 204));
        keycloak.on("PUT", ADMIN_USER_PATH, request -> StubHttpServer.StubResponse.empty(answers.remove(0)));

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                .andExpect(status().isOk());

        assertThat(keycloak.recorded("PUT", ADMIN_USER_PATH)).hasSize(2);
        // At least one: the first call may have used a token cached by an earlier test.
        assertThat(keycloak.recorded("POST", TOKEN_PATH).stream()
                .filter(r -> r.body().contains("client_credentials")).count()).isGreaterThanOrEqualTo(1);
    }

    // A 401 from the admin API means the cached service-account token is dead, not that the
    // caller lacks rights: the token is fetched again and the call retried once.
    @Test
    void aRejectedAdminTokenIsRefreshedAndTheCallRetriedOnce() throws Exception {
        freshlyAuthenticated("fresh");
        List<Integer> answers = new java.util.concurrent.CopyOnWriteArrayList<>(List.of(401, 204));
        keycloak.on("PUT", ADMIN_USER_PATH, request -> StubHttpServer.StubResponse.empty(answers.remove(0)));

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                .andExpect(status().isOk());

        assertThat(keycloak.recorded("PUT", ADMIN_USER_PATH)).hasSize(2);
        assertThat(keycloak.recorded("POST", TOKEN_PATH).stream()
                .filter(r -> r.body().contains("client_credentials")).count()).isGreaterThanOrEqualTo(1);
    }
}
