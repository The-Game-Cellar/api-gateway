package com.thegamecellar.apigateway.controller;

import com.thegamecellar.apigateway.support.GatewayTestBase;
import com.thegamecellar.apigateway.support.StubHttpServer;
import org.junit.jupiter.api.Test;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class SessionEndpointsTest extends GatewayTestBase {

    private static final String REVOKE_PATH = "/realms/" + REALM + "/protocol/openid-connect/revoke";

    private static String form(StubHttpServer.RecordedRequest request, String key) {
        String raw = UriComponentsBuilder.newInstance().query(request.body()).build().getQueryParams().getFirst(key);
        return raw == null ? null : java.net.URLDecoder.decode(raw, java.nio.charset.StandardCharsets.UTF_8);
    }

    @Test
    void meReadsIdentityFromTheAccessCookieOnly() throws Exception {
        issueWithRoles("alice-token", "alice", "user");

        mvc.perform(get("/api/v1/auth/me").cookie(accessCookie("alice-token")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("alice"))
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.email").value("alice@example.test"))
                .andExpect(jsonPath("$.roles[0]").value("user"));

        // A bearer header authenticates the security chain but is not where the session lives.
        mvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer alice-token"))
                .andExpect(status().isUnauthorized());

        // Rejected by the resource-server filter, which reads the same cookie, before the
        // controller's own "Invalid token" branch could run.
        mvc.perform(get("/api/v1/auth/me").cookie(accessCookie("expired-or-forged")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void meFallsBackToPreferredUsernameWhenTheTokenHasNoEmail() throws Exception {
        issueBare("username-only", "carol", Map.of("preferred_username", "carol", "azp", CLIENT_ID));

        mvc.perform(get("/api/v1/auth/me").cookie(accessCookie("username-only")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("carol"))
                .andExpect(jsonPath("$.email").value("carol"))
                .andExpect(jsonPath("$.roles").isEmpty());
    }

    @Test
    void meReturnsAnEmptyUsernameWhenTheTokenCarriesNone() throws Exception {
        issueBare("no-username", "dave", Map.of("email", "dave@example.test", "azp", CLIENT_ID));

        mvc.perform(get("/api/v1/auth/me").cookie(accessCookie("no-username")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(""))
                .andExpect(jsonPath("$.email").value("dave@example.test"));
    }

    @Test
    void refreshRotatesBothCookiesAndReturnsTheIdentity() throws Exception {
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.StubResponse.json(200,
                tokenJson("alice-access-2", "alice-refresh-2", "alice-id-2")));
        issue("alice-access-2", "alice");

        mvc.perform(post("/api/v1/auth/refresh").cookie(refreshCookie("alice-refresh")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("alice"))
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(header().stringValues("Set-Cookie", hasItems(
                        startsWith("access_token=alice-access-2;"),
                        startsWith("refresh_token=alice-refresh-2;"))));

        StubHttpServer.RecordedRequest call = keycloak.recorded("POST", TOKEN_PATH).get(0);
        assertThat(form(call, "grant_type")).isEqualTo("refresh_token");
        assertThat(form(call, "refresh_token")).isEqualTo("alice-refresh");
        assertThat(form(call, "client_id")).isEqualTo(CLIENT_ID);
    }

    @Test
    void refreshWithoutACookieIs401AndNeverCallsKeycloak() throws Exception {
        mvc.perform(post("/api/v1/auth/refresh"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("No refresh token"));

        assertThat(keycloak.recorded()).isEmpty();
    }

    @Test
    void refreshKeycloakRefusesClearsBothCookies() throws Exception {
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.StubResponse.json(400, "{\"error\":\"invalid_grant\"}"));

        mvc.perform(post("/api/v1/auth/refresh").cookie(refreshCookie("stale")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Refresh token expired"))
                .andExpect(header().stringValues("Set-Cookie", hasItems(
                        allOf(startsWith("access_token=;"), containsString("Max-Age=0;")),
                        allOf(startsWith("refresh_token=;"), containsString("Max-Age=0;")))));
    }

    @Test
    void logoutRevokesTheRefreshTokenAndClearsCookies() throws Exception {
        keycloak.on("POST", REVOKE_PATH, StubHttpServer.StubResponse.empty(200));

        mvc.perform(post("/api/v1/auth/logout").cookie(refreshCookie("alice-refresh")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Logged out"))
                .andExpect(header().stringValues("Set-Cookie", hasItems(
                        allOf(startsWith("access_token=;"), containsString("Max-Age=0;")),
                        allOf(startsWith("refresh_token=;"), containsString("Max-Age=0;")))));

        StubHttpServer.RecordedRequest revoke = keycloak.recorded("POST", REVOKE_PATH).get(0);
        assertThat(form(revoke, "token")).isEqualTo("alice-refresh");
        assertThat(form(revoke, "token_type_hint")).isEqualTo("refresh_token");
    }

    // Revocation is best effort: a Keycloak outage must not keep a user signed in on this side.
    @Test
    void logoutStillClearsCookiesWhenRevocationFailsOrThereIsNothingToRevoke() throws Exception {
        keycloak.on("POST", REVOKE_PATH, StubHttpServer.StubResponse.empty(500));

        mvc.perform(post("/api/v1/auth/logout").cookie(refreshCookie("alice-refresh")))
                .andExpect(status().isOk())
                .andExpect(header().stringValues("Set-Cookie", hasItems(
                        allOf(startsWith("access_token=;"), containsString("Max-Age=0;")))));

        mvc.perform(post("/api/v1/auth/logout"))
                .andExpect(status().isOk());
        assertThat(keycloak.recorded("POST", REVOKE_PATH)).hasSize(1);
    }
}
