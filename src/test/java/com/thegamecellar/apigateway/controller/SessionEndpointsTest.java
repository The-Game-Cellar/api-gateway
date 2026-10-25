package com.thegamecellar.apigateway.controller;

import com.thegamecellar.apigateway.support.GatewayTestBase;
import com.thegamecellar.apigateway.support.StubHttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.not;
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
        mvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + token("alice-token")))
                .andExpect(status().isUnauthorized());

        // The security chain leaves the auth endpoints alone, so the controller's own check answers.
        mvc.perform(get("/api/v1/auth/me").cookie(accessCookie("expired-or-forged")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid token"));
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
        keycloak.on("POST", TOKEN_PATH, tokenResponse("alice-access-2", "alice-refresh-2", "alice-id-2"));
        issue("alice-access-2", "alice");

        mvc.perform(post("/api/v1/auth/refresh").cookie(refreshCookie("alice-refresh")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("alice"))
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(header().stringValues("Set-Cookie", hasItems(
                        startsWith("access_token=" + token("alice-access-2") + ";"),
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

    @Test
    void logoutClearsTheCookiesWhenRevocationNeverAnswers() {
        keycloak.on("POST", REVOKE_PATH, StubHttpServer.after(Duration.ofSeconds(3), StubHttpServer.StubResponse.empty(200)));

        assertTimeoutPreemptively(Duration.ofSeconds(2), () ->
                mvc.perform(post("/api/v1/auth/logout").cookie(refreshCookie("alice-refresh")))
                        .andExpect(status().isOk())
                        .andExpect(header().stringValues("Set-Cookie", hasItems(
                                allOf(startsWith("access_token=;"), containsString("Max-Age=0;")),
                                allOf(startsWith("refresh_token=;"), containsString("Max-Age=0;"))))));
    }

    // Rotated cookies carry exactly what the first ones did: a rotation that dropped HttpOnly or
    // widened the refresh path would undo the login's settings on the first refresh.
    @Test
    void refreshSetsTheRotatedCookiesWithTheSameAttributesAsTheLogin() throws Exception {
        keycloak.on("POST", TOKEN_PATH, tokenResponse("alice-access-2", "alice-refresh-2", "alice-id-2"));
        issue("alice-access-2", "alice");

        mvc.perform(post("/api/v1/auth/refresh").cookie(refreshCookie("alice-refresh")))
                .andExpect(status().isOk())
                .andExpect(header().stringValues("Set-Cookie", hasItems(
                        allOf(startsWith("access_token=" + token("alice-access-2") + ";"), containsString("Path=/;"),
                                containsString("Max-Age=300;"), containsString("HttpOnly"), containsString("SameSite=Strict")),
                        allOf(startsWith("refresh_token=alice-refresh-2;"), containsString("Path=/api/v1/auth;"),
                                containsString("Max-Age=1800;"), containsString("HttpOnly"), containsString("SameSite=Strict")))));
    }

    // Keycloak down, answering nothing usable or never answering: the session cannot be renewed
    // either way, and the app sends the user to sign in on any failed refresh.
    @ParameterizedTest
    @ValueSource(strings = {"500", "503", "empty"})
    void refreshThatKeycloakCannotServeClearsBothCookies(String failure) throws Exception {
        keycloak.on("POST", TOKEN_PATH, failure.equals("empty")
                ? StubHttpServer.StubResponse.empty(200)
                : StubHttpServer.StubResponse.json(Integer.parseInt(failure), "{\"error\":\"unavailable\"}"));

        mvc.perform(post("/api/v1/auth/refresh").cookie(refreshCookie("alice-refresh")))
                .andExpect(status().isUnauthorized())
                .andExpect(header().stringValues("Set-Cookie", hasItems(
                        allOf(startsWith("access_token=;"), containsString("Path=/;"), containsString("Max-Age=0;")),
                        allOf(startsWith("refresh_token=;"), containsString("Path=/api/v1/auth;"), containsString("Max-Age=0;")))));
    }

    @Test
    void refreshThatKeycloakNeverAnswersClearsBothCookiesInsteadOfHanging() {
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.after(Duration.ofSeconds(3), StubHttpServer.StubResponse.json(200, "{}")));

        assertTimeoutPreemptively(Duration.ofSeconds(2), () ->
                mvc.perform(post("/api/v1/auth/refresh").cookie(refreshCookie("alice-refresh")))
                        .andExpect(status().isUnauthorized())
                        .andExpect(header().stringValues("Set-Cookie", hasItems(
                                startsWith("access_token=;"), startsWith("refresh_token=;")))));
    }

    // A token this gateway would refuse on the next request is never set as a cookie: the app
    // would hold a session with no user in it. Garbled, or signed for another issuer.
    @ParameterizedTest
    @ValueSource(strings = {"garbled", "other-issuer"})
    void refreshThatReturnsATokenTheGatewayRejectsSetsNoSession(String kind) throws Exception {
        if (kind.equals("other-issuer")) {
            issue("rejected-access", "alice", Map.of("iss", "http://elsewhere.test/realms/" + REALM));
        }
        String accessName = kind.equals("garbled") ? "not-a-jwt" : "rejected-access";
        keycloak.on("POST", TOKEN_PATH, tokenResponse(accessName, "alice-refresh-2", "alice-id-2"));

        mvc.perform(post("/api/v1/auth/refresh").cookie(refreshCookie("alice-refresh")))
                .andExpect(status().isUnauthorized())
                .andExpect(header().stringValues("Set-Cookie", hasItems(
                        startsWith("access_token=;"), startsWith("refresh_token=;"))))
                .andExpect(header().stringValues("Set-Cookie", not(hasItem(containsString("alice-refresh-2")))));
    }

    // The auth endpoints check the access cookie themselves, so one the decoder rejects (a rotated
    // realm key, a changed issuer) cannot stop a refresh or a logout.
    @Test
    void aRejectedAccessCookieDoesNotStopARefresh() throws Exception {
        keycloak.on("POST", TOKEN_PATH, tokenResponse("alice-access-2", "alice-refresh-2", "alice-id-2"));
        issue("alice-access-2", "alice");

        mvc.perform(post("/api/v1/auth/refresh").cookie(accessCookie("stale-or-forged"), refreshCookie("alice-refresh")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("alice"))
                .andExpect(header().stringValues("Set-Cookie", hasItem(startsWith("access_token=" + token("alice-access-2") + ";"))));
    }

    @Test
    void aRejectedAccessCookieDoesNotStopALogout() throws Exception {
        keycloak.on("POST", REVOKE_PATH, StubHttpServer.StubResponse.empty(200));

        mvc.perform(post("/api/v1/auth/logout").cookie(accessCookie("stale-or-forged"), refreshCookie("alice-refresh")))
                .andExpect(status().isOk())
                .andExpect(header().stringValues("Set-Cookie", hasItems(
                        allOf(startsWith("access_token=;"), containsString("Max-Age=0;")),
                        allOf(startsWith("refresh_token=;"), containsString("Max-Age=0;")))));

        assertThat(form(keycloak.recorded("POST", REVOKE_PATH).get(0), "token")).isEqualTo("alice-refresh");
    }

    // The refresh cookie lives on /api/v1/auth. A clear on any other path is a different cookie
    // to the browser, and the original would survive the logout.
    @Test
    void logoutClearsEachCookieOnThePathItWasSetOn() throws Exception {
        keycloak.on("POST", REVOKE_PATH, StubHttpServer.StubResponse.empty(200));

        mvc.perform(post("/api/v1/auth/logout").cookie(refreshCookie("alice-refresh")))
                .andExpect(header().stringValues("Set-Cookie", hasItems(
                        allOf(startsWith("access_token=;"), containsString("Path=/;"), containsString("Max-Age=0;"),
                                containsString("HttpOnly"), containsString("SameSite=Strict")),
                        allOf(startsWith("refresh_token=;"), containsString("Path=/api/v1/auth;"), containsString("Max-Age=0;"),
                                containsString("HttpOnly"), containsString("SameSite=Strict")))));
    }
}
