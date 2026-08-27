package com.thegamecellar.apigateway.controller;

import com.thegamecellar.apigateway.support.GatewayTestBase;
import com.thegamecellar.apigateway.support.StubHttpServer;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class CallbackEndpointTest extends GatewayTestBase {

    // The browser's half of the round trip: what /authorize handed out, kept for the return.
    private record Started(MockHttpSession session, String state, String nonce, String codeChallenge) {}

    private Started start(String... params) throws Exception {
        return start(null, params);
    }

    private Started start(jakarta.servlet.http.Cookie cookie, String... params) throws Exception {
        var request = get("/api/v1/auth/authorize");
        for (int i = 0; i < params.length; i += 2) {
            request = request.param(params[i], params[i + 1]);
        }
        if (cookie != null) {
            request = request.cookie(cookie);
        }
        MvcResult result = mvc.perform(request).andReturn();
        MultiValueMap<String, String> q = AuthorizeEndpointTest.query(result);
        return new Started((MockHttpSession) result.getRequest().getSession(false),
                q.getFirst("state"), q.getFirst("nonce"), q.getFirst("code_challenge"));
    }

    private void keycloakIssuesTokensFor(Started started, long authTimeSeconds) {
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.StubResponse.json(200,
                tokenJson("alice-access", "alice-refresh", "alice-id")));
        issue("alice-access", "alice", Map.of("auth_time", authTimeSeconds));
        issue("alice-id", "alice", Map.of("nonce", started.nonce(), "auth_time", authTimeSeconds));
    }

    private static String form(StubHttpServer.RecordedRequest request, String key) {
        String raw = UriComponentsBuilder.newInstance().query(request.body()).build().getQueryParams().getFirst(key);
        return raw == null ? null : java.net.URLDecoder.decode(raw, StandardCharsets.UTF_8);
    }

    private static String s256(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    @Test
    void successfulLoginExchangesTheCodeWithTheStoredVerifierAndSetsBothCookies() throws Exception {
        Started started = start();
        keycloakIssuesTokensFor(started, Instant.now().getEpochSecond());

        mvc.perform(get("/api/v1/auth/callback")
                        .session(started.session())
                        .param("code", "the-code")
                        .param("state", started.state()))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", APP_URL + "/dashboard"))
                .andExpect(header().stringValues("Set-Cookie",
                        org.hamcrest.Matchers.hasItems(
                                org.hamcrest.Matchers.allOf(
                                        org.hamcrest.Matchers.startsWith("access_token=alice-access;"),
                                        org.hamcrest.Matchers.containsString("Path=/;"),
                                        org.hamcrest.Matchers.containsString("Max-Age=300;"),
                                        org.hamcrest.Matchers.containsString("HttpOnly"),
                                        org.hamcrest.Matchers.containsString("SameSite=Strict")),
                                org.hamcrest.Matchers.allOf(
                                        org.hamcrest.Matchers.startsWith("refresh_token=alice-refresh;"),
                                        org.hamcrest.Matchers.containsString("Path=/api/v1/auth;"),
                                        org.hamcrest.Matchers.containsString("Max-Age=1800;")))));

        StubHttpServer.RecordedRequest exchange = keycloak.recorded("POST", TOKEN_PATH).get(0);
        assertThat(form(exchange, "grant_type")).isEqualTo("authorization_code");
        assertThat(form(exchange, "code")).isEqualTo("the-code");
        assertThat(form(exchange, "redirect_uri")).isEqualTo(REDIRECT_URI);
        assertThat(form(exchange, "client_id")).isEqualTo(CLIENT_ID);
        // PKCE closes only if the verifier sent back hashes to the challenge sent out.
        assertThat(s256(form(exchange, "code_verifier"))).isEqualTo(started.codeChallenge());
    }

    @Test
    void theSessionIsSingleUseSoAReplayedCodeFindsNoVerifier() throws Exception {
        Started started = start();
        keycloakIssuesTokensFor(started, Instant.now().getEpochSecond());

        mvc.perform(get("/api/v1/auth/callback").session(started.session())
                        .param("code", "the-code").param("state", started.state()))
                .andExpect(header().string("Location", APP_URL + "/dashboard"));

        mvc.perform(get("/api/v1/auth/callback").session(started.session())
                        .param("code", "the-code").param("state", started.state()))
                .andExpect(header().string("Location", APP_URL + "/login?error=auth_failed"));

        assertThat(keycloak.recorded("POST", TOKEN_PATH)).hasSize(1);
    }

    @Test
    void stateMismatchOrMissingCodeIsRejectedBeforeAnyExchange() throws Exception {
        Started started = start();
        keycloakIssuesTokensFor(started, Instant.now().getEpochSecond());

        mvc.perform(get("/api/v1/auth/callback").session(started.session())
                        .param("code", "the-code").param("state", "someone-elses-state"))
                .andExpect(header().string("Location", APP_URL + "/login?error=auth_failed"));

        Started again = start();
        mvc.perform(get("/api/v1/auth/callback").session(again.session())
                        .param("state", again.state()))
                .andExpect(header().string("Location", APP_URL + "/login?error=auth_failed"));

        // No session at all, which is what a callback forged from outside looks like.
        mvc.perform(get("/api/v1/auth/callback").param("code", "x").param("state", "y"))
                .andExpect(header().string("Location", APP_URL + "/login?error=auth_failed"));

        assertThat(keycloak.recorded("POST", TOKEN_PATH)).isEmpty();
    }

    @Test
    void nonceMismatchInTheIdTokenIsRejectedAndSetsNoCookies() throws Exception {
        Started started = start();
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.StubResponse.json(200,
                tokenJson("alice-access", "alice-refresh", "alice-id")));
        issue("alice-access", "alice");
        issue("alice-id", "alice", Map.of("nonce", "not-the-nonce"));

        mvc.perform(get("/api/v1/auth/callback").session(started.session())
                        .param("code", "the-code").param("state", started.state()))
                .andExpect(header().string("Location", APP_URL + "/login?error=auth_failed"))
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    @Test
    void keycloakRefusingTheExchangeLandsOnTheFailurePageForTheIntent() throws Exception {
        Started login = start();
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.StubResponse.json(400, "{\"error\":\"invalid_grant\"}"));
        mvc.perform(get("/api/v1/auth/callback").session(login.session())
                        .param("code", "the-code").param("state", login.state()))
                .andExpect(header().string("Location", APP_URL + "/login?error=auth_failed"));

        Started password = start("intent", "UPDATE_PASSWORD");
        mvc.perform(get("/api/v1/auth/callback").session(password.session())
                        .param("code", "the-code").param("state", password.state()))
                .andExpect(header().string("Location", APP_URL + "/profile?action=password&status=error"));
    }

    @Test
    void keycloakErrorParameterLandsOnTheFailurePageWithoutAnExchange() throws Exception {
        Started started = start("intent", "DELETE_ACCOUNT");

        mvc.perform(get("/api/v1/auth/callback").session(started.session())
                        .param("error", "access_denied"))
                .andExpect(header().string("Location", APP_URL + "/profile?action=delete&status=error"));

        assertThat(keycloak.recorded()).isEmpty();
    }

    @Test
    void deleteIntentNeedsAFreshAuthTimeToLandOnReady() throws Exception {
        Started fresh = start("intent", "DELETE_ACCOUNT");
        keycloakIssuesTokensFor(fresh, Instant.now().getEpochSecond());
        mvc.perform(get("/api/v1/auth/callback").session(fresh.session())
                        .param("code", "the-code").param("state", fresh.state()))
                .andExpect(header().string("Location", APP_URL + "/profile?action=delete&status=ready"));

        Started stale = start("intent", "DELETE_ACCOUNT");
        keycloakIssuesTokensFor(stale, Instant.now().minusSeconds(3600).getEpochSecond());
        mvc.perform(get("/api/v1/auth/callback").session(stale.session())
                        .param("code", "the-code").param("state", stale.state()))
                .andExpect(header().string("Location", APP_URL + "/profile?action=delete&status=reauth_failed"));
    }

    @Test
    void passwordChangeReportsKeycloaksActionStatus() throws Exception {
        Started started = start("intent", "UPDATE_PASSWORD");
        keycloakIssuesTokensFor(started, Instant.now().getEpochSecond());

        mvc.perform(get("/api/v1/auth/callback").session(started.session())
                        .param("code", "the-code").param("state", started.state())
                        .param("kc_action_status", "success"))
                .andExpect(header().string("Location", APP_URL + "/profile?action=password&status=success"));
    }

    // Keycloak reports success both when it wrote the address and when it only mailed a
    // confirmation, so the outcome is read by comparing the address before and after.
    @Test
    void emailChangeIsPendingWhenTheAddressDidNotMoveAndChangedWhenItDid() throws Exception {
        issue("old-access", "alice", Map.of("email", "alice@example.test"));

        Started same = start(accessCookie("old-access"), "intent", "UPDATE_EMAIL");
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.StubResponse.json(200,
                tokenJson("alice-access", "alice-refresh", "alice-id")));
        issue("alice-access", "alice", Map.of("email", "alice@example.test", "auth_time", Instant.now().getEpochSecond()));
        issue("alice-id", "alice", Map.of("nonce", same.nonce(), "auth_time", Instant.now().getEpochSecond()));
        mvc.perform(get("/api/v1/auth/callback").session(same.session())
                        .param("code", "c").param("state", same.state()).param("kc_action_status", "success"))
                .andExpect(header().string("Location", APP_URL + "/profile?action=email&status=pending"));

        Started moved = start(accessCookie("old-access"), "intent", "UPDATE_EMAIL");
        issue("alice-access", "alice", Map.of("email", "new@example.test", "auth_time", Instant.now().getEpochSecond()));
        issue("alice-id", "alice", Map.of("nonce", moved.nonce(), "auth_time", Instant.now().getEpochSecond()));
        mvc.perform(get("/api/v1/auth/callback").session(moved.session())
                        .param("code", "c").param("state", moved.state()).param("kc_action_status", "success"))
                .andExpect(header().string("Location", APP_URL + "/profile?action=email&status=changed"));
    }

    // Keycloak's confirmation branch ends on its own page and returns the browser with no code.
    // Whoever still holds a refresh cookie is signed in, so the tokens are refreshed rather
    // than the login declared failed.
    @Test
    void returnWithNeitherCodeNorStateRefreshesTheSessionInsteadOfFailing() throws Exception {
        Started started = start();
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.StubResponse.json(200,
                tokenJson("alice-access-2", "alice-refresh-2", "alice-id-2")));
        issue("alice-access-2", "alice");

        mvc.perform(get("/api/v1/auth/callback").session(started.session())
                        .cookie(refreshCookie("alice-refresh")))
                .andExpect(header().string("Location", APP_URL + "/dashboard"))
                .andExpect(header().stringValues("Set-Cookie",
                        org.hamcrest.Matchers.hasItem(org.hamcrest.Matchers.startsWith("access_token=alice-access-2;"))));

        StubHttpServer.RecordedRequest refresh = keycloak.recorded("POST", TOKEN_PATH).get(0);
        assertThat(form(refresh, "grant_type")).isEqualTo("refresh_token");
        assertThat(form(refresh, "refresh_token")).isEqualTo("alice-refresh");
    }

    @Test
    void returnWithNothingAndNoRefreshCookieIsAFailedLogin() throws Exception {
        Started started = start();

        mvc.perform(get("/api/v1/auth/callback").session(started.session()))
                .andExpect(header().string("Location", APP_URL + "/login?error=auth_failed"));

        assertThat(keycloak.recorded()).isEmpty();
    }

    @Test
    void tokensAreNeverSetFromAnUnverifiableIdToken() throws Exception {
        Started started = start();
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.StubResponse.json(200,
                tokenJson("alice-access", "alice-refresh", "garbage")));
        issue("alice-access", "alice");
        // "garbage" stays on the decoder's default path and throws.

        MvcResult result = mvc.perform(get("/api/v1/auth/callback").session(started.session())
                        .param("code", "the-code").param("state", started.state()))
                .andReturn();

        assertThat(result.getResponse().getHeader("Location")).isEqualTo(APP_URL + "/login?error=auth_failed");
        assertThat(result.getResponse().getHeaders("Set-Cookie")).isEqualTo(List.of());
    }
}
