package com.thegamecellar.apigateway.controller;

import ch.qos.logback.classic.Level;
import com.thegamecellar.apigateway.support.GatewayTestBase;
import com.thegamecellar.apigateway.support.LogCapture;
import com.thegamecellar.apigateway.support.StubHttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
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
        keycloak.on("POST", TOKEN_PATH, tokenResponse("alice-access", "alice-refresh", "alice-id"));
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
                                        org.hamcrest.Matchers.startsWith("access_token=" + token("alice-access") + ";"),
                                        org.hamcrest.Matchers.containsString("Path=/;"),
                                        org.hamcrest.Matchers.containsString("Max-Age=300;"),
                                        org.hamcrest.Matchers.containsString("HttpOnly"),
                                        org.hamcrest.Matchers.containsString("SameSite=Strict")),
                                org.hamcrest.Matchers.allOf(
                                        org.hamcrest.Matchers.startsWith("refresh_token=alice-refresh;"),
                                        org.hamcrest.Matchers.containsString("Path=/api/v1/auth;"),
                                        org.hamcrest.Matchers.containsString("Max-Age=1800;"),
                                        org.hamcrest.Matchers.containsString("HttpOnly"),
                                        org.hamcrest.Matchers.containsString("SameSite=Strict")))));

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
        keycloak.on("POST", TOKEN_PATH, tokenResponse("alice-access", "alice-refresh", "alice-id"));
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
        keycloak.on("POST", TOKEN_PATH, tokenResponse("alice-access", "alice-refresh", "alice-id"));
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
        keycloak.on("POST", TOKEN_PATH, tokenResponse("alice-access-2", "alice-refresh-2", "alice-id-2"));
        issue("alice-access-2", "alice");

        mvc.perform(get("/api/v1/auth/callback").session(started.session())
                        .cookie(refreshCookie("alice-refresh")))
                .andExpect(header().string("Location", APP_URL + "/dashboard"))
                .andExpect(header().stringValues("Set-Cookie",
                        org.hamcrest.Matchers.hasItem(org.hamcrest.Matchers.startsWith("access_token=" + token("alice-access-2") + ";"))));

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
        keycloak.on("POST", TOKEN_PATH, tokenResponse("alice-access", "alice-refresh", "garbage"));
        issue("alice-access", "alice");
        // Nobody issued "garbage", so it reaches the decoder as is and fails to parse.

        MvcResult result = mvc.perform(get("/api/v1/auth/callback").session(started.session())
                        .param("code", "the-code").param("state", started.state()))
                .andReturn();

        assertThat(result.getResponse().getHeader("Location")).isEqualTo(APP_URL + "/login?error=auth_failed");
        assertThat(result.getResponse().getHeaders("Set-Cookie")).isEqualTo(List.of());
    }

    // The browser is mid-navigation when Keycloak fails the exchange, so every failure lands on
    // the failure page for the intent, never on a JSON error.
    @ParameterizedTest
    @CsvSource({
            "500,   LOGIN,        /login?error=auth_failed",
            "503,   UPDATE_EMAIL, /profile?action=email&status=error",
            "empty, LOGIN,        /login?error=auth_failed",
            "empty, DELETE_ACCOUNT, /profile?action=delete&status=error",
    })
    void keycloakFailingTheExchangeLandsOnTheFailurePageWithNoCookies(String failure, String intent, String landing)
            throws Exception {
        Started started = start("intent", intent);
        keycloak.on("POST", TOKEN_PATH, failure.equals("empty")
                ? StubHttpServer.StubResponse.empty(200)
                : StubHttpServer.StubResponse.json(Integer.parseInt(failure), "{\"error\":\"unavailable\"}"));

        mvc.perform(get("/api/v1/auth/callback").session(started.session())
                        .param("code", "the-code").param("state", started.state()))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", APP_URL + landing))
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    @Test
    void keycloakNeverAnsweringTheExchangeLandsOnTheFailurePageInsteadOfHanging() {
        Started started = assertDoesNotThrowStart("intent", "UPDATE_PASSWORD");
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.after(Duration.ofSeconds(3),
                StubHttpServer.StubResponse.json(200, "{}")));

        assertTimeoutPreemptively(Duration.ofSeconds(2), () ->
                mvc.perform(get("/api/v1/auth/callback").session(started.session())
                                .param("code", "the-code").param("state", started.state()))
                        .andExpect(status().isFound())
                        .andExpect(header().string("Location", APP_URL + "/profile?action=password&status=error")));
    }

    @Test
    void errorOnALoginLandsOnTheLoginFailureWithoutAnExchange() throws Exception {
        Started started = start();

        mvc.perform(get("/api/v1/auth/callback").session(started.session()).param("error", "access_denied"))
                .andExpect(header().string("Location", APP_URL + "/login?error=auth_failed"));

        assertThat(keycloak.recorded()).isEmpty();
    }

    // The error value is whatever the query string says, so it must not be able to write a
    // line of its own into the log.
    @Test
    void anErrorValueCannotForgeALogLine() throws Exception {
        Started started = start();

        try (LogCapture logs = LogCapture.of(AuthController.class)) {
            mvc.perform(get("/api/v1/auth/callback").session(started.session())
                            .param("error", "access_denied\r\n12:00:00.000  INFO forged line\tend"))
                    .andExpect(header().string("Location", APP_URL + "/login?error=auth_failed"));

            assertThat(logs.messages(Level.WARN))
                    .anySatisfy(message -> assertThat(message).contains("access_denied")
                            .doesNotContain("\r").doesNotContain("\n").doesNotContain("\t"));
        }
    }

    @Test
    void stateMismatchOnAnAccountActionLandsOnThatActionsErrorWithoutAnExchange() throws Exception {
        Started started = start("intent", "UPDATE_EMAIL");

        mvc.perform(get("/api/v1/auth/callback").session(started.session())
                        .param("code", "the-code").param("state", "someone-elses-state"))
                .andExpect(header().string("Location", APP_URL + "/profile?action=email&status=error"));

        assertThat(keycloak.recorded()).isEmpty();
    }

    // max_age=0 makes auth_time mandatory, so its absence means Keycloak ignored the request
    // and nothing proves the user just signed in.
    @Test
    void deleteIntentWithNoAuthTimeIsNotReady() throws Exception {
        Started started = start("intent", "DELETE_ACCOUNT");
        keycloak.on("POST", TOKEN_PATH, tokenResponse("alice-access", "alice-refresh", "alice-id"));
        issue("alice-access", "alice");
        issue("alice-id", "alice", Map.of("nonce", started.nonce()));

        mvc.perform(get("/api/v1/auth/callback").session(started.session())
                        .param("code", "the-code").param("state", started.state()))
                .andExpect(header().string("Location", APP_URL + "/profile?action=delete&status=reauth_failed"));
    }

    // The action already ran on Keycloak's side, so a stale auth_time cannot undo it; it is
    // reported as Keycloak reported it, and the warning is what says the realm needs a look.
    @ParameterizedTest
    @CsvSource({
            "UPDATE_PASSWORD, /profile?action=password&status=success",
            "UPDATE_EMAIL,    /profile?action=email&status=changed",
    })
    void aStaleAuthTimeOnAnUpdateStillReportsTheOutcomeAndWarns(String intent, String landing) throws Exception {
        try (LogCapture logs = LogCapture.of(AuthController.class)) {
            Started fresh = start("intent", intent);
            keycloakIssuesTokensFor(fresh, Instant.now().getEpochSecond());
            mvc.perform(get("/api/v1/auth/callback").session(fresh.session())
                            .param("code", "c").param("state", fresh.state()).param("kc_action_status", "success"))
                    .andExpect(header().string("Location", APP_URL + landing));
            assertThat(logs.messages(Level.WARN)).noneSatisfy(m -> assertThat(m).contains("without a fresh authentication"));

            Started stale = start("intent", intent);
            keycloakIssuesTokensFor(stale, Instant.now().minusSeconds(3600).getEpochSecond());
            mvc.perform(get("/api/v1/auth/callback").session(stale.session())
                            .param("code", "c").param("state", stale.state()).param("kc_action_status", "success"))
                    .andExpect(header().string("Location", APP_URL + landing));
            assertThat(logs.messages(Level.WARN))
                    .anySatisfy(m -> assertThat(m).contains(intent).contains("without a fresh authentication"));
        }
    }

    @Test
    void anAbsentActionStatusIsUnknownAndAnyOtherIsPassedOn() throws Exception {
        Started absent = start("intent", "UPDATE_PASSWORD");
        keycloakIssuesTokensFor(absent, Instant.now().getEpochSecond());
        mvc.perform(get("/api/v1/auth/callback").session(absent.session())
                        .param("code", "c").param("state", absent.state()))
                .andExpect(header().string("Location", APP_URL + "/profile?action=password&status=unknown"));

        Started cancelled = start("intent", "UPDATE_EMAIL");
        keycloakIssuesTokensFor(cancelled, Instant.now().getEpochSecond());
        mvc.perform(get("/api/v1/auth/callback").session(cancelled.session())
                        .param("code", "c").param("state", cancelled.state()).param("kc_action_status", "cancelled"))
                .andExpect(header().string("Location", APP_URL + "/profile?action=email&status=cancelled"));
    }

    // The status is echoed into the landing URL, so it is encoded as one value and cannot add
    // a parameter of its own.
    @Test
    void aCraftedActionStatusCannotAddParametersToTheLanding() throws Exception {
        Started started = start("intent", "UPDATE_PASSWORD");
        keycloakIssuesTokensFor(started, Instant.now().getEpochSecond());

        MvcResult result = mvc.perform(get("/api/v1/auth/callback").session(started.session())
                        .param("code", "c").param("state", started.state())
                        .param("kc_action_status", "success&action=delete#x"))
                .andReturn();

        MultiValueMap<String, String> landing = AuthorizeEndpointTest.query(result);
        assertThat(landing.get("action")).containsExactly("password");
        assertThat(java.net.URLDecoder.decode(landing.getFirst("status"), StandardCharsets.UTF_8))
                .isEqualTo("success&action=delete#x");
    }

    // Keycloak's email confirmation ends on its own page and returns with no code. The tokens are
    // refreshed, and the refreshed address says whether the change has landed yet.
    @Test
    void outOfBandEmailReturnIsChangedWhenTheRefreshedAddressMovedAndProfileWhenItDidNot() throws Exception {
        issue("old-access", "alice", Map.of("email", "alice@example.test"));
        keycloak.on("POST", TOKEN_PATH, tokenResponse("alice-access-2", "alice-refresh-2", "alice-id-2"));

        Started moved = start(accessCookie("old-access"), "intent", "UPDATE_EMAIL");
        issue("alice-access-2", "alice", Map.of("email", "new@example.test"));
        mvc.perform(get("/api/v1/auth/callback").session(moved.session()).cookie(refreshCookie("alice-refresh")))
                .andExpect(header().string("Location", APP_URL + "/profile?action=email&status=changed"))
                .andExpect(header().stringValues("Set-Cookie", org.hamcrest.Matchers.hasItem(
                        org.hamcrest.Matchers.startsWith("access_token=" + token("alice-access-2") + ";"))));

        Started unchanged = start(accessCookie("old-access"), "intent", "UPDATE_EMAIL");
        issue("alice-access-2", "alice", Map.of("email", "alice@example.test"));
        mvc.perform(get("/api/v1/auth/callback").session(unchanged.session()).cookie(refreshCookie("alice-refresh")))
                .andExpect(header().string("Location", APP_URL + "/profile"));
    }

    // Whoever holds a refresh cookie is still signed in, so a refresh that fails here sends them
    // on to the app, where the next call settles it, rather than reporting a failed sign-in.
    @ParameterizedTest
    @ValueSource(strings = {"400", "500", "empty"})
    void outOfBandReturnWhoseRefreshFailsGoesToTheDashboardWithNoCookies(String failure) throws Exception {
        Started started = start("intent", "UPDATE_EMAIL");
        keycloak.on("POST", TOKEN_PATH, failure.equals("empty")
                ? StubHttpServer.StubResponse.empty(200)
                : StubHttpServer.StubResponse.json(Integer.parseInt(failure), "{\"error\":\"invalid_grant\"}"));

        mvc.perform(get("/api/v1/auth/callback").session(started.session()).cookie(refreshCookie("alice-refresh")))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", APP_URL + "/dashboard"))
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    @Test
    void outOfBandReturnWhoseRefreshNeverAnswersGoesToTheDashboardInsteadOfHanging() {
        Started started = assertDoesNotThrowStart("intent", "UPDATE_EMAIL");
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.after(Duration.ofSeconds(3),
                StubHttpServer.StubResponse.json(200, "{}")));

        assertTimeoutPreemptively(Duration.ofSeconds(2), () ->
                mvc.perform(get("/api/v1/auth/callback").session(started.session()).cookie(refreshCookie("alice-refresh")))
                        .andExpect(status().isFound())
                        .andExpect(header().string("Location", APP_URL + "/dashboard")));
    }

    // Keycloak's redirect back carries whatever access cookie the browser still holds. One the
    // decoder rejects must not turn a successful sign-in into a 401.
    @Test
    void aLoginReturnCarryingARejectedAccessCookieCompletes() throws Exception {
        Started started = start();
        keycloakIssuesTokensFor(started, Instant.now().getEpochSecond());

        mvc.perform(get("/api/v1/auth/callback").session(started.session())
                        .cookie(accessCookie("stale-or-forged"))
                        .param("code", "the-code").param("state", started.state()))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", APP_URL + "/dashboard"))
                .andExpect(header().stringValues("Set-Cookie", org.hamcrest.Matchers.hasItem(
                        org.hamcrest.Matchers.startsWith("access_token=" + token("alice-access") + ";"))));
    }

    // The same rule as the code exchange: no cookie is ever set from a token this gateway rejects.
    @Test
    void outOfBandReturnWhoseRefreshedTokenTheGatewayRejectsSetsNoCookies() throws Exception {
        Started started = start("intent", "UPDATE_EMAIL");
        keycloak.on("POST", TOKEN_PATH, tokenResponse("not-a-jwt", "alice-refresh-2", "alice-id-2"));

        mvc.perform(get("/api/v1/auth/callback").session(started.session()).cookie(refreshCookie("alice-refresh")))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", APP_URL + "/dashboard"))
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    private Started assertDoesNotThrowStart(String... params) {
        try {
            return start(params);
        } catch (Exception e) {
            throw new AssertionError("Starting the flow failed", e);
        }
    }
}
