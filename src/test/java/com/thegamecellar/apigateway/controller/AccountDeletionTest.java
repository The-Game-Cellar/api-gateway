package com.thegamecellar.apigateway.controller;

import ch.qos.logback.classic.Level;
import com.thegamecellar.apigateway.support.GatewayTestBase;
import com.thegamecellar.apigateway.support.LogCapture;
import com.thegamecellar.apigateway.support.StubHttpServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
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
    private static final String RECOMMENDATION_PURGE_PATH = "/api/v1/recommendations/account";
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
        recommendationService.on("DELETE", RECOMMENDATION_PURGE_PATH, StubHttpServer.StubResponse.json(200, "{\"message\":\"purged\"}"));
        libraryService.on("DELETE", LIBRARY_PURGE_PATH, StubHttpServer.StubResponse.json(200, "{\"message\":\"purged\"}"));
        libraryService.on("POST", LEDGER_COMPLETE_PATH, StubHttpServer.StubResponse.empty(204));
    }

    private void freshlyAuthenticated(String token) {
        issue(token, USER, Map.of("auth_time", Instant.now().getEpochSecond()));
    }

    @Test
    void shutsTheIdentityThenPurgesBothServicesThenDeletesItThenClosesTheLedgerAndClearsCookies() throws Exception {
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
        StubHttpServer.RecordedRequest recommendations = recommendationService.recorded("DELETE", RECOMMENDATION_PURGE_PATH).get(0);
        StubHttpServer.RecordedRequest purge = libraryService.recorded("DELETE", LIBRARY_PURGE_PATH).get(0);
        StubHttpServer.RecordedRequest identity = keycloak.recorded("DELETE", ADMIN_USER_PATH).get(0);
        StubHttpServer.RecordedRequest complete = libraryService.recorded("POST", LEDGER_COMPLETE_PATH).get(0);

        assertThat(disable.body()).contains("\"enabled\":false");
        assertThat(disable.header("Authorization")).isEqualTo("Bearer admin-token");
        assertThat(recommendations.header("Authorization")).isEqualTo("Bearer " + token("fresh"));
        assertThat(purge.header("Authorization")).isEqualTo("Bearer " + token("fresh"));
        assertThat(identity.header("Authorization")).isEqualTo("Bearer admin-token");
        assertThat(complete.header("X-Internal-Token")).isEqualTo("test-internal-token");
        assertThat(disable.seq()).isLessThan(logout.seq());
        assertThat(logout.seq()).isLessThan(recommendations.seq());
        assertThat(recommendations.seq()).isLessThan(purge.seq());
        assertThat(purge.seq()).isLessThan(identity.seq());
        assertThat(identity.seq()).isLessThan(complete.seq());
    }

    @Test
    void refusedWithoutACookieOrWithATokenTheDecoderRejects() throws Exception {
        mvc.perform(delete("/api/v1/auth/account"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Not authenticated"));

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("forged")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid token"));

        assertThat(recommendationService.recorded()).isEmpty();
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

        assertThat(recommendationService.recorded()).isEmpty();
        assertThat(libraryService.recorded()).isEmpty();
        assertThat(keycloak.recorded("DELETE", ADMIN_USER_PATH)).isEmpty();
    }

    // A 404 from the token endpoint is a wrong realm or URL, never a user that is already gone.
    // Read as gone, the request would purge both services and answer "Account deleted" while
    // the identity stayed in Keycloak, enabled.
    @Test
    void aTokenEndpointAnswering404DeletesNothing() throws Exception {
        freshlyAuthenticated("fresh");
        forgetAdminToken();
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.StubResponse.json(404, "{\"error\":\"Realm does not exist\"}"));

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.error").value("Could not reach the identity provider. Nothing was deleted, try again."))
                .andExpect(header().doesNotExist("Set-Cookie"));

        assertThat(recommendationService.recorded()).isEmpty();
        assertThat(libraryService.recorded()).isEmpty();
        assertThat(keycloak.recorded("DELETE", ADMIN_USER_PATH)).isEmpty();
    }

    // Same failure on the second fetch, after a cached token was rejected.
    @Test
    void aTokenEndpointAnswering404OnTheRefetchDeletesNothing() throws Exception {
        freshlyAuthenticated("fresh");
        forgetAdminToken();
        List<Integer> tokenAnswers = new java.util.concurrent.CopyOnWriteArrayList<>(List.of(200, 404));
        keycloak.on("POST", TOKEN_PATH, request -> tokenAnswers.remove(0) == 200
                ? StubHttpServer.StubResponse.json(200, "{\"access_token\":\"admin-token\",\"expires_in\":60}")
                : StubHttpServer.StubResponse.json(404, "{\"error\":\"Realm does not exist\"}"));
        keycloak.on("PUT", ADMIN_USER_PATH, StubHttpServer.StubResponse.empty(401));

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                .andExpect(status().isBadGateway())
                .andExpect(header().doesNotExist("Set-Cookie"));

        assertThat(recommendationService.recorded()).isEmpty();
        assertThat(libraryService.recorded()).isEmpty();
        assertThat(keycloak.recorded("DELETE", ADMIN_USER_PATH)).isEmpty();
    }

    @Test
    void recommendationPurgeFailingReEnablesTheIdentityAndNeverReachesTheLibrary() throws Exception {
        freshlyAuthenticated("fresh");
        recommendationService.on("DELETE", RECOMMENDATION_PURGE_PATH, StubHttpServer.StubResponse.json(500, "{\"error\":\"db down\"}"));

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.error").value("Could not purge recommendation data, try again"))
                .andExpect(header().doesNotExist("Set-Cookie"));

        List<StubHttpServer.RecordedRequest> updates = keycloak.recorded("PUT", ADMIN_USER_PATH);
        assertThat(updates).hasSize(2);
        assertThat(updates.get(0).body()).contains("\"enabled\":false");
        assertThat(updates.get(1).body()).contains("\"enabled\":true");
        assertThat(libraryService.recorded()).isEmpty();
        assertThat(keycloak.recorded("DELETE", ADMIN_USER_PATH)).isEmpty();
    }

    // Recommendation data is rebuilt from the library, so having purged it before a library
    // failure costs nothing: the account comes back exactly as usable as it was.
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
        assertThat(recommendationService.recorded("DELETE", RECOMMENDATION_PURGE_PATH)).hasSize(1);
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

    // Each admin token the stub hands out is numbered, so a test can tell a fresh one from a reused one.
    private AtomicInteger numberedAdminTokens() {
        forgetAdminToken();
        AtomicInteger issued = new AtomicInteger();
        keycloak.on("POST", TOKEN_PATH, request -> StubHttpServer.StubResponse.json(200,
                "{\"access_token\":\"admin-token-" + issued.incrementAndGet() + "\",\"expires_in\":60}"));
        return issued;
    }

    // A 401 means the cached service-account token is dead. A 403 can mean the token predates a
    // role grant, since roles are baked in at issuance. Either way the retry must carry a token
    // fetched after the refusal, not the one that was just refused.
    @ParameterizedTest
    @ValueSource(ints = {401, 403})
    void aRefusedAdminCallIsRetriedOnceWithANewlyFetchedToken(int refusal) throws Exception {
        freshlyAuthenticated("fresh");
        AtomicInteger issued = numberedAdminTokens();
        keycloak.on("PUT", ADMIN_USER_PATH, request -> "Bearer admin-token-1".equals(request.header("Authorization"))
                ? StubHttpServer.StubResponse.empty(refusal)
                : StubHttpServer.StubResponse.empty(204));

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                .andExpect(status().isOk());

        List<StubHttpServer.RecordedRequest> disables = keycloak.recorded("PUT", ADMIN_USER_PATH);
        assertThat(disables).extracting(r -> r.header("Authorization"))
                .containsExactly("Bearer admin-token-1", "Bearer admin-token-2");
        assertThat(issued.get()).isEqualTo(2);
    }

    // One retry, then the answer stands: a service account that really lacks the role is not
    // asked a third time, and nothing is deleted.
    @Test
    void aRefusalThatSurvivesTheFreshTokenStandsAndDeletesNothing() throws Exception {
        freshlyAuthenticated("fresh");
        AtomicInteger issued = numberedAdminTokens();
        keycloak.on("PUT", ADMIN_USER_PATH, StubHttpServer.StubResponse.empty(403));

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                .andExpect(status().isBadGateway())
                .andExpect(header().doesNotExist("Set-Cookie"));

        assertThat(keycloak.recorded("PUT", ADMIN_USER_PATH)).hasSize(2);
        assertThat(issued.get()).isEqualTo(2);
        assertThat(recommendationService.recorded()).isEmpty();
        assertThat(libraryService.recorded()).isEmpty();
    }

    @Test
    void refusedWhenTheTokenNamesNoSubject() throws Exception {
        issueBare("no-sub", null, Map.of("azp", CLIENT_ID, "auth_time", Instant.now().getEpochSecond()));

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("no-sub")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid token"));

        assertThat(keycloak.recorded()).isEmpty();
        assertThat(recommendationService.recorded()).isEmpty();
        assertThat(libraryService.recorded()).isEmpty();
    }

    // The session lives in the cookie. A bearer header passes the security chain but names no
    // session, so it cannot delete an account.
    @Test
    void aBearerHeaderWithoutTheCookieDeletesNothing() throws Exception {
        freshlyAuthenticated("fresh");

        mvc.perform(delete("/api/v1/auth/account").header("Authorization", "Bearer " + token("fresh")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Not authenticated"));

        assertThat(keycloak.recorded()).isEmpty();
        assertThat(recommendationService.recorded()).isEmpty();
        assertThat(libraryService.recorded()).isEmpty();
    }

    // Five minutes plus thirty seconds of clock skew, with two seconds either side so the test
    // never races the clock.
    @Test
    void theReauthenticationWindowIsFiveMinutesPlusThirtySecondsOfSkew() throws Exception {
        issue("outside", USER, Map.of("auth_time", Instant.now().minusSeconds(332).getEpochSecond()));
        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("outside")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Re-authentication required"));
        assertThat(keycloak.recorded()).isEmpty();

        issue("inside", USER, Map.of("auth_time", Instant.now().minusSeconds(328).getEpochSecond()));
        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("inside")))
                .andExpect(status().isOk());
    }

    @Test
    void anIdentityProviderThatNeverAnswersTheDisableDeletesNothing() throws Exception {
        freshlyAuthenticated("fresh");
        keycloak.on("PUT", ADMIN_USER_PATH, StubHttpServer.after(Duration.ofSeconds(3), StubHttpServer.StubResponse.empty(204)));

        assertTimeoutPreemptively(Duration.ofSeconds(3), () ->
                mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                        .andExpect(status().isBadGateway())
                        .andExpect(jsonPath("$.error").value("Could not reach the identity provider. Nothing was deleted, try again."))
                        .andExpect(header().doesNotExist("Set-Cookie")));

        assertThat(recommendationService.recorded()).isEmpty();
        assertThat(libraryService.recorded()).isEmpty();
        assertThat(keycloak.recorded("DELETE", ADMIN_USER_PATH)).isEmpty();
    }

    // A purge that never answers is a failed purge: the identity is switched back on and the
    // account stays usable.
    @ParameterizedTest
    @ValueSource(strings = {"recommendation", "library"})
    void aPurgeThatNeverAnswersReEnablesTheIdentity(String hanging) throws Exception {
        freshlyAuthenticated("fresh");
        if (hanging.equals("recommendation")) {
            recommendationService.on("DELETE", RECOMMENDATION_PURGE_PATH,
                    StubHttpServer.after(Duration.ofSeconds(3), StubHttpServer.StubResponse.empty(200)));
        } else {
            libraryService.on("DELETE", LIBRARY_PURGE_PATH,
                    StubHttpServer.after(Duration.ofSeconds(3), StubHttpServer.StubResponse.empty(200)));
        }

        assertTimeoutPreemptively(Duration.ofSeconds(3), () ->
                mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                        .andExpect(status().isBadGateway())
                        .andExpect(jsonPath("$.error").value("Could not purge " + hanging + " data, try again"))
                        .andExpect(header().doesNotExist("Set-Cookie")));

        List<StubHttpServer.RecordedRequest> updates = keycloak.recorded("PUT", ADMIN_USER_PATH);
        assertThat(updates).extracting(StubHttpServer.RecordedRequest::body)
                .satisfiesExactly(
                        body -> assertThat(body).contains("\"enabled\":false"),
                        body -> assertThat(body).contains("\"enabled\":true"));
        assertThat(keycloak.recorded("DELETE", ADMIN_USER_PATH)).isEmpty();
    }

    // The user is left disabled with their data intact, which nobody would notice without the
    // ERROR: it is the event that reaches Sentry and says to re-enable by hand.
    @Test
    void aReEnableThatFailsAfterAFailedPurgeIsReportedAsAnError() throws Exception {
        freshlyAuthenticated("fresh");
        recommendationService.on("DELETE", RECOMMENDATION_PURGE_PATH, StubHttpServer.StubResponse.json(500, "{\"error\":\"db down\"}"));
        keycloak.on("PUT", ADMIN_USER_PATH, request -> request.body().contains("\"enabled\":true")
                ? StubHttpServer.StubResponse.json(500, "{\"error\":\"down\"}")
                : StubHttpServer.StubResponse.empty(204));

        try (LogCapture logs = LogCapture.of(AuthController.class)) {
            mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                    .andExpect(status().isBadGateway())
                    .andExpect(jsonPath("$.error").value("Could not purge recommendation data, try again"));

            assertThat(logs.messages(Level.ERROR))
                    .anySatisfy(message -> assertThat(message).contains(USER).contains("re-enable by hand"));
        }
        assertThat(libraryService.recorded()).isEmpty();
        assertThat(keycloak.recorded("DELETE", ADMIN_USER_PATH)).isEmpty();
    }

    // An identity Keycloak no longer has is the state a delete wants, so the account counts as
    // deleted and the ledger is closed.
    @Test
    void anIdentityAlreadyGoneAtTheDeleteCountsAsDeleted() throws Exception {
        freshlyAuthenticated("fresh");
        keycloak.on("DELETE", ADMIN_USER_PATH, StubHttpServer.StubResponse.json(404, "{\"error\":\"User not found\"}"));

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Account deleted"));

        assertThat(libraryService.recorded("POST", LEDGER_COMPLETE_PATH)).hasSize(1);
    }

    // The cookies are cleared on the paths they were set on, with the attributes they were set
    // with: a clear on any other path leaves the original in the browser.
    @Test
    void theClearingCookiesMatchThePathsAndAttributesTheCookiesWereSetWith() throws Exception {
        freshlyAuthenticated("fresh");

        mvc.perform(delete("/api/v1/auth/account").cookie(accessCookie("fresh")))
                .andExpect(status().isOk())
                .andExpect(header().stringValues("Set-Cookie", hasItems(
                        allOf(startsWith("access_token=;"), containsString("Path=/;"), containsString("Max-Age=0;"),
                                containsString("HttpOnly"), containsString("SameSite=Strict")),
                        allOf(startsWith("refresh_token=;"), containsString("Path=/api/v1/auth;"), containsString("Max-Age=0;"),
                                containsString("HttpOnly"), containsString("SameSite=Strict")))));
    }
}
