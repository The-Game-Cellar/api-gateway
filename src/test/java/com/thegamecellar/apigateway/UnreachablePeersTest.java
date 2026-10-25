package com.thegamecellar.apigateway;

import ch.qos.logback.classic.Level;
import com.thegamecellar.apigateway.scheduler.AccountDeletionRetryJob;
import com.thegamecellar.apigateway.support.LogCapture;
import com.thegamecellar.apigateway.support.StubHttpServer;
import com.thegamecellar.apigateway.support.TestTokens;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// Keycloak and every service refusing the connection outright: nothing listens on their port.
// Only the realm's key is still published, so tokens can be checked and the failure is the
// peer's, not the token's.
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class UnreachablePeersTest {

    private static final String APP_URL = "http://app.test";
    private static final String NOBODY = "http://127.0.0.1:" + closedPort();
    private static final StubHttpServer JWKS = StubHttpServer.start();

    static {
        JWKS.serveQuietly("GET", TestTokens.JWKS_PATH, StubHttpServer.StubResponse.json(200, TestTokens.jwksJson()));
    }

    private static int closedPort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @DynamicPropertySource
    static void nobodyAnswers(DynamicPropertyRegistry registry) {
        registry.add("KEYCLOAK_AUTH_SERVER_URL", () -> NOBODY);
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri", () -> JWKS.baseUrl() + TestTokens.JWKS_PATH);
        registry.add("KEYCLOAK_ISSUER_URI", () -> TestTokens.ISSUER);
        registry.add("KEYCLOAK_PUBLIC_URL", () -> "http://auth.test");
        registry.add("GAME_SERVICE_URL", () -> NOBODY);
        registry.add("LIBRARY_SERVICE_URL", () -> NOBODY);
        registry.add("RECOMMENDATION_SERVICE_URL", () -> NOBODY);
        registry.add("APP_BASE_URL", () -> APP_URL);
        registry.add("AUTH_REDIRECT_URI", () -> "http://gw.test/api/v1/auth/callback");
        registry.add("ALLOWED_ORIGINS", () -> APP_URL);
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private AccountDeletionRetryJob job;

    @BeforeEach
    void forgetTokens() {
        TestTokens.forgetAll();
    }

    private static Cookie access(String name) {
        return new Cookie("access_token", TestTokens.resolve(name));
    }

    @Test
    void aProxiedCallToAServiceThatRefusesTheConnectionIsA504() throws Exception {
        TestTokens.issue("alice", "alice", Map.of());

        mvc.perform(get("/api/v1/library/games").cookie(access("alice")))
                .andExpect(status().isGatewayTimeout())
                .andExpect(jsonPath("$.error").value("Upstream service did not respond"));
    }

    @Test
    void aCodeExchangeKeycloakCannotBeReachedForLandsOnTheFailurePage() throws Exception {
        MvcResult authorize = mvc.perform(get("/api/v1/auth/authorize").param("intent", "UPDATE_PASSWORD")).andReturn();
        String state = UriComponentsBuilder.fromUriString(authorize.getResponse().getHeader("Location"))
                .build().getQueryParams().getFirst("state");

        mvc.perform(get("/api/v1/auth/callback")
                        .session((MockHttpSession) authorize.getRequest().getSession(false))
                        .param("code", "c").param("state", state))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", APP_URL + "/profile?action=password&status=error"))
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    @Test
    void anOutOfBandReturnKeycloakCannotBeReachedForGoesToTheDashboard() throws Exception {
        mvc.perform(get("/api/v1/auth/callback").cookie(new Cookie("refresh_token", "alice-refresh")))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", APP_URL + "/dashboard"));
    }

    @Test
    void aRefreshKeycloakCannotBeReachedForClearsTheSession() throws Exception {
        mvc.perform(post("/api/v1/auth/refresh").cookie(new Cookie("refresh_token", "alice-refresh")))
                .andExpect(status().isUnauthorized())
                .andExpect(header().stringValues("Set-Cookie", hasItems(
                        startsWith("access_token=;"), startsWith("refresh_token=;"))));
    }

    @Test
    void logoutClearsTheCookiesEvenWhenRevocationCannotBeReached() throws Exception {
        mvc.perform(post("/api/v1/auth/logout").cookie(new Cookie("refresh_token", "alice-refresh")))
                .andExpect(status().isOk())
                .andExpect(header().stringValues("Set-Cookie", hasItems(
                        startsWith("access_token=;"), startsWith("refresh_token=;"))));
    }

    @Test
    void anAccountDeleteWithNoIdentityProviderDeletesNothing() throws Exception {
        TestTokens.issue("fresh", "6f1c2d3e-0000-4000-8000-000000000009",
                Map.of("auth_time", Instant.now().getEpochSecond()));

        mvc.perform(delete("/api/v1/auth/account").cookie(access("fresh")))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.error").value("Could not reach the identity provider. Nothing was deleted, try again."))
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    @Test
    void anExportWithNoSourcesIsA502WithNoPartialFile() throws Exception {
        TestTokens.issue("alice", "alice", Map.of());

        mvc.perform(get("/api/v1/auth/account/export").cookie(access("alice")))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.account").doesNotExist());
    }

    @Test
    void theRetryJobWithNoLedgerToReachWarnsAndWaitsForTheNextRun() {
        try (LogCapture logs = LogCapture.of(AccountDeletionRetryJob.class)) {
            job.run();

            assertThat(logs.messages(Level.WARN)).anySatisfy(message -> assertThat(message).contains("ledger unreachable"));
        }
    }
}
