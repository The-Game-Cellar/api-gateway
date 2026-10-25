package com.thegamecellar.apigateway.support;

import com.thegamecellar.apigateway.client.KeycloakAdminClient;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

// One Spring context for the whole suite. Every outbound URL the gateway knows points at a
// stub on this machine, and tokens are signed with a test key the Keycloak stub publishes as
// the realm's JWKS, so the gateway's own decoder checks signature, issuer, azp and expiry.
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public abstract class GatewayTestBase {

    public static final String APP_URL = "http://app.test";
    public static final String KEYCLOAK_PUBLIC_URL = "http://auth.test";
    public static final String REDIRECT_URI = "http://gw.test/api/v1/auth/callback";
    public static final String CLIENT_ID = TestTokens.CLIENT_ID;
    public static final String REALM = TestTokens.REALM;
    public static final String TOKEN_PATH = "/realms/" + REALM + "/protocol/openid-connect/token";

    protected static final StubHttpServer keycloak = StubHttpServer.start();
    protected static final StubHttpServer gameService = StubHttpServer.start();
    protected static final StubHttpServer libraryService = StubHttpServer.start();
    protected static final StubHttpServer recommendationService = StubHttpServer.start();

    static {
        keycloak.serveQuietly("GET", TestTokens.JWKS_PATH, StubHttpServer.StubResponse.json(200, TestTokens.jwksJson()));
    }

    @DynamicPropertySource
    static void wireStubs(DynamicPropertyRegistry registry) {
        registry.add("KEYCLOAK_AUTH_SERVER_URL", keycloak::baseUrl);
        registry.add("KEYCLOAK_PUBLIC_URL", () -> KEYCLOAK_PUBLIC_URL);
        registry.add("KEYCLOAK_ISSUER_URI", () -> TestTokens.ISSUER);
        registry.add("GAME_SERVICE_URL", gameService::baseUrl);
        registry.add("LIBRARY_SERVICE_URL", libraryService::baseUrl);
        registry.add("RECOMMENDATION_SERVICE_URL", recommendationService::baseUrl);
        registry.add("APP_BASE_URL", () -> APP_URL);
        registry.add("AUTH_REDIRECT_URI", () -> REDIRECT_URI);
        registry.add("ALLOWED_ORIGINS", () -> APP_URL);
    }

    @Autowired
    protected MockMvc mvc;

    @Autowired
    private KeycloakAdminClient keycloakAdminClient;

    @BeforeEach
    void resetStubsAndTokens() {
        keycloak.reset();
        gameService.reset();
        libraryService.reset();
        recommendationService.reset();
        TestTokens.forgetAll();
        gameService.on("GET", "/", StubHttpServer.StubResponse.json(200, "{\"from\":\"game\"}"));
        libraryService.on("GET", "/", StubHttpServer.StubResponse.json(200, "{\"from\":\"library\"}"));
        recommendationService.on("GET", "/", StubHttpServer.StubResponse.json(200, "{\"from\":\"recommendation\"}"));
    }

    protected String issue(String name, String subject, Map<String, Object> extraClaims) {
        return TestTokens.issue(name, subject, extraClaims);
    }

    protected String issue(String name, String subject) {
        return issue(name, subject, Map.of());
    }

    protected String issueBare(String name, String subject, Map<String, Object> claims) {
        return TestTokens.issueBare(name, subject, claims);
    }

    protected String issueWithRoles(String name, String subject, String... roles) {
        return issue(name, subject, Map.of("realm_access", Map.of("roles", List.of(roles))));
    }

    // The signed value behind a name, for asserting what was forwarded or set as a cookie.
    protected static String token(String name) {
        return TestTokens.resolve(name);
    }

    // The admin token is cached for the life of the shared context, so whether an admin call
    // fetches one depends on the tests before it. Forgetting it makes the next call fetch.
    protected void forgetAdminToken() {
        ((AtomicReference<?>) ReflectionTestUtils.getField(keycloakAdminClient, "cachedToken")).set(null);
    }

    protected static Cookie accessCookie(String name) {
        return new Cookie("access_token", token(name));
    }

    // Refresh tokens are opaque to the gateway, which only passes them to Keycloak.
    protected static Cookie refreshCookie(String token) {
        return new Cookie("refresh_token", token);
    }

    // Resolved when Keycloak is asked, so a test may issue the tokens after wiring the stub.
    protected static Function<StubHttpServer.RecordedRequest, StubHttpServer.StubResponse> tokenResponse(
            String accessName, String refreshToken, String idName) {
        return request -> StubHttpServer.StubResponse.json(200, "{\"access_token\":\"" + token(accessName)
                + "\",\"refresh_token\":\"" + refreshToken
                + "\",\"id_token\":\"" + token(idName) + "\",\"expires_in\":300}");
    }
}
