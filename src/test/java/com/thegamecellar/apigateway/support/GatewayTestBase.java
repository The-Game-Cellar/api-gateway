package com.thegamecellar.apigateway.support;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.lenient;

// One Spring context for the whole suite. Every outbound URL the gateway knows points at a
// stub on this machine, and the JwtDecoder is a mock, so nothing here needs Keycloak, Redis
// or a downstream service to exist.
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public abstract class GatewayTestBase {

    public static final String APP_URL = "http://app.test";
    public static final String KEYCLOAK_PUBLIC_URL = "http://auth.test";
    public static final String REDIRECT_URI = "http://gw.test/api/v1/auth/callback";
    public static final String CLIENT_ID = "game-cellar-client";
    public static final String REALM = "game-cellar";
    public static final String TOKEN_PATH = "/realms/" + REALM + "/protocol/openid-connect/token";

    protected static final StubHttpServer keycloak = StubHttpServer.start();
    protected static final StubHttpServer gameService = StubHttpServer.start();
    protected static final StubHttpServer libraryService = StubHttpServer.start();
    protected static final StubHttpServer recommendationService = StubHttpServer.start();

    @DynamicPropertySource
    static void wireStubs(DynamicPropertyRegistry registry) {
        registry.add("KEYCLOAK_AUTH_SERVER_URL", keycloak::baseUrl);
        registry.add("KEYCLOAK_PUBLIC_URL", () -> KEYCLOAK_PUBLIC_URL);
        registry.add("GAME_SERVICE_URL", gameService::baseUrl);
        registry.add("LIBRARY_SERVICE_URL", libraryService::baseUrl);
        registry.add("RECOMMENDATION_SERVICE_URL", recommendationService::baseUrl);
        registry.add("APP_BASE_URL", () -> APP_URL);
        registry.add("AUTH_REDIRECT_URI", () -> REDIRECT_URI);
        registry.add("ALLOWED_ORIGINS", () -> APP_URL);
    }

    @Autowired
    protected MockMvc mvc;

    @MockitoBean
    protected JwtDecoder jwtDecoder;

    @BeforeEach
    void resetStubsAndDecoder() {
        keycloak.reset();
        gameService.reset();
        libraryService.reset();
        recommendationService.reset();
        gameService.on("GET", "/", StubHttpServer.StubResponse.json(200, "{\"from\":\"game\"}"));
        libraryService.on("GET", "/", StubHttpServer.StubResponse.json(200, "{\"from\":\"library\"}"));
        recommendationService.on("GET", "/", StubHttpServer.StubResponse.json(200, "{\"from\":\"recommendation\"}"));
        // Anything not explicitly issued by a test is rejected, the way a real decoder rejects
        // a token it cannot verify.
        lenient().when(jwtDecoder.decode(anyString())).thenThrow(new BadJwtException("unknown token"));
    }

    protected Jwt issue(String tokenValue, String subject, Map<String, Object> extraClaims) {
        Instant now = Instant.now();
        Jwt.Builder builder = Jwt.withTokenValue(tokenValue)
                .header("alg", "RS256")
                .subject(subject)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .claim("azp", CLIENT_ID)
                .claim("email", subject + "@example.test")
                .claim("preferred_username", subject);
        extraClaims.forEach(builder::claim);
        Jwt jwt = builder.build();
        // doReturn rather than when(): when() would invoke the mock, and the default stub throws.
        doReturn(jwt).when(jwtDecoder).decode(tokenValue);
        return jwt;
    }

    protected Jwt issue(String tokenValue, String subject) {
        return issue(tokenValue, subject, Map.of());
    }

    // No defaults at all, for the cases where a claim being absent is the point.
    protected Jwt issueBare(String tokenValue, String subject, Map<String, Object> claims) {
        Instant now = Instant.now();
        Jwt.Builder builder = Jwt.withTokenValue(tokenValue)
                .header("alg", "RS256")
                .subject(subject)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300));
        claims.forEach(builder::claim);
        Jwt jwt = builder.build();
        doReturn(jwt).when(jwtDecoder).decode(tokenValue);
        return jwt;
    }

    protected Jwt issueWithRoles(String tokenValue, String subject, String... roles) {
        return issue(tokenValue, subject, Map.of("realm_access", Map.of("roles", List.of(roles))));
    }

    protected static Cookie accessCookie(String token) {
        return new Cookie("access_token", token);
    }

    protected static Cookie refreshCookie(String token) {
        return new Cookie("refresh_token", token);
    }

    protected static String tokenJson(String accessToken, String refreshToken, String idToken) {
        return "{\"access_token\":\"" + accessToken + "\",\"refresh_token\":\"" + refreshToken
                + "\",\"id_token\":\"" + idToken + "\",\"expires_in\":300}";
    }
}
