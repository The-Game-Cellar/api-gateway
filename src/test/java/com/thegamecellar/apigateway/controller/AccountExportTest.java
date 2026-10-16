package com.thegamecellar.apigateway.controller;

import com.thegamecellar.apigateway.support.GatewayTestBase;
import com.thegamecellar.apigateway.support.StubHttpServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AccountExportTest extends GatewayTestBase {

    private static final String USER = "6f1c2d3e-0000-4000-8000-000000000002";
    private static final String ADMIN_USER_PATH = "/admin/realms/" + REALM + "/users/" + USER;
    private static final String CREDENTIALS_PATH = ADMIN_USER_PATH + "/credentials";
    private static final String SESSIONS_PATH = ADMIN_USER_PATH + "/sessions";
    private static final String LIBRARY_EXPORT_PATH = "/api/v1/library/account/export";
    private static final String RECOMMENDATION_EXPORT_PATH = "/api/v1/recommendations/account/export";
    private static final String EXPORT = "/api/v1/auth/account/export";

    // 2026-05-01T10:00:00Z and two later instants, as Keycloak sends them: epoch milliseconds.
    private static final long CREATED = 1777629600000L;
    private static final long SESSION_START = 1777633200000L;
    private static final long SESSION_LAST = 1777636800000L;

    @BeforeEach
    void everySourceAnswers() {
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.StubResponse.json(200,
                "{\"access_token\":\"admin-token\",\"expires_in\":60}"));
        // Registered user first: routes match on prefix and the newest wins.
        keycloak.on("GET", ADMIN_USER_PATH, StubHttpServer.StubResponse.json(200,
                "{\"id\":\"" + USER + "\",\"username\":\"alex\",\"email\":\"alex@example.test\",\"emailVerified\":true,"
                        + "\"firstName\":\"Alex\",\"lastName\":\"W\",\"createdTimestamp\":" + CREATED + ",\"enabled\":true}"));
        keycloak.on("GET", CREDENTIALS_PATH, StubHttpServer.StubResponse.json(200,
                "[{\"id\":\"c1\",\"type\":\"password\",\"createdDate\":" + CREATED + ","
                        + "\"credentialData\":\"{\\\"hashIterations\\\":210000,\\\"algorithm\\\":\\\"pbkdf2-sha512\\\"}\","
                        + "\"secretData\":\"{\\\"value\\\":\\\"hashed-secret\\\",\\\"salt\\\":\\\"pepper\\\"}\"},"
                        + "{\"id\":\"c2\",\"type\":\"otp\",\"userLabel\":\"Phone\",\"createdDate\":" + SESSION_START + "}]"));
        keycloak.on("GET", SESSIONS_PATH, StubHttpServer.StubResponse.json(200,
                "[{\"id\":\"s1\",\"username\":\"alex\",\"userId\":\"" + USER + "\",\"ipAddress\":\"203.0.113.7\","
                        + "\"start\":" + SESSION_START + ",\"lastAccess\":" + SESSION_LAST + ",\"clients\":{\"x\":\"game-cellar-client\"}}]"));
        libraryService.on("GET", LIBRARY_EXPORT_PATH, StubHttpServer.StubResponse.json(200,
                "{\"userId\":\"" + USER + "\",\"games\":[{\"gameName\":\"Hollow Knight\"}],\"onboardingCompletedAt\":\"2026-05-01T12:00:00\"}"));
        recommendationService.on("GET", RECOMMENDATION_EXPORT_PATH, StubHttpServer.StubResponse.json(200,
                "{\"userId\":\"" + USER + "\",\"profile\":{\"ratedCount\":5},\"candidatePool\":[]}"));
    }

    private void signedIn(String token) {
        issue(token, USER, Map.of());
    }

    // Each part as its source sent it, the account reduced to what the policy lists, and the
    // caller's own bearer token on both service calls.
    @Test
    void assemblesTheAccountAndBothServiceExportsIntoOneFile() throws Exception {
        signedIn("fresh");

        mvc.perform(get(EXPORT).cookie(accessCookie("fresh")))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andExpect(jsonPath("$.exportedAt").exists())
                .andExpect(jsonPath("$.account.userId").value(USER))
                .andExpect(jsonPath("$.account.username").value("alex"))
                .andExpect(jsonPath("$.account.email").value("alex@example.test"))
                .andExpect(jsonPath("$.account.emailVerified").value(true))
                .andExpect(jsonPath("$.account.firstName").value("Alex"))
                .andExpect(jsonPath("$.account.lastName").value("W"))
                .andExpect(jsonPath("$.account.createdAt").value("2026-05-01T10:00:00Z"))
                .andExpect(jsonPath("$.account.credentials", hasSize(2)))
                .andExpect(jsonPath("$.account.credentials[0].type").value("password"))
                .andExpect(jsonPath("$.account.credentials[0].createdAt").value("2026-05-01T10:00:00Z"))
                .andExpect(jsonPath("$.account.credentials[1].type").value("otp"))
                .andExpect(jsonPath("$.account.credentials[1].label").value("Phone"))
                .andExpect(jsonPath("$.account.sessions", hasSize(1)))
                .andExpect(jsonPath("$.account.sessions[0].ipAddress").value("203.0.113.7"))
                .andExpect(jsonPath("$.account.sessions[0].startedAt").value("2026-05-01T11:00:00Z"))
                .andExpect(jsonPath("$.account.sessions[0].lastAccessAt").value("2026-05-01T12:00:00Z"))
                .andExpect(jsonPath("$.library.games[0].gameName").value("Hollow Knight"))
                .andExpect(jsonPath("$.library.onboardingCompletedAt").value("2026-05-01T12:00:00"))
                .andExpect(jsonPath("$.recommendations.profile.ratedCount").value(5))
                // Nothing of a credential's secret or hashing setup leaves Keycloak.
                .andExpect(content().string(not(containsString("hashed-secret"))))
                .andExpect(content().string(not(containsString("pepper"))))
                .andExpect(content().string(not(containsString("hashIterations"))))
                .andExpect(content().string(not(containsString("secretData"))))
                .andExpect(content().string(not(containsString("credentialData"))));

        assertThat(libraryService.recorded("GET", LIBRARY_EXPORT_PATH).get(0).header("Authorization")).isEqualTo("Bearer fresh");
        assertThat(recommendationService.recorded("GET", RECOMMENDATION_EXPORT_PATH).get(0).header("Authorization")).isEqualTo("Bearer fresh");
        assertThat(keycloak.recorded("GET", ADMIN_USER_PATH))
                .allSatisfy(r -> assertThat(r.header("Authorization")).isEqualTo("Bearer admin-token"));
    }

    // The user is the token's subject and nothing else: there is no parameter to name another
    // one, and every admin read goes to that subject's own record.
    @Test
    void readsOnlyTheRecordOfTheUserInTheToken() throws Exception {
        signedIn("fresh");

        mvc.perform(get(EXPORT + "?userId=someone-else").cookie(accessCookie("fresh")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.account.userId").value(USER));

        assertThat(keycloak.recorded().stream().filter(r -> r.method().equals("GET")))
                .isNotEmpty()
                .allSatisfy(r -> assertThat(r.path()).startsWith(ADMIN_USER_PATH));
    }

    @Test
    void refusedWithoutACookieOrWithATokenTheDecoderRejects() throws Exception {
        mvc.perform(get(EXPORT))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Not authenticated"));

        // A cookie the decoder rejects never reaches the controller: the resource-server
        // filter reads the same cookie and answers 401 itself.
        mvc.perform(get(EXPORT).cookie(accessCookie("forged")))
                .andExpect(status().isUnauthorized());

        assertThat(keycloak.recorded()).isEmpty();
        assertThat(libraryService.recorded()).isEmpty();
        assertThat(recommendationService.recorded()).isEmpty();
    }

    @Test
    void refusedWhenTheTokenNamesNoSubject() throws Exception {
        Instant now = Instant.now();
        Jwt noSubject = Jwt.withTokenValue("no-sub").header("alg", "RS256").claim("azp", CLIENT_ID)
                .issuedAt(now).expiresAt(now.plusSeconds(300)).build();
        doReturn(noSubject).when(jwtDecoder).decode("no-sub");

        mvc.perform(get(EXPORT).cookie(accessCookie("no-sub")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid token"));

        assertThat(keycloak.recorded()).isEmpty();
    }

    // Complete or nothing: any part failing fails the whole export, with no partial file.
    @ParameterizedTest
    @ValueSource(strings = {"library", "recommendations", "user", "user-missing", "credentials", "sessions", "token"})
    void anyPartFailingFailsTheWholeExport(String failing) throws Exception {
        signedIn("fresh");
        switch (failing) {
            case "library" -> libraryService.on("GET", LIBRARY_EXPORT_PATH, StubHttpServer.StubResponse.json(500, "{}"));
            case "recommendations" -> recommendationService.on("GET", RECOMMENDATION_EXPORT_PATH, StubHttpServer.StubResponse.json(500, "{}"));
            case "user" -> keycloak.on("GET", ADMIN_USER_PATH, StubHttpServer.StubResponse.json(500, "{}"));
            // A user Keycloak no longer knows is a failure on a read, not an empty account.
            case "user-missing" -> keycloak.on("GET", ADMIN_USER_PATH, StubHttpServer.StubResponse.json(404, "{\"error\":\"User not found\"}"));
            case "credentials" -> keycloak.on("GET", CREDENTIALS_PATH, StubHttpServer.StubResponse.json(500, "{}"));
            case "sessions" -> keycloak.on("GET", SESSIONS_PATH, StubHttpServer.StubResponse.json(500, "{}"));
            case "token" -> {
                forgetAdminToken();
                keycloak.on("POST", TOKEN_PATH, StubHttpServer.StubResponse.json(404, "{\"error\":\"Realm does not exist\"}"));
            }
            default -> throw new IllegalArgumentException(failing);
        }

        mvc.perform(get(EXPORT).cookie(accessCookie("fresh")))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.error").value("Could not gather all of your data, try again"))
                .andExpect(jsonPath("$.account").doesNotExist())
                .andExpect(jsonPath("$.library").doesNotExist())
                .andExpect(jsonPath("$.recommendations").doesNotExist());
    }
}
