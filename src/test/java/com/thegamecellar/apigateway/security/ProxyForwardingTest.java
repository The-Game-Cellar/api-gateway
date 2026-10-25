package com.thegamecellar.apigateway.security;

import com.thegamecellar.apigateway.support.GatewayTestBase;
import com.thegamecellar.apigateway.support.StubHttpServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// What the proxy does to a request on its way to a service and to the answer on its way back.
class ProxyForwardingTest extends GatewayTestBase {

    // Non-ASCII on purpose: a body that is re-encoded on the way through would not survive it.
    private static final String BODY = "{\"status\":\"PLAYING\",\"note\":\"Över ✓\"}";

    @BeforeEach
    void signedIn() {
        issue("alice-token", "alice");
        issueWithRoles("root-token", "root", "ADMIN");
    }

    private List<StubHttpServer> services() {
        return List.of(gameService, libraryService, recommendationService);
    }

    private void nothingReachedAnyService() {
        services().forEach(service -> assertThat(service.recorded()).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"POST", "PUT", "PATCH", "DELETE"})
    void aWriteReachesTheServiceWithItsMethodBodyAndContentType(String method) throws Exception {
        libraryService.on(method, "/api/v1/library/games/7", StubHttpServer.StubResponse.json(201, "{\"saved\":true}"));

        mvc.perform(request(HttpMethod.valueOf(method), "/api/v1/library/games/7")
                        .cookie(accessCookie("alice-token"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(BODY.getBytes(java.nio.charset.StandardCharsets.UTF_8)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.saved").value(true));

        StubHttpServer.RecordedRequest forwarded = libraryService.recorded(method, "/api/v1/library/games/7").get(0);
        assertThat(forwarded.body()).isEqualTo(BODY);
        assertThat(forwarded.header("Content-Type")).startsWith(MediaType.APPLICATION_JSON_VALUE);
        assertThat(forwarded.header("Authorization")).isEqualTo("Bearer " + token("alice-token"));
    }

    // Every route carries writes, not only the library's.
    @ParameterizedTest
    @CsvSource({
            "/api/v1/games/42/refresh,              game,           root-token",
            "/api/v1/admin/sync,                    game,           root-token",
            "/api/v1/admin/rec/recompute,           recommendation, root-token",
            "/api/v1/recommendations/feedback,      recommendation, alice-token",
            "/api/v1/library/platforms,             library,        alice-token",
    })
    void aPostReachesTheServiceThatOwnsThePrefixWithItsBody(String path, String service, String tokenName) throws Exception {
        StubHttpServer owner = switch (service) {
            case "game" -> gameService;
            case "library" -> libraryService;
            default -> recommendationService;
        };
        owner.on("POST", path, StubHttpServer.StubResponse.json(200, "{\"from\":\"" + service + "\"}"));

        mvc.perform(post(path).cookie(accessCookie(tokenName)).contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.from").value(service));

        assertThat(owner.recorded("POST", path).get(0).body()).isEqualTo(BODY);
    }

    // A service's own error is the answer: its status and its body reach the caller unchanged,
    // not replaced by one of the gateway's.
    @ParameterizedTest
    @ValueSource(ints = {400, 403, 404, 409, 500, 503})
    void aServiceErrorReachesTheCallerAsTheServiceSentIt(int code) throws Exception {
        libraryService.on("GET", "/api/v1/library/games/9", StubHttpServer.StubResponse.json(code,
                "{\"error\":\"from library\",\"status\":" + code + "}"));

        mvc.perform(get("/api/v1/library/games/9").cookie(accessCookie("alice-token")))
                .andExpect(status().is(code))
                .andExpect(content().json("{\"error\":\"from library\",\"status\":" + code + "}", true));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/v1/games/42",
            "/api/v1/platforms",
            "/api/v1/library/games",
            "/api/v1/recommendations/dashboard",
            "/api/v1/admin/sync",
            "/api/v1/admin/rec/refresh",
            "/api/v1/library/admin/curation",
    })
    void everyRouteRefusesARequestWithoutAToken(String path) throws Exception {
        mvc.perform(get(path)).andExpect(status().isUnauthorized());
        mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(BODY)).andExpect(status().isUnauthorized());

        nothingReachedAnyService();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/api/v1/admin/sync", "/api/v1/admin/rec/refresh", "/api/v1/library/admin/curation"})
    void everyAdminPrefixRefusesAUserWithoutTheAdminRole(String path) throws Exception {
        issueWithRoles("user-token", "carol", "user", "offline_access");

        mvc.perform(get(path).cookie(accessCookie("user-token"))).andExpect(status().isForbidden());
        mvc.perform(post(path).cookie(accessCookie("user-token")).contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isForbidden());

        nothingReachedAnyService();
    }

    // The header the caller sent is the identity that reaches the service; a cookie alongside it
    // does not replace it.
    @Test
    void aBearerHeaderWinsOverAnAccessCookieAndIsForwardedUnchanged() throws Exception {
        issue("bob-token", "bob");

        mvc.perform(get("/api/v1/library/games")
                        .header("Authorization", "Bearer " + token("alice-token"))
                        .cookie(accessCookie("bob-token")))
                .andExpect(status().isOk());

        assertThat(libraryService.recorded("GET", "/api/v1/library/games").get(0).header("Authorization"))
                .isEqualTo("Bearer " + token("alice-token"));
    }

    // library-service's internal paths sit behind a shared secret and are meant for the services
    // alone. No route forwards them, whoever asks and whatever they carry.
    @ParameterizedTest
    @ValueSource(strings = {
            "/internal/library/account-deletions/pending",
            "/internal/library/account-deletions/6f1c2d3e-0000-4000-8000-000000000001/complete",
    })
    void internalPathsAreNeverForwarded(String path) throws Exception {
        mvc.perform(get(path)).andExpect(status().isUnauthorized());
        mvc.perform(get(path).cookie(accessCookie("root-token"))
                        .header("X-Internal-Token", "test-internal-token"))
                .andExpect(status().isNotFound());
        mvc.perform(post(path).cookie(accessCookie("root-token"))
                        .header("X-Internal-Token", "test-internal-token"))
                .andExpect(status().isNotFound());

        nothingReachedAnyService();
    }

    // A path that climbs out of a routed prefix is refused before routing, plain or encoded.
    @ParameterizedTest
    @ValueSource(strings = {
            "/api/v1/library/../../internal/library/account-deletions/pending",
            "/api/v1/library/%2e%2e/%2e%2e/internal/library/account-deletions/pending",
            "/api/v1/library/%2E%2E%2F%2E%2E%2Finternal/library/account-deletions/pending",
    })
    void aPathClimbingOutOfARoutedPrefixIsRejected(String path) throws Exception {
        mvc.perform(get(path).cookie(accessCookie("root-token"))
                        .header("X-Internal-Token", "test-internal-token"))
                .andExpect(status().isBadRequest());

        nothingReachedAnyService();
    }

    // Open on purpose: the frontend's types are generated from it.
    @Test
    void theApiDescriptionIsReadableWithoutAToken() throws Exception {
        mvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.openapi").exists())
                .andExpect(jsonPath("$.paths['/api/v1/auth/me']").exists());

        nothingReachedAnyService();
    }

    @Test
    void responseHeadersFromTheServiceReachTheCaller() throws Exception {
        libraryService.on("GET", "/api/v1/library/games/9", new StubHttpServer.StubResponse(200, "{}",
                Map.of("Content-Type", "application/json", "X-Total-Count", "42")));

        mvc.perform(get("/api/v1/library/games/9").cookie(accessCookie("alice-token")))
                .andExpect(status().isOk())
                .andExpect(result -> assertThat(result.getResponse().getHeader("X-Total-Count")).isEqualTo("42"));
    }
}
