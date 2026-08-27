package com.thegamecellar.apigateway.security;

import com.thegamecellar.apigateway.support.GatewayTestBase;
import com.thegamecellar.apigateway.support.StubHttpServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// Routes live in GatewayRoutesConfig as code because YAML routes silently fail on Gateway
// MVC 5.x. Each prefix must land on the right downstream, and the recommendation admin
// prefix must beat the wider game-service admin prefix it sits inside.
class RouteMappingTest extends GatewayTestBase {

    @BeforeEach
    void authenticate() {
        issueWithRoles("root-token", "root", "ADMIN");
    }

    @ParameterizedTest
    @CsvSource({
            "/api/v1/games/42,                game",
            "/api/v1/games/search?q=zelda,    game",
            "/api/v1/platforms,               game",
            "/api/v1/admin/sync,              game",
            "/api/v1/admin/rec/refresh,       recommendation",
            "/api/v1/library/games,           library",
            "/api/v1/library/account/export,  library",
            "/api/v1/recommendations/dashboard, recommendation",
    })
    void prefixReachesTheServiceThatOwnsIt(String path, String expectedService) throws Exception {
        mvc.perform(get(path).cookie(accessCookie("root-token")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.from").value(expectedService));

        StubHttpServer owner = switch (expectedService) {
            case "game" -> gameService;
            case "library" -> libraryService;
            default -> recommendationService;
        };
        String pathOnly = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;
        assertThat(owner.recorded("GET", pathOnly)).hasSize(1);
    }

    @ParameterizedTest
    @CsvSource({
            "/api/v1/games/search?q=zelda&limit=5, q=zelda&limit=5",
            "/api/v1/library/games?status=BACKLOG, status=BACKLOG",
    })
    void queryStringSurvivesTheProxy(String path, String expectedQuery) throws Exception {
        mvc.perform(get(path).cookie(accessCookie("root-token")))
                .andExpect(status().isOk());

        StubHttpServer owner = path.startsWith("/api/v1/games") ? gameService : libraryService;
        StubHttpServer.RecordedRequest forwarded = owner.recorded().get(0);
        assertThat(forwarded.query()).isEqualTo(expectedQuery);
    }
}
