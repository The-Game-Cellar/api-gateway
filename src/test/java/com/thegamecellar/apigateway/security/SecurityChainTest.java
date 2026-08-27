package com.thegamecellar.apigateway.security;

import com.thegamecellar.apigateway.support.GatewayTestBase;
import com.thegamecellar.apigateway.support.StubHttpServer;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class SecurityChainTest extends GatewayTestBase {

    @Test
    void protectedRouteWithoutTokenIs401AndNeverReachesDownstream() throws Exception {
        mvc.perform(get("/api/v1/library/games"))
                .andExpect(status().isUnauthorized());

        assertThat(libraryService.recorded()).isEmpty();
    }

    @Test
    void tokenTheDecoderRejectsIs401() throws Exception {
        mvc.perform(get("/api/v1/library/games").header("Authorization", "Bearer forged"))
                .andExpect(status().isUnauthorized());

        assertThat(libraryService.recorded()).isEmpty();
    }

    @Test
    void bearerHeaderIsAcceptedAndForwardedAsIs() throws Exception {
        issue("alice-token", "alice");

        mvc.perform(get("/api/v1/library/games").header("Authorization", "Bearer alice-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.from").value("library"));

        StubHttpServer.RecordedRequest forwarded = libraryService.recorded("GET", "/api/v1/library/games").get(0);
        assertThat(forwarded.header("Authorization")).isEqualTo("Bearer alice-token");
    }

    // The browser never holds the token: it arrives as an httpOnly cookie and leaves the
    // gateway as the Authorization header the services expect.
    @Test
    void accessCookieIsAcceptedAndTranslatedToBearerHeaderDownstream() throws Exception {
        issue("alice-token", "alice");

        mvc.perform(get("/api/v1/library/games").cookie(accessCookie("alice-token")))
                .andExpect(status().isOk());

        StubHttpServer.RecordedRequest forwarded = libraryService.recorded("GET", "/api/v1/library/games").get(0);
        assertThat(forwarded.header("Authorization")).isEqualTo("Bearer alice-token");
    }

    @Test
    void adminPrefixRequiresRealmAdminRole() throws Exception {
        issue("alice-token", "alice");
        issueWithRoles("admin-token", "root", "ADMIN");

        mvc.perform(get("/api/v1/admin/sync").cookie(accessCookie("alice-token")))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/v1/library/admin/curation").cookie(accessCookie("alice-token")))
                .andExpect(status().isForbidden());
        assertThat(gameService.recorded()).isEmpty();
        assertThat(libraryService.recorded()).isEmpty();

        mvc.perform(get("/api/v1/admin/sync").cookie(accessCookie("admin-token")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.from").value("game"));
    }

    @Test
    void healthAndAuthPathsNeedNoToken() throws Exception {
        mvc.perform(get("/actuator/health"))
                .andExpect(status().isOk());

        // Reaches the controller, which answers 401 for a missing cookie on its own terms:
        // the security chain let it through.
        mvc.perform(get("/api/v1/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Not authenticated"));
    }

    @Test
    void unknownPathAnswers404NotFive00() throws Exception {
        issue("alice-token", "alice");

        mvc.perform(get("/nothing/here").cookie(accessCookie("alice-token")))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("Resource not found"))
                .andExpect(jsonPath("$.requestId").isNotEmpty());
    }

    @Test
    void requestIdIsEchoedAndSanitised() throws Exception {
        mvc.perform(get("/api/v1/auth/me"))
                .andExpect(header().exists("X-Request-ID"));

        String tooLong = "x".repeat(200);
        mvc.perform(get("/api/v1/auth/me").header("X-Request-ID", tooLong))
                .andExpect(header().string("X-Request-ID", "x".repeat(64)));

        mvc.perform(get("/api/v1/auth/me").header("X-Request-ID", "abc\r\nInjected: line"))
                .andExpect(header().string("X-Request-ID", "abc__Injected: line"));
    }
}
