package com.thegamecellar.apigateway.controller;

import com.thegamecellar.apigateway.support.GatewayTestBase;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

// Production runs with COOKIE_SECURE=true. Over a real socket, because MockMvc never sees the
// servlet container's session cookie, which is the one carrying the PKCE verifier.
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = "COOKIE_SECURE=true")
class SecureCookiesTest extends GatewayTestBase {

    @LocalServerPort
    private int port;

    // Redirects are not followed, so every Location and Set-Cookie is the gateway's own.
    private final HttpClient http = HttpClient.newHttpClient();

    private HttpResponse<String> send(HttpRequest.Builder request) throws Exception {
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private URI url(String pathAndQuery) {
        return URI.create("http://localhost:" + port + pathAndQuery);
    }

    private static String cookie(HttpResponse<?> response, String name) {
        return response.headers().allValues("Set-Cookie").stream()
                .filter(header -> header.startsWith(name + "="))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No " + name + " cookie in " + response.headers().allValues("Set-Cookie")));
    }

    // Lax, not Strict: the browser must send it on the redirect back from Keycloak, or no
    // login could pass the state check.
    @Test
    void theSessionCookieThatCarriesTheVerifierIsHttpOnlyLaxAndSecure() throws Exception {
        HttpResponse<String> response = send(HttpRequest.newBuilder(url("/api/v1/auth/authorize")).GET());

        assertThat(response.statusCode()).isEqualTo(302);
        assertThat(cookie(response, "JSESSIONID"))
                .contains("HttpOnly")
                .contains("Secure")
                .contains("SameSite=Lax");
    }

    @Test
    void theAuthCookiesAreSecureWhenSetAndWhenCleared() throws Exception {
        HttpResponse<String> authorize = send(HttpRequest.newBuilder(url("/api/v1/auth/authorize")).GET());
        String session = cookie(authorize, "JSESSIONID").split(";")[0];
        Map<String, List<String>> query = UriComponentsBuilder
                .fromUriString(authorize.headers().firstValue("Location").orElseThrow())
                .build().getQueryParams();
        String state = query.get("state").get(0);
        String nonce = query.get("nonce").get(0);

        keycloak.on("POST", TOKEN_PATH, tokenResponse("alice-access", "alice-refresh", "alice-id"));
        issue("alice-access", "alice", Map.of("auth_time", Instant.now().getEpochSecond()));
        issue("alice-id", "alice", Map.of("nonce", nonce));

        HttpResponse<String> callback = send(HttpRequest.newBuilder(url("/api/v1/auth/callback?code=c&state=" + state))
                .header("Cookie", session).GET());

        assertThat(callback.headers().firstValue("Location")).hasValue(APP_URL + "/dashboard");
        assertThat(cookie(callback, "access_token")).contains("Secure").contains("HttpOnly").contains("SameSite=Strict");
        assertThat(cookie(callback, "refresh_token")).contains("Secure").contains("HttpOnly").contains("SameSite=Strict");

        keycloak.on("POST", "/realms/" + REALM + "/protocol/openid-connect/revoke",
                com.thegamecellar.apigateway.support.StubHttpServer.StubResponse.empty(200));
        HttpResponse<String> logout = send(HttpRequest.newBuilder(url("/api/v1/auth/logout"))
                .header("Cookie", "refresh_token=alice-refresh")
                .POST(HttpRequest.BodyPublishers.noBody()));

        assertThat(logout.statusCode()).isEqualTo(200);
        // A clearing cookie without Secure cannot replace a Secure one, so the clear must carry it too.
        assertThat(cookie(logout, "access_token")).contains("Max-Age=0").contains("Secure");
        assertThat(cookie(logout, "refresh_token")).contains("Max-Age=0").contains("Secure");
    }
}
