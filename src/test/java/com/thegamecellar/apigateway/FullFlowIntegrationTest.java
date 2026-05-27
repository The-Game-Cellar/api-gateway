package com.thegamecellar.apigateway;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.*;
import org.springframework.test.context.TestPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

// @Disabled: requires live Keycloak (:8080) + Game Service (:8081). Run: mvn test -Dtest=FullFlowIntegrationTest
@SpringBootTest(webEnvironment = RANDOM_PORT)
@TestPropertySource(
        locations = "classpath:application-test.properties",
        properties = "recommendation.ratelimit.distributed=false")
class FullFlowIntegrationTest {

    private static final String GAMES_GENRES_PATH = "/api/v1/games/genres";

    private static final String TOKEN_URL =
            "http://localhost:8080/realms/game-cellar/protocol/openid-connect/token";

    @LocalServerPort
    private int port;

    @Value("${keycloak.test.client-secret}")
    private String clientSecret;

    @Value("${keycloak.test.username}")
    private String testUsername;

    @Value("${keycloak.test.password}")
    private String testPassword;

    @Test
    @Disabled("Requires Keycloak (:8080) and Game Service (:8081) to be running")
    void requestWithoutToken_shouldReturn401() {
        ResponseEntity<String> response = client()
                .get()
                .uri(gatewayUrl(GAMES_GENRES_PATH))
                .retrieve()
                .onStatus(status -> true, (req, res) -> {})
                .toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @Disabled("Requires Keycloak (:8080) and Game Service (:8081) to be running")
    void requestWithInvalidToken_shouldReturn401() {
        ResponseEntity<String> response = client()
                .get()
                .uri(gatewayUrl(GAMES_GENRES_PATH))
                .header(HttpHeaders.AUTHORIZATION, "Bearer garbage")
                .retrieve()
                .onStatus(status -> true, (req, res) -> {})
                .toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @Disabled("Requires Keycloak (:8080) and Game Service (:8081) to be running")
    void requestWithValidToken_shouldReturn200() {
        String token = fetchKeycloakToken();

        ResponseEntity<String> response = client()
                .get()
                .uri(gatewayUrl(GAMES_GENRES_PATH))
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .onStatus(status -> true, (req, res) -> {})
                .toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    private RestClient client() {
        return RestClient.create();
    }

    private String gatewayUrl(String path) {
        return "http://localhost:" + port + path;
    }

    @SuppressWarnings("unchecked")
    private String fetchKeycloakToken() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", "game-cellar-client");
        form.add("client_secret", clientSecret);
        form.add("username", testUsername);
        form.add("password", testPassword);

        ResponseEntity<Map> tokenResponse = RestClient.create()
                .post()
                .uri(TOKEN_URL)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .toEntity(Map.class);

        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(tokenResponse.getBody()).containsKey("access_token");

        return (String) tokenResponse.getBody().get("access_token");
    }
}
