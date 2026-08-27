package com.thegamecellar.apigateway.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

// Every Admin REST call the gateway makes, sharing one cached service-account token.
// Used by the account deletion request and by the job that finishes deletions it left behind.
@Component
public class KeycloakAdminClient {

    private static final Logger log = LoggerFactory.getLogger(KeycloakAdminClient.class);
    private static final long TOKEN_SAFETY_MARGIN_MS = 5_000L;

    public enum Outcome { DONE, ALREADY_GONE }

    private record TokenWithExpiry(String token, long expiresAtEpochMillis) {}

    private final RestClient restClient;
    private final AtomicReference<TokenWithExpiry> cachedToken = new AtomicReference<>();
    private final String keycloakUrl;
    private final String realm;
    private final String clientId;
    private final String clientSecret;

    public KeycloakAdminClient(RestClient outboundRestClient,
                               @Value("${KEYCLOAK_AUTH_SERVER_URL:http://localhost:8080}") String keycloakUrl,
                               @Value("${KEYCLOAK_REALM:game-cellar}") String realm,
                               @Value("${GATEWAY_ADMIN_CLIENT_ID:gateway-admin}") String clientId,
                               @Value("${GATEWAY_ADMIN_CLIENT_SECRET}") String clientSecret) {
        this.restClient = outboundRestClient;
        this.keycloakUrl = keycloakUrl;
        this.realm = realm;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    // Partial update: Keycloak leaves every field the body omits as it was. Disabling also ends
    // token refresh, since the token endpoint checks the flag on every refresh grant.
    public Outcome setEnabled(String userId, boolean enabled) {
        return tolerateNotFound(() -> execute(token -> restClient.put()
                .uri(userUri(userId))
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("enabled", enabled))
                .retrieve()
                .toBodilessEntity()));
    }

    public Outcome logout(String userId) {
        return tolerateNotFound(() -> execute(token -> restClient.post()
                .uri(userUri(userId) + "/logout")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .toBodilessEntity()));
    }

    public Outcome delete(String userId) {
        return tolerateNotFound(() -> execute(token -> restClient.delete()
                .uri(userUri(userId))
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .toBodilessEntity()));
    }

    private String userUri(String userId) {
        return keycloakUrl + "/admin/realms/" + realm + "/users/" + userId;
    }

    // A user that is already gone is the state every caller here wants, not a failure.
    private static Outcome tolerateNotFound(Runnable call) {
        try {
            call.run();
            return Outcome.DONE;
        } catch (RestClientResponseException e) {
            if (e.getStatusCode().value() == 404) {
                return Outcome.ALREADY_GONE;
            }
            throw e;
        }
    }

    // Retry once on 401 so a rotated gateway-admin secret or revoked cached token recovers transparently.
    private void execute(Consumer<String> action) {
        try {
            action.accept(getToken());
        } catch (RestClientResponseException e) {
            if (e.getStatusCode().value() == 401) {
                cachedToken.set(null);
                action.accept(refreshToken());
                return;
            }
            throw e;
        }
    }

    private String getToken() {
        TokenWithExpiry cached = cachedToken.get();
        long now = System.currentTimeMillis();
        if (cached != null && cached.expiresAtEpochMillis() - TOKEN_SAFETY_MARGIN_MS > now) {
            return cached.token();
        }
        return refreshToken();
    }

    @SuppressWarnings("unchecked")
    private String refreshToken() {
        String tokenUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        Map<?, ?> tokens = restClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);
        String accessToken = (String) tokens.get("access_token");
        Object expiresInObj = tokens.get("expires_in");
        long expiresInSec = expiresInObj instanceof Number n ? n.longValue() : 60L;
        cachedToken.set(new TokenWithExpiry(accessToken, System.currentTimeMillis() + expiresInSec * 1000L));
        log.debug("Fetched a new gateway-admin token, valid {}s", expiresInSec);
        return accessToken;
    }
}
