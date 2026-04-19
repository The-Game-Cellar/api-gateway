package com.thegamecellar.apigateway.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RestClient restClient = RestClient.create();

    @Value("${KEYCLOAK_AUTH_SERVER_URL:http://localhost:8080}")
    private String keycloakUrl;

    @Value("${KEYCLOAK_REALM:game-cellar}")
    private String realm;

    @Value("${KEYCLOAK_CLIENT_ID:game-cellar-client}")
    private String clientId;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body, HttpServletResponse response) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", clientId);
        form.add("scope", "openid");
        form.add("username", body.get("username"));
        form.add("password", body.get("password"));

        try {
            Map<?, ?> tokens = callKeycloak(form);
            setAuthCookies(response, tokens);
            return ResponseEntity.ok(extractUserInfo(tokens));
        } catch (RestClientResponseException e) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = readCookie(request, "refresh_token");
        if (refreshToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "No refresh token"));
        }

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "refresh_token");
        form.add("client_id", clientId);
        form.add("refresh_token", refreshToken);

        try {
            Map<?, ?> tokens = callKeycloak(form);
            setAuthCookies(response, tokens);
            return ResponseEntity.ok(extractUserInfo(tokens));
        } catch (RestClientResponseException e) {
            clearAuthCookies(response);
            return ResponseEntity.status(401).body(Map.of("error", "Refresh token expired"));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = readCookie(request, "refresh_token");
        if (refreshToken != null) {
            try {
                MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
                form.add("client_id", clientId);
                form.add("token", refreshToken);
                form.add("token_type_hint", "refresh_token");
                String revokeUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/revoke";
                restClient.post().uri(revokeUrl)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .body(form)
                        .retrieve()
                        .toBodilessEntity();
            } catch (Exception ignored) {
                // Best-effort revocation — always clear cookies regardless
            }
        }
        clearAuthCookies(response);
        return ResponseEntity.ok(Map.of("message", "Logged out"));
    }

    @PostMapping("/callback")
    public ResponseEntity<?> callback(@RequestBody Map<String, String> body, HttpServletResponse response) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("client_id", clientId);
        form.add("code", body.get("code"));
        form.add("redirect_uri", body.get("redirectUri"));
        if (body.get("codeVerifier") != null) {
            form.add("code_verifier", body.get("codeVerifier"));
        }

        try {
            Map<?, ?> tokens = callKeycloak(form);
            setAuthCookies(response, tokens);
            return ResponseEntity.ok(extractUserInfo(tokens));
        } catch (RestClientResponseException e) {
            return ResponseEntity.status(401).body(Map.of("error", "Authorization code exchange failed"));
        }
    }

    @SuppressWarnings("unchecked")
    private Map<?, ?> callKeycloak(MultiValueMap<String, String> form) {
        String tokenUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";
        return restClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);
    }

    private void setAuthCookies(HttpServletResponse response, Map<?, ?> tokens) {
        String accessToken = (String) tokens.get("access_token");
        String refreshToken = (String) tokens.get("refresh_token");
        Map<String, Object> userInfo = extractUserInfo(tokens);

        addCookie(response, ResponseCookie.from("access_token", accessToken)
                .httpOnly(true)
                .path("/")
                .maxAge(300)
                .sameSite("Strict")
                .build());

        addCookie(response, ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(true)
                .path("/api/v1/auth")
                .maxAge(1800)
                .sameSite("Strict")
                .build());

        addCookie(response, ResponseCookie.from("user_info", encodeUserInfo(userInfo))
                .httpOnly(false)
                .path("/")
                .maxAge(1800)
                .sameSite("Strict")
                .build());
    }

    private void clearAuthCookies(HttpServletResponse response) {
        for (String name : List.of("access_token", "user_info")) {
            addCookie(response, ResponseCookie.from(name, "")
                    .httpOnly(!name.equals("user_info"))
                    .path("/")
                    .maxAge(0)
                    .sameSite("Strict")
                    .build());
        }
        addCookie(response, ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .path("/api/v1/auth")
                .maxAge(0)
                .sameSite("Strict")
                .build());
    }

    private void addCookie(HttpServletResponse response, ResponseCookie cookie) {
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private Map<String, Object> extractUserInfo(Map<?, ?> tokens) {
        String accessToken = (String) tokens.get("access_token");
        Map<?, ?> claims = parseJwtPayload(accessToken);
        String userId = (String) claims.get("sub");
        String email = claims.containsKey("email")
                ? (String) claims.get("email")
                : (String) claims.get("preferred_username");

        Object roles = Collections.emptyList();
        Object realmAccessObj = claims.get("realm_access");
        if (realmAccessObj instanceof Map<?, ?> realmAccess) {
            Object rolesObj = realmAccess.get("roles");
            if (rolesObj != null) roles = rolesObj;
        }

        return Map.of(
                "userId", userId != null ? userId : "",
                "email", email != null ? email : "",
                "roles", roles
        );
    }

    @SuppressWarnings("unchecked")
    private Map<?, ?> parseJwtPayload(String token) {
        try {
            String[] parts = token.split("\\.");
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            return objectMapper.readValue(payload, Map.class);
        } catch (Exception e) {
            return Map.of();
        }
    }

    private String encodeUserInfo(Map<String, Object> userInfo) {
        try {
            String json = objectMapper.writeValueAsString(userInfo);
            return Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return "";
        }
    }

    private String readCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie c : cookies) {
            if (name.equals(c.getName())) return c.getValue();
        }
        return null;
    }
}
