package com.thegamecellar.apigateway.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RestClient restClient = RestClient.create();

    @Value("${KEYCLOAK_AUTH_SERVER_URL:http://localhost:8080}")
    private String keycloakUrl;

    @Value("${KEYCLOAK_REALM:game-cellar}")
    private String realm;

    @Value("${KEYCLOAK_CLIENT_ID:game-cellar-client}")
    private String clientId;

    @Value("${COOKIE_SECURE:false}")
    private boolean cookieSecure;

    @Value("${GATEWAY_ADMIN_CLIENT_ID:gateway-admin}")
    private String adminClientId;

    @Value("${GATEWAY_ADMIN_CLIENT_SECRET:}")
    private String adminClientSecret;

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

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> body, HttpServletResponse response) {
        String username = body.get("username");
        String email    = body.get("email");
        String password = body.get("password");

        if (username == null || username.isBlank() ||
            email    == null || email.isBlank()    ||
            password == null || password.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Username, email, and password are required"));
        }

        try {
            String adminToken = getAdminToken();
            createKeycloakUser(adminToken, username, email, password);

            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("grant_type", "password");
            form.add("client_id", clientId);
            form.add("scope", "openid");
            form.add("username", username);
            form.add("password", password);

            Map<?, ?> tokens = callKeycloak(form);
            setAuthCookies(response, tokens);
            return ResponseEntity.ok(extractUserInfo(tokens));
        } catch (RestClientResponseException e) {
            log.error("Registration Keycloak error: status={} body={}", e.getStatusCode(), e.getResponseBodyAsString());
            if (e.getStatusCode().value() == 409) {
                return ResponseEntity.status(409).body(Map.of("error", "Username or email already taken"));
            }
            return ResponseEntity.status(400).body(Map.of("error", "Registration failed. Check your details and try again."));
        } catch (Exception e) {
            log.error("Registration unexpected error", e);
            return ResponseEntity.status(500).body(Map.of("error", "Registration failed. Please try again."));
        }
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

    @GetMapping("/me")
    public ResponseEntity<?> me(HttpServletRequest request) {
        String accessToken = readCookie(request, "access_token");
        if (accessToken == null || accessToken.isBlank()) {
            return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        }
        Map<?, ?> claims = parseJwtPayload(accessToken);
        if (claims.isEmpty()) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid token"));
        }
        return ResponseEntity.ok(extractUserInfoFromClaims(claims));
    }

    @SuppressWarnings("unchecked")
    private String getAdminToken() {
        String tokenUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", adminClientId);
        form.add("client_secret", adminClientSecret);
        Map<?, ?> tokens = restClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);
        return (String) tokens.get("access_token");
    }

    private void createKeycloakUser(String adminToken, String username, String email, String password) {
        String usersUrl = keycloakUrl + "/admin/realms/" + realm + "/users";
        Map<String, Object> credential = Map.of("type", "password", "value", password, "temporary", false);
        Map<String, Object> user = new LinkedHashMap<>();
        user.put("username", username);
        user.put("email", email);
        user.put("enabled", true);
        user.put("emailVerified", true);
        user.put("requiredActions", List.of());
        user.put("credentials", List.of(credential));

        var createResponse = restClient.post()
                .uri(usersUrl)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .body(user)
                .retrieve()
                .toBodilessEntity();

        // Extract userId from Location header and clear any realm-default required actions
        var location = createResponse.getHeaders().getLocation();
        log.info("User created. Location header: {}", location);
        if (location != null) {
            String userId = location.getPath().substring(location.getPath().lastIndexOf('/') + 1);
            log.info("Clearing required actions for userId: {}", userId);
            Map<String, Object> patch = Map.of("requiredActions", List.of());
            restClient.put()
                    .uri(keycloakUrl + "/admin/realms/" + realm + "/users/" + userId)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(patch)
                    .retrieve()
                    .toBodilessEntity();
            log.info("Required actions cleared for userId: {}", userId);
        } else {
            log.warn("No Location header returned — cannot clear required actions");
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

        addCookie(response, ResponseCookie.from("access_token", accessToken)
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/")
                .maxAge(300)
                .sameSite("Strict")
                .build());

        addCookie(response, ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/api/v1/auth")
                .maxAge(1800)
                .sameSite("Strict")
                .build());
    }

    private void clearAuthCookies(HttpServletResponse response) {
        addCookie(response, ResponseCookie.from("access_token", "")
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/")
                .maxAge(0)
                .sameSite("Strict")
                .build());
        addCookie(response, ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(cookieSecure)
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
        return extractUserInfoFromClaims(parseJwtPayload(accessToken));
    }

    private Map<String, Object> extractUserInfoFromClaims(Map<?, ?> claims) {
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

    private String readCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie c : cookies) {
            if (name.equals(c.getName())) return c.getValue();
        }
        return null;
    }
}
