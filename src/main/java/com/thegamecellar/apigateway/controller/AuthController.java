package com.thegamecellar.apigateway.controller;

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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final RestClient restClient = RestClient.create();
    private final JwtDecoder jwtDecoder;

    public AuthController(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

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

    @Value("${GATEWAY_ADMIN_CLIENT_SECRET}")
    private String adminClientSecret;

    @Value("${LIBRARY_SERVICE_URL:http://localhost:8082}")
    private String libraryServiceUrl;

    private static final long ADMIN_TOKEN_SAFETY_MARGIN_MS = 5_000L;
    private final AtomicReference<TokenWithExpiry> cachedAdminToken = new AtomicReference<>();

    private record TokenWithExpiry(String token, long expiresAtEpochMillis) {}

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
            createKeycloakUser(username, email, password);

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

    @PutMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody Map<String, String> body,
                                            HttpServletRequest request) {
        String currentPassword = body.get("currentPassword");
        String newPassword     = body.get("newPassword");

        if (currentPassword == null || currentPassword.isBlank() ||
            newPassword     == null || newPassword.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Current and new password are required"));
        }

        if (!isPasswordStrong(newPassword)) {
            return ResponseEntity.badRequest().body(Map.of("error",
                    "New password must be at least 8 characters and contain at least one letter and one digit"));
        }

        String accessToken = readCookie(request, "access_token");
        if (accessToken == null || accessToken.isBlank()) {
            return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        }
        Map<?, ?> claims = parseJwtPayload(accessToken);
        String userId = (String) claims.get("sub");
        String username = (String) claims.get("preferred_username");
        if (userId == null || username == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid token"));
        }

        if (!verifyPassword(username, currentPassword)) {
            return ResponseEntity.status(401).body(Map.of("error", "Current password is incorrect"));
        }

        try {
            Map<String, Object> credential = Map.of("type", "password", "value", newPassword, "temporary", false);
            adminPut(keycloakUrl + "/admin/realms/" + realm + "/users/" + userId + "/reset-password", credential);
            return ResponseEntity.ok(Map.of("message", "Password updated"));
        } catch (RestClientResponseException e) {
            log.error("Change password Keycloak error: status={} body={}", e.getStatusCode(), e.getResponseBodyAsString());
            return ResponseEntity.status(400).body(Map.of("error", "Password update failed. Check requirements and try again."));
        } catch (Exception e) {
            log.error("Change password unexpected error", e);
            return ResponseEntity.status(500).body(Map.of("error", "Password update failed. Please try again."));
        }
    }

    @PutMapping("/change-email")
    public ResponseEntity<?> changeEmail(@RequestBody Map<String, String> body,
                                         HttpServletRequest request,
                                         HttpServletResponse response) {
        String currentPassword = body.get("currentPassword");
        String newEmail        = body.get("newEmail");

        if (currentPassword == null || currentPassword.isBlank() ||
            newEmail        == null || newEmail.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Current password and new email are required"));
        }

        String accessToken = readCookie(request, "access_token");
        if (accessToken == null || accessToken.isBlank()) {
            return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        }
        Map<?, ?> claims = parseJwtPayload(accessToken);
        String userId = (String) claims.get("sub");
        String username = (String) claims.get("preferred_username");
        String currentEmail = (String) claims.get("email");
        if (userId == null || username == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid token"));
        }

        if (currentEmail != null && currentEmail.equalsIgnoreCase(newEmail.trim())) {
            return ResponseEntity.badRequest().body(Map.of("error", "New email is the same as current email"));
        }

        if (!verifyPassword(username, currentPassword)) {
            return ResponseEntity.status(401).body(Map.of("error", "Current password is incorrect"));
        }

        try {
            Map<String, Object> patch = Map.of("email", newEmail.trim(), "emailVerified", true);
            adminPut(keycloakUrl + "/admin/realms/" + realm + "/users/" + userId, patch);

            String refreshToken = readCookie(request, "refresh_token");
            if (refreshToken != null) {
                MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
                form.add("grant_type", "refresh_token");
                form.add("client_id", clientId);
                form.add("refresh_token", refreshToken);
                Map<?, ?> tokens = callKeycloak(form);
                setAuthCookies(response, tokens);
                return ResponseEntity.ok(extractUserInfo(tokens));
            }
            return ResponseEntity.ok(Map.of("message", "Email updated"));
        } catch (RestClientResponseException e) {
            log.error("Change email Keycloak error: status={} body={}", e.getStatusCode(), e.getResponseBodyAsString());
            if (e.getStatusCode().value() == 409) {
                return ResponseEntity.status(409).body(Map.of("error", "Email already in use"));
            }
            return ResponseEntity.status(400).body(Map.of("error", "Email update failed. Check the address and try again."));
        } catch (Exception e) {
            log.error("Change email unexpected error", e);
            return ResponseEntity.status(500).body(Map.of("error", "Email update failed. Please try again."));
        }
    }

    @DeleteMapping("/account")
    public ResponseEntity<?> deleteAccount(@RequestBody Map<String, String> body,
                                            HttpServletRequest request,
                                            HttpServletResponse response) {
        String currentPassword = body.get("currentPassword");
        if (currentPassword == null || currentPassword.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Current password is required"));
        }

        String accessToken = readCookie(request, "access_token");
        if (accessToken == null || accessToken.isBlank()) {
            return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        }
        Map<?, ?> claims = parseJwtPayload(accessToken);
        String userId = (String) claims.get("sub");
        String username = (String) claims.get("preferred_username");
        if (userId == null || username == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid token"));
        }

        if (!verifyPassword(username, currentPassword)) {
            return ResponseEntity.status(401).body(Map.of("error", "Current password is incorrect"));
        }

        try {
            // Step 1: purge user data from library_db.
            // If this fails, Keycloak account stays intact and user can retry.
            try {
                restClient.delete()
                        .uri(libraryServiceUrl + "/api/v1/library/account")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                        .retrieve()
                        .toBodilessEntity();
            } catch (RestClientResponseException e) {
                log.error("Account delete: library purge failed for userId={}: status={} body={}",
                        userId, e.getStatusCode(), e.getResponseBodyAsString());
                return ResponseEntity.status(502).body(Map.of("error", "Could not purge library data — try again"));
            }

            // Step 2: delete the Keycloak user. After this the access token
            // becomes orphaned and the next refresh will fail.
            adminDelete(keycloakUrl + "/admin/realms/" + realm + "/users/" + userId);

            // Step 3: clear cookies so the now-stale access token isn't reused.
            clearAuthCookies(response);
            return ResponseEntity.ok(Map.of("message", "Account deleted"));
        } catch (RestClientResponseException e) {
            log.error("Account delete Keycloak error for userId={}: status={} body={}",
                    userId, e.getStatusCode(), e.getResponseBodyAsString());
            return ResponseEntity.status(502).body(Map.of("error",
                    "Library data purged but Keycloak account remains. Contact support."));
        } catch (Exception e) {
            log.error("Account delete unexpected error for userId={}", userId, e);
            return ResponseEntity.status(500).body(Map.of("error", "Account deletion failed. Please try again."));
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

    private boolean isPasswordStrong(String password) {
        if (password == null || password.length() < 8) return false;
        boolean hasLetter = false;
        boolean hasDigit = false;
        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);
            if (Character.isLetter(c)) hasLetter = true;
            else if (Character.isDigit(c)) hasDigit = true;
            if (hasLetter && hasDigit) return true;
        }
        return false;
    }

    private boolean verifyPassword(String username, String password) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", clientId);
        form.add("scope", "openid");
        form.add("username", username);
        form.add("password", password);
        try {
            callKeycloak(form);
            return true;
        } catch (RestClientResponseException e) {
            return false;
        }
    }

    private String getAdminToken() {
        TokenWithExpiry cached = cachedAdminToken.get();
        long now = System.currentTimeMillis();
        if (cached != null && cached.expiresAtEpochMillis() - ADMIN_TOKEN_SAFETY_MARGIN_MS > now) {
            return cached.token();
        }
        return refreshAdminToken();
    }

    @SuppressWarnings("unchecked")
    private String refreshAdminToken() {
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
        String accessToken = (String) tokens.get("access_token");
        Object expiresInObj = tokens.get("expires_in");
        long expiresInSec = expiresInObj instanceof Number n ? n.longValue() : 60L;
        long expiresAt = System.currentTimeMillis() + expiresInSec * 1000L;
        cachedAdminToken.set(new TokenWithExpiry(accessToken, expiresAt));
        return accessToken;
    }

    /**
     * Run a single privileged Keycloak admin call. Retries once with a freshly-minted
     * admin token if Keycloak returns 401, so a rotated {@code gateway-admin} client
     * secret or a token revoked mid-cache is recovered transparently on the next call.
     */
    private void executeAdminCall(Consumer<String> action) {
        try {
            action.accept(getAdminToken());
        } catch (RestClientResponseException e) {
            if (e.getStatusCode().value() == 401) {
                cachedAdminToken.set(null);
                action.accept(refreshAdminToken());
                return;
            }
            throw e;
        }
    }

    private void adminPut(String uri, Object body) {
        executeAdminCall(adminToken -> restClient.put()
                .uri(uri)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .retrieve()
                .toBodilessEntity());
    }

    private void adminDelete(String uri) {
        executeAdminCall(adminToken -> restClient.delete()
                .uri(uri)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .retrieve()
                .toBodilessEntity());
    }

    private void createKeycloakUser(String username, String email, String password) {
        String usersUrl = keycloakUrl + "/admin/realms/" + realm + "/users";
        Map<String, Object> credential = Map.of("type", "password", "value", password, "temporary", false);
        Map<String, Object> user = new LinkedHashMap<>();
        user.put("username", username);
        user.put("email", email);
        user.put("enabled", true);
        user.put("emailVerified", true);
        user.put("requiredActions", List.of());
        user.put("credentials", List.of(credential));

        AtomicReference<URI> locationRef = new AtomicReference<>();
        executeAdminCall(adminToken -> {
            var createResponse = restClient.post()
                    .uri(usersUrl)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(user)
                    .retrieve()
                    .toBodilessEntity();
            locationRef.set(createResponse.getHeaders().getLocation());
        });

        URI location = locationRef.get();
        log.info("User created. Location header: {}", location);
        if (location != null) {
            String userId = location.getPath().substring(location.getPath().lastIndexOf('/') + 1);
            log.info("Clearing required actions for userId: {}", userId);
            Map<String, Object> patch = Map.of("requiredActions", List.of());
            adminPut(keycloakUrl + "/admin/realms/" + realm + "/users/" + userId, patch);
            log.info("Required actions cleared for userId: {}", userId);
        } else {
            log.warn("No Location header returned, cannot clear required actions");
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

    /**
     * Validate the token against the realm JWKS (signature, exp, nbf) and return
     * its claims. Empty map signals "untrusted or malformed token" so callers can
     * reject with 401 without distinguishing the specific failure mode.
     */
    private Map<String, Object> parseJwtPayload(String token) {
        if (token == null || token.isBlank()) {
            return Map.of();
        }
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getClaims();
        } catch (JwtException e) {
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
