package com.thegamecellar.apigateway.controller;

import jakarta.servlet.http.Cookie;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
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

    // Browser-facing Keycloak origin. Differs from KEYCLOAK_AUTH_SERVER_URL in production,
    // where the gateway reaches Keycloak on the compose network but the user's browser cannot.
    @Value("${KEYCLOAK_PUBLIC_URL:${KEYCLOAK_AUTH_SERVER_URL:http://localhost:8080}}")
    private String keycloakPublicUrl;

    // Must match a Valid Redirect URI on the realm client byte for byte, or Keycloak
    // refuses the authorization request.
    @Value("${AUTH_REDIRECT_URI:http://localhost:8000/api/v1/auth/callback}")
    private String authRedirectUri;

    @Value("${APP_BASE_URL:http://localhost:5173}")
    private String appBaseUrl;

    private static final long ADMIN_TOKEN_SAFETY_MARGIN_MS = 5_000L;
    private final AtomicReference<TokenWithExpiry> cachedAdminToken = new AtomicReference<>();

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String SESSION_CODE_VERIFIER = "pkce.code_verifier";
    private static final String SESSION_STATE = "oauth.state";
    private static final String SESSION_NONCE = "oidc.nonce";

    private record TokenWithExpiry(String token, long expiresAtEpochMillis) {}

    @GetMapping("/authorize")
    public ResponseEntity<Void> authorize(
            @RequestParam(name = "register", defaultValue = "false") boolean register,
            HttpServletRequest request) {
        String codeVerifier = randomToken(32);
        String state = randomToken(32);
        String nonce = randomToken(32);

        HttpSession session = request.getSession(true);
        session.setAttribute(SESSION_CODE_VERIFIER, codeVerifier);
        session.setAttribute(SESSION_STATE, state);
        session.setAttribute(SESSION_NONCE, nonce);

        // Same flow either way; the registrations endpoint just opens Keycloak's
        // sign-up form first and returns the browser to this callback afterwards.
        String endpoint = register ? "/registrations" : "/auth";
        String authorizeUrl = UriComponentsBuilder
                .fromUriString(keycloakPublicUrl + "/realms/" + realm + "/protocol/openid-connect" + endpoint)
                .queryParam("client_id", clientId)
                .queryParam("response_type", "code")
                .queryParam("scope", "openid")
                .queryParam("redirect_uri", authRedirectUri)
                .queryParam("state", state)
                .queryParam("nonce", nonce)
                .queryParam("code_challenge", codeChallenge(codeVerifier))
                .queryParam("code_challenge_method", "S256")
                .encode()
                .toUriString();

        return redirect(authorizeUrl);
    }

    @GetMapping("/callback")
    public ResponseEntity<Void> callback(@RequestParam(required = false) String code,
                                         @RequestParam(required = false) String state,
                                         @RequestParam(required = false) String error,
                                         HttpServletRequest request,
                                         HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        String expectedState = sessionAttribute(session, SESSION_STATE);
        String codeVerifier = sessionAttribute(session, SESSION_CODE_VERIFIER);
        String expectedNonce = sessionAttribute(session, SESSION_NONCE);
        // Single use: a replayed code must not find a verifier waiting for it.
        if (session != null) {
            session.invalidate();
        }

        if (error != null) {
            log.warn("Authorization callback returned error: {}", error);
            return redirect(appBaseUrl + "/login?error=auth_failed");
        }
        if (code == null || state == null || expectedState == null || codeVerifier == null
                || !constantTimeEquals(state, expectedState)) {
            log.warn("Authorization callback rejected: missing code or state mismatch");
            return redirect(appBaseUrl + "/login?error=auth_failed");
        }

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("client_id", clientId);
        form.add("code", code);
        form.add("redirect_uri", authRedirectUri);
        form.add("code_verifier", codeVerifier);

        try {
            Map<?, ?> tokens = callKeycloak(form);
            Map<?, ?> idClaims = parseJwtPayload((String) tokens.get("id_token"));
            if (expectedNonce == null || !expectedNonce.equals(idClaims.get("nonce"))) {
                log.warn("Authorization callback rejected: id_token nonce mismatch");
                return redirect(appBaseUrl + "/login?error=auth_failed");
            }
            setAuthCookies(response, tokens);
            return redirect(appBaseUrl + "/dashboard");
        } catch (RestClientResponseException e) {
            log.error("Code exchange failed: status={}", e.getStatusCode());
            return redirect(appBaseUrl + "/login?error=auth_failed");
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
                // Best-effort revoke; cookies cleared regardless.
            }
        }
        clearAuthCookies(response);
        return ResponseEntity.ok(Map.of("message", "Logged out"));
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
            log.error("Change password Keycloak error: status={}", e.getStatusCode());
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
            // Purge library first so a failure leaves the Keycloak account intact and retryable.
            try {
                restClient.delete()
                        .uri(libraryServiceUrl + "/api/v1/library/account")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                        .retrieve()
                        .toBodilessEntity();
            } catch (RestClientResponseException e) {
                log.error("Account delete: library purge failed for userId={}: status={} body={}",
                        userId, e.getStatusCode(), e.getResponseBodyAsString());
                return ResponseEntity.status(502).body(Map.of("error", "Could not purge library data, try again"));
            }

            adminDelete(keycloakUrl + "/admin/realms/" + realm + "/users/" + userId);
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

    private static ResponseEntity<Void> redirect(String url) {
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(url)).build();
    }

    private static String sessionAttribute(HttpSession session, String name) {
        if (session == null) return null;
        Object value = session.getAttribute(name);
        return value instanceof String s ? s : null;
    }

    private static String randomToken(int byteCount) {
        byte[] buffer = new byte[byteCount];
        SECURE_RANDOM.nextBytes(buffer);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buffer);
    }

    private static String codeChallenge(String codeVerifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required for PKCE", e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
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

    // Retry once on 401 so a rotated gateway-admin secret or revoked cached token recovers transparently.
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

    // Empty map = untrusted or malformed; callers reject with 401 without distinguishing the cause.
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
