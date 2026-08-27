package com.thegamecellar.apigateway.controller;

import com.thegamecellar.apigateway.client.AccountDeletionLedgerClient;
import com.thegamecellar.apigateway.client.KeycloakAdminClient;
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
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final RestClient restClient = RestClient.create();
    private final JwtDecoder jwtDecoder;
    private final KeycloakAdminClient keycloakAdmin;
    private final AccountDeletionLedgerClient deletionLedger;

    public AuthController(JwtDecoder jwtDecoder,
                          KeycloakAdminClient keycloakAdmin,
                          AccountDeletionLedgerClient deletionLedger) {
        this.jwtDecoder = jwtDecoder;
        this.keycloakAdmin = keycloakAdmin;
        this.deletionLedger = deletionLedger;
    }

    @Value("${KEYCLOAK_AUTH_SERVER_URL:http://localhost:8080}")
    private String keycloakUrl;

    @Value("${KEYCLOAK_REALM:game-cellar}")
    private String realm;

    @Value("${KEYCLOAK_CLIENT_ID:game-cellar-client}")
    private String clientId;

    @Value("${COOKIE_SECURE:false}")
    private boolean cookieSecure;

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

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String SESSION_CODE_VERIFIER = "pkce.code_verifier";
    private static final String SESSION_STATE = "oauth.state";
    private static final String SESSION_NONCE = "oidc.nonce";
    private static final String SESSION_INTENT = "auth.intent";
    private static final String SESSION_INTENT_REQUESTED_AT = "auth.intent_requested_at";
    private static final String SESSION_EMAIL_BEFORE = "auth.email_before";

    // How recently the user must have authenticated for a destructive action to be allowed.
    // Read from auth_time, which survives token refresh, so this is time since the password
    // was last entered rather than time since the last token was issued.
    private static final long REAUTH_WINDOW_MS = 5 * 60 * 1000L;
    private static final long AUTH_TIME_SKEW_MS = 30_000L;

    /**
     * What the browser left for, remembered across the redirect. Everything but LOGIN forces a
     * fresh authentication; the two with a Keycloak action name let Keycloak own the form.
     */
    private enum AuthIntent {
        LOGIN(null, null),
        UPDATE_PASSWORD("UPDATE_PASSWORD", "password"),
        UPDATE_EMAIL("UPDATE_EMAIL", "email"),
        DELETE_ACCOUNT(null, "delete");

        private final String keycloakAction;
        private final String landingAction;

        AuthIntent(String keycloakAction, String landingAction) {
            this.keycloakAction = keycloakAction;
            this.landingAction = landingAction;
        }

        // Anything unrecognised is a plain login, which grants nothing the caller did not already have.
        static AuthIntent from(String raw) {
            if (raw == null) return LOGIN;
            for (AuthIntent intent : values()) {
                if (intent.name().equalsIgnoreCase(raw)) return intent;
            }
            return LOGIN;
        }
    }

    @GetMapping("/authorize")
    public ResponseEntity<Void> authorize(
            @RequestParam(name = "register", defaultValue = "false") boolean register,
            @RequestParam(name = "intent", required = false) String intentParam,
            HttpServletRequest request) {
        AuthIntent intent = AuthIntent.from(intentParam);
        String codeVerifier = randomToken(32);
        String state = randomToken(32);
        String nonce = randomToken(32);

        HttpSession session = request.getSession(true);
        session.setAttribute(SESSION_CODE_VERIFIER, codeVerifier);
        session.setAttribute(SESSION_STATE, state);
        session.setAttribute(SESSION_NONCE, nonce);
        session.setAttribute(SESSION_INTENT, intent.name());
        session.setAttribute(SESSION_INTENT_REQUESTED_AT, System.currentTimeMillis());
        if (intent == AuthIntent.UPDATE_EMAIL) {
            // Keycloak reports the same success whether it wrote the address or mailed a
            // confirmation for it, so the only way to tell is to compare before and after.
            String currentEmail = (String) parseJwtPayload(readCookie(request, "access_token")).get("email");
            if (currentEmail != null) {
                session.setAttribute(SESSION_EMAIL_BEFORE, currentEmail);
            }
        }

        // Same flow either way; the registrations endpoint just opens Keycloak's
        // sign-up form first and returns the browser to this callback afterwards.
        String endpoint = register ? "/registrations" : "/auth";
        UriComponentsBuilder authorizeUrl = UriComponentsBuilder
                .fromUriString(keycloakPublicUrl + "/realms/" + realm + "/protocol/openid-connect" + endpoint)
                .queryParam("client_id", clientId)
                .queryParam("response_type", "code")
                .queryParam("scope", "openid")
                .queryParam("redirect_uri", authRedirectUri)
                .queryParam("state", state)
                .queryParam("nonce", nonce)
                .queryParam("code_challenge", codeChallenge(codeVerifier))
                .queryParam("code_challenge_method", "S256");

        if (intent != AuthIntent.LOGIN) {
            // Keycloak's own update forms never ask for the current password, and deletion is
            // confirmed after the return, so nothing else forces the user to prove who they are.
            // max_age is what makes auth_time mandatory in the id_token; prompt leaves it optional.
            authorizeUrl.queryParam("prompt", "login").queryParam("max_age", 0);
            if (intent.keycloakAction != null) {
                authorizeUrl.queryParam("kc_action", intent.keycloakAction);
            }
        }

        return redirect(authorizeUrl.encode().toUriString());
    }

    @GetMapping("/callback")
    public ResponseEntity<Void> callback(@RequestParam(required = false) String code,
                                         @RequestParam(required = false) String state,
                                         @RequestParam(required = false) String error,
                                         @RequestParam(name = "kc_action_status", required = false) String kcActionStatus,
                                         HttpServletRequest request,
                                         HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        String expectedState = sessionAttribute(session, SESSION_STATE);
        String codeVerifier = sessionAttribute(session, SESSION_CODE_VERIFIER);
        String expectedNonce = sessionAttribute(session, SESSION_NONCE);
        AuthIntent intent = AuthIntent.from(sessionAttribute(session, SESSION_INTENT));
        long requestedAt = sessionLong(session, SESSION_INTENT_REQUESTED_AT);
        String emailBefore = sessionAttribute(session, SESSION_EMAIL_BEFORE);
        // Single use: a replayed code must not find a verifier waiting for it.
        if (session != null) {
            session.invalidate();
        }

        if (error != null) {
            log.warn("Authorization callback returned error: {}", error);
            return redirect(failureLanding(intent));
        }
        // Keycloak ends the email-confirmation branch on its own page rather than returning a
        // code, and applies the change later when the mailed link is followed. The browser then
        // arrives here with nothing to exchange. Whoever already holds a refresh cookie is
        // signed in, so telling them their sign-in failed would be wrong whatever the session
        // still remembers. Anything carrying a code goes through the state check below.
        if (code == null && state == null && readCookie(request, "refresh_token") != null) {
            return completeOutOfBandReturn(intent, emailBefore, request, response);
        }

        if (code == null || state == null || expectedState == null || codeVerifier == null
                || !constantTimeEquals(state, expectedState)) {
            log.warn("Authorization callback rejected: missing code or state mismatch");
            return redirect(failureLanding(intent));
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
                return redirect(failureLanding(intent));
            }
            setAuthCookies(response, tokens);

            if (intent == AuthIntent.LOGIN) {
                return redirect(appBaseUrl + "/dashboard");
            }

            boolean fresh = isFreshAuthentication(idClaims, requestedAt);
            if (intent == AuthIntent.DELETE_ACCOUNT) {
                if (!fresh) {
                    log.warn("Re-authentication before account deletion rejected: auth_time is stale or absent");
                    return redirect(actionLanding(intent, "reauth_failed"));
                }
                // Nothing is recorded server-side: the cookies just set carry auth_time, and
                // the delete endpoint reads its proof from there. A servlet session does not
                // reliably survive this round trip, and a lost one would refuse a user who
                // has just proved who they are.
                return redirect(actionLanding(intent, "ready"));
            }

            if (!fresh) {
                // The action has already run, so refusing here would be theatre. A stale auth_time
                // means prompt=login did not take effect and the realm needs looking at.
                log.warn("Action {} completed without a fresh authentication", intent);
            }

            String status = kcActionStatus != null ? kcActionStatus : "unknown";
            if (intent == AuthIntent.UPDATE_EMAIL && "success".equals(status)) {
                String emailAfter = (String) parseJwtPayload((String) tokens.get("access_token")).get("email");
                status = emailBefore != null && emailBefore.equals(emailAfter) ? "pending" : "changed";
            }
            return redirect(actionLanding(intent, status));
        } catch (RestClientResponseException e) {
            log.error("Code exchange failed: status={}", e.getStatusCode());
            return redirect(failureLanding(intent));
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

    @DeleteMapping("/account")
    public ResponseEntity<?> deleteAccount(HttpServletRequest request,
                                            HttpServletResponse response) {
        String accessToken = readCookie(request, "access_token");
        if (accessToken == null || accessToken.isBlank()) {
            return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        }
        Map<?, ?> claims = parseJwtPayload(accessToken);
        String userId = (String) claims.get("sub");
        if (userId == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid token"));
        }

        if (!isFreshAuthentication(claims, System.currentTimeMillis() - REAUTH_WINDOW_MS)) {
            return ResponseEntity.status(403).body(Map.of("error", "Re-authentication required"));
        }

        // Identity is shut before anything is destroyed: once the library is gone the user must
        // not be able to sign in again, whatever happens to the rest of this method. A refusal
        // here also proves the admin credentials work before they are needed for the delete.
        try {
            keycloakAdmin.setEnabled(userId, false);
        } catch (RestClientException e) {
            log.error("Account delete: could not disable Keycloak user userId={}: {}", userId, describe(e));
            return ResponseEntity.status(502).body(Map.of("error",
                    "Could not reach the identity provider. Nothing was deleted, try again."));
        }
        try {
            keycloakAdmin.logout(userId);
        } catch (RestClientException e) {
            // A disabled user cannot refresh, so a failed logout only leaves an SSO cookie that opens nothing.
            log.warn("Account delete: could not end sessions for userId={}: {}", userId, describe(e));
        }

        try {
            restClient.delete()
                    .uri(libraryServiceUrl + "/api/v1/library/account")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .retrieve()
                    .toBodilessEntity();
        } catch (RestClientException e) {
            log.error("Account delete: library purge failed for userId={}: {}", userId, describe(e));
            reEnable(userId);
            return ResponseEntity.status(502).body(Map.of("error", "Could not purge library data, try again"));
        }

        // The purge wrote the ledger row, so from here every failure is finished by the retry job.
        boolean identityGone = false;
        try {
            keycloakAdmin.delete(userId);
            identityGone = true;
        } catch (RestClientException e) {
            log.warn("Account delete: identity delete failed for userId={}, left to the retry job: {}",
                    userId, describe(e));
        }
        if (identityGone) {
            try {
                deletionLedger.complete(userId);
            } catch (RestClientException e) {
                log.warn("Account delete: ledger not closed for userId={}, the retry job will confirm: {}",
                        userId, describe(e));
            }
        }
        clearAuthCookies(response);
        return identityGone
                ? ResponseEntity.ok(Map.of("message", "Account deleted"))
                : ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of("message",
                        "Account deletion accepted and will finish shortly"));
    }

    private void reEnable(String userId) {
        try {
            keycloakAdmin.setEnabled(userId, true);
        } catch (RestClientException e) {
            log.error("Account delete: userId={} left disabled with its library intact after a failed purge; re-enable by hand",
                    userId, e);
        }
    }

    private static String describe(RestClientException e) {
        if (e instanceof RestClientResponseException r) {
            return "status=" + r.getStatusCode() + " body=" + r.getResponseBodyAsString();
        }
        return e.getClass().getSimpleName() + ": " + e.getMessage();
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

    private static long sessionLong(HttpSession session, String name) {
        if (session == null) return 0L;
        Object value = session.getAttribute(name);
        return value instanceof Number n ? n.longValue() : 0L;
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

    // The cookies still describe the user as they were before leaving, so they are refreshed
    // here: without that, Profile would show the old address until the access token expires.
    private ResponseEntity<Void> completeOutOfBandReturn(AuthIntent intent, String emailBefore,
                                                         HttpServletRequest request,
                                                         HttpServletResponse response) {
        String refreshToken = readCookie(request, "refresh_token");
        if (refreshToken == null || refreshToken.isBlank()) {
            return redirect(appBaseUrl + "/dashboard");
        }
        try {
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("grant_type", "refresh_token");
            form.add("client_id", clientId);
            form.add("refresh_token", refreshToken);
            Map<?, ?> tokens = callKeycloak(form);
            setAuthCookies(response, tokens);

            if (intent == AuthIntent.UPDATE_EMAIL) {
                String emailAfter = (String) parseJwtPayload((String) tokens.get("access_token")).get("email");
                if (emailBefore != null && !emailBefore.equals(emailAfter)) {
                    return redirect(actionLanding(intent, "changed"));
                }
                // The address before the redirect is read from the access-token cookie, which
                // may have expired while the user was on Keycloak's pages. Land on the account
                // page anyway, where the refreshed token shows what the address actually is.
                log.debug("Out-of-band email return without a usable before-and-after comparison");
                return redirect(appBaseUrl + "/profile");
            }
            return redirect(appBaseUrl + "/dashboard");
        } catch (RestClientResponseException e) {
            log.warn("Out-of-band return could not refresh tokens: status={}", e.getStatusCode());
            return redirect(appBaseUrl + "/dashboard");
        }
    }

    private String failureLanding(AuthIntent intent) {
        return intent == AuthIntent.LOGIN
                ? appBaseUrl + "/login?error=auth_failed"
                : actionLanding(intent, "error");
    }

    private String actionLanding(AuthIntent intent, String status) {
        return UriComponentsBuilder.fromUriString(appBaseUrl + "/profile")
                .queryParam("action", intent.landingAction)
                .queryParam("status", status)
                .encode()
                .toUriString();
    }

    private static boolean isFreshAuthentication(Map<?, ?> claims, long notBeforeMillis) {
        Object authTime = claims.get("auth_time");
        long authTimeMillis;
        if (authTime instanceof Number seconds) {
            authTimeMillis = seconds.longValue() * 1000L;
        } else if (authTime instanceof Instant instant) {
            authTimeMillis = instant.toEpochMilli();
        } else {
            // Absent means the authorization server ignored max_age; treat that as not proven.
            return false;
        }
        return authTimeMillis >= notBeforeMillis - AUTH_TIME_SKEW_MS;
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
