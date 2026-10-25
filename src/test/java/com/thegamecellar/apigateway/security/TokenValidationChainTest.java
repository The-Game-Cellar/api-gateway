package com.thegamecellar.apigateway.security;

import com.thegamecellar.apigateway.support.GatewayTestBase;
import com.thegamecellar.apigateway.support.TestTokens;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// The decoder the gateway runs in production, against the key the realm publishes: every check
// a token has to pass runs in the filter chain, before anything reaches a service. Each refusal
// is tried both ways a token arrives, as a bearer header and as the access cookie.
class TokenValidationChainTest extends GatewayTestBase {

    private static final String PROTECTED = "/api/v1/library/games";

    private void accepted(String tokenValue) throws Exception {
        mvc.perform(get(PROTECTED).header("Authorization", "Bearer " + tokenValue))
                .andExpect(status().isOk());
        mvc.perform(get(PROTECTED).cookie(new Cookie("access_token", tokenValue)))
                .andExpect(status().isOk());
    }

    private void refused(String tokenValue) throws Exception {
        mvc.perform(get(PROTECTED).header("Authorization", "Bearer " + tokenValue))
                .andExpect(status().isUnauthorized());
        mvc.perform(get(PROTECTED).cookie(new Cookie("access_token", tokenValue)))
                .andExpect(status().isUnauthorized());
        assertThat(libraryService.recorded()).isEmpty();
    }

    private static Date secondsFromNow(long seconds) {
        return Date.from(Instant.now().plusSeconds(seconds));
    }

    @Test
    void aTokenTheRealmSignedForThisClientIsAccepted() throws Exception {
        accepted(issue("good", "alice"));
    }

    @Test
    void anExpiredTokenIsRefusedBeyondTheClockSkew() throws Exception {
        refused(TestTokens.sign("long-expired", claims -> claims.subject("alice").claim("azp", CLIENT_ID)
                .issueTime(secondsFromNow(-600)).expirationTime(secondsFromNow(-120))));
    }

    // Keycloak and the gateway run on different clocks, so a token a few seconds past its expiry
    // still passes: the default skew is sixty seconds.
    @Test
    void aTokenJustPastItsExpiryIsAcceptedWithinTheClockSkew() throws Exception {
        accepted(TestTokens.sign("just-expired", claims -> claims.subject("alice").claim("azp", CLIENT_ID)
                .issueTime(secondsFromNow(-300)).expirationTime(secondsFromNow(-10))));
    }

    @Test
    void aTokenNotYetValidIsRefused() throws Exception {
        refused(TestTokens.sign("future", claims -> claims.subject("alice").claim("azp", CLIENT_ID)
                .notBeforeTime(secondsFromNow(600))));
    }

    @Test
    void aTokenFromAnotherRealmIsRefused() throws Exception {
        refused(TestTokens.sign("master", claims -> claims.subject("alice").claim("azp", CLIENT_ID)
                .issuer("http://auth.test/realms/master")));
    }

    // Keycloak stamps every realm token with aud "account", so the client check reads azp.
    @Test
    void aTokenIssuedToAnotherClientOrToNoneIsRefused() throws Exception {
        refused(TestTokens.sign("admin-cli", claims -> claims.subject("alice").claim("azp", "admin-cli")));
        refused(TestTokens.sign("no-azp", claims -> claims.subject("alice")));
    }

    @Test
    void aTokenSignedWithAnyOtherKeyIsRefused() throws Exception {
        refused(TestTokens.signWithForeignKey("foreign", "alice"));
    }

    @Test
    void anUnsignedTokenIsRefused() throws Exception {
        refused(TestTokens.unsigned("none", "alice"));
    }

    // A genuine signature over a payload that was changed afterwards: the subject is swapped
    // for another user's.
    @Test
    void aTokenWhosePayloadWasChangedAfterSigningIsRefused() throws Exception {
        String[] parts = issue("genuine", "alice").split("\\.");
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        String swapped = payload.replace("\"sub\":\"alice\"", "\"sub\":\"bob\"");
        assertThat(swapped).isNotEqualTo(payload);

        refused(parts[0] + "." + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(swapped.getBytes(StandardCharsets.UTF_8)) + "." + parts[2]);
    }
}
