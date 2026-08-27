package com.thegamecellar.apigateway.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

// The checks a token has to pass after its signature is verified. Signature and JWKS
// handling belong to Nimbus and are not re-tested here.
class TokenValidatorTest {

    private static final String ISSUER = "https://auth.gamecellar.app/realms/game-cellar";
    private static final String CLIENT = "game-cellar-client";

    private final OAuth2TokenValidator<Jwt> validator = SecurityConfig.tokenValidator(ISSUER, CLIENT);

    private static Jwt token(Consumer<Jwt.Builder> customise) {
        Instant now = Instant.now();
        Jwt.Builder builder = Jwt.withTokenValue("t")
                .header("alg", "RS256")
                .subject("alice")
                .issuer(ISSUER)
                .issuedAt(now.minusSeconds(10))
                .expiresAt(now.plusSeconds(300))
                .claim("azp", CLIENT);
        customise.accept(builder);
        return builder.build();
    }

    @Test
    void aTokenFromOurRealmForOurClientPasses() {
        OAuth2TokenValidatorResult result = validator.validate(token(b -> {}));

        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void anotherIssuerIsRejected() {
        OAuth2TokenValidatorResult result = validator.validate(
                token(b -> b.issuer("https://auth.gamecellar.app/realms/master")));

        assertThat(result.hasErrors()).isTrue();
    }

    // Keycloak stamps every realm token with aud "account", so the client check has to
    // read azp. A token minted for a different client in the same realm must not pass.
    @Test
    void aTokenIssuedToAnotherClientIsRejected() {
        assertThat(validator.validate(token(b -> b.claim("azp", "admin-cli"))).hasErrors()).isTrue();
        assertThat(validator.validate(token(b -> b.claims(c -> c.remove("azp")))).hasErrors()).isTrue();
    }

    @Test
    void anExpiredTokenIsRejectedBeyondTheClockSkew() {
        Instant now = Instant.now();
        OAuth2TokenValidatorResult longExpired = validator.validate(
                token(b -> b.issuedAt(now.minusSeconds(600)).expiresAt(now.minusSeconds(120))));
        OAuth2TokenValidatorResult justExpired = validator.validate(
                token(b -> b.issuedAt(now.minusSeconds(300)).expiresAt(now.minusSeconds(10))));

        assertThat(longExpired.hasErrors()).isTrue();
        // Within the default 60 second skew, so still accepted.
        assertThat(justExpired.hasErrors()).isFalse();
    }

    @Test
    void aTokenNotYetValidIsRejected() {
        Instant now = Instant.now();
        OAuth2TokenValidatorResult result = validator.validate(
                token(b -> b.notBefore(now.plusSeconds(600))));

        assertThat(result.hasErrors()).isTrue();
    }
}
