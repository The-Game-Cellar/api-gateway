package com.thegamecellar.apigateway.support;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

// Tokens as Keycloak signs them, verified by the gateway's real decoder against the JWKS the
// Keycloak stub serves. Tests refer to a token by name; the name resolves to the signed value,
// and a name nobody issued stays as it is, which is what a forged or garbled token looks like.
public final class TestTokens {

    public static final String REALM = "game-cellar";
    public static final String CLIENT_ID = "game-cellar-client";
    public static final String ISSUER = "http://auth.test/realms/" + REALM;
    public static final String JWKS_PATH = "/realms/" + REALM + "/protocol/openid-connect/certs";

    private static final RSAKey REALM_KEY = generate("realm-key");
    // Never published. Same key id as the realm key, so only the signature tells them apart.
    private static final RSAKey FOREIGN_KEY = generate("realm-key");

    private static final Map<String, String> ISSUED = new ConcurrentHashMap<>();

    private TestTokens() {}

    public static String jwksJson() {
        return new JWKSet(REALM_KEY.toPublicJWK()).toString();
    }

    public static void forgetAll() {
        ISSUED.clear();
    }

    public static String resolve(String name) {
        return ISSUED.getOrDefault(name, name);
    }

    // The claims Keycloak puts on every token for this client, plus whatever the test adds.
    public static String issue(String name, String subject, Map<String, Object> extraClaims) {
        return sign(name, claims -> {
            claims.subject(subject)
                    .claim("azp", CLIENT_ID)
                    .claim("email", subject + "@example.test")
                    .claim("preferred_username", subject);
            extraClaims.forEach(claims::claim);
        });
    }

    // Issuer and timestamps only, for the cases where a claim being absent is the point.
    public static String issueBare(String name, String subject, Map<String, Object> claims) {
        return sign(name, builder -> {
            if (subject != null) builder.subject(subject);
            claims.forEach(builder::claim);
        });
    }

    // A valid token for this client with the claim set changed afterwards, signed by the realm key.
    public static String sign(String name, Consumer<JWTClaimsSet.Builder> customise) {
        return register(name, signWith(REALM_KEY, base(customise)));
    }

    // Everything right except the key: what a token minted anywhere but the realm looks like.
    public static String signWithForeignKey(String name, String subject) {
        return register(name, signWith(FOREIGN_KEY, base(claims -> claims.subject(subject)
                .claim("azp", CLIENT_ID))));
    }

    // alg "none": a token that claims everything and proves nothing.
    public static String unsigned(String name, String subject) {
        return register(name, new PlainJWT(base(claims -> claims.subject(subject).claim("azp", CLIENT_ID))).serialize());
    }

    private static JWTClaimsSet base(Consumer<JWTClaimsSet.Builder> customise) {
        Instant now = Instant.now();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)));
        customise.accept(claims);
        return claims.build();
    }

    private static String signWith(RSAKey key, JWTClaimsSet claims) {
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(key.getKeyID())
                    .type(JOSEObjectType.JWT)
                    .build(), claims);
            jwt.sign(new RSASSASigner(key));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Could not sign a test token", e);
        }
    }

    private static String register(String name, String token) {
        ISSUED.put(name, token);
        return token;
    }

    private static RSAKey generate(String keyId) {
        try {
            return new RSAKeyGenerator(2048).keyID(keyId).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException("Could not generate a test key", e);
        }
    }
}
