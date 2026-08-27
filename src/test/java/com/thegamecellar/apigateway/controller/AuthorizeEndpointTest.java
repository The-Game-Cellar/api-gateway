package com.thegamecellar.apigateway.controller;

import com.thegamecellar.apigateway.support.GatewayTestBase;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AuthorizeEndpointTest extends GatewayTestBase {

    private static final String AUTH_ENDPOINT = KEYCLOAK_PUBLIC_URL + "/realms/" + REALM + "/protocol/openid-connect/auth";
    private static final String REGISTRATIONS_ENDPOINT = KEYCLOAK_PUBLIC_URL + "/realms/" + REALM + "/protocol/openid-connect/registrations";

    static MultiValueMap<String, String> query(MvcResult result) {
        String location = result.getResponse().getHeader("Location");
        return UriComponentsBuilder.fromUriString(location).build().getQueryParams();
    }

    static String withoutQuery(MvcResult result) {
        String location = result.getResponse().getHeader("Location");
        return location.substring(0, location.indexOf('?'));
    }

    @Test
    void loginRedirectsToKeycloakWithPkceAndStoresTheVerifierInTheSession() throws Exception {
        MvcResult result = mvc.perform(get("/api/v1/auth/authorize"))
                .andExpect(status().isFound())
                .andReturn();

        assertThat(withoutQuery(result)).isEqualTo(AUTH_ENDPOINT);
        MultiValueMap<String, String> q = query(result);
        assertThat(q.getFirst("client_id")).isEqualTo(CLIENT_ID);
        assertThat(q.getFirst("response_type")).isEqualTo("code");
        assertThat(q.getFirst("scope")).isEqualTo("openid");
        assertThat(q.getFirst("redirect_uri")).isEqualTo(REDIRECT_URI);
        assertThat(q.getFirst("code_challenge_method")).isEqualTo("S256");
        assertThat(q.getFirst("code_challenge")).hasSize(43);
        assertThat(q.getFirst("state")).isNotBlank();
        assertThat(q.getFirst("nonce")).isNotBlank();
        // A plain login must not force re-authentication or name a Keycloak action.
        assertThat(q.containsKey("prompt")).isFalse();
        assertThat(q.containsKey("max_age")).isFalse();
        assertThat(q.containsKey("kc_action")).isFalse();

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        assertThat(session).isNotNull();
        assertThat(session.getAttribute("oauth.state")).isEqualTo(q.getFirst("state"));
        assertThat(session.getAttribute("oidc.nonce")).isEqualTo(q.getFirst("nonce"));
        assertThat(session.getAttribute("pkce.code_verifier")).isNotNull();
        assertThat(session.getAttribute("auth.intent")).isEqualTo("LOGIN");
    }

    @Test
    void everyCallGetsFreshStateNonceAndChallenge() throws Exception {
        MultiValueMap<String, String> first = query(mvc.perform(get("/api/v1/auth/authorize")).andReturn());
        MultiValueMap<String, String> second = query(mvc.perform(get("/api/v1/auth/authorize")).andReturn());

        assertThat(first.getFirst("state")).isNotEqualTo(second.getFirst("state"));
        assertThat(first.getFirst("nonce")).isNotEqualTo(second.getFirst("nonce"));
        assertThat(first.getFirst("code_challenge")).isNotEqualTo(second.getFirst("code_challenge"));
    }

    @Test
    void registerOpensTheSignUpFormOnTheSameFlow() throws Exception {
        MvcResult result = mvc.perform(get("/api/v1/auth/authorize").param("register", "true"))
                .andExpect(status().isFound())
                .andReturn();

        assertThat(withoutQuery(result)).isEqualTo(REGISTRATIONS_ENDPOINT);
        assertThat(query(result).getFirst("code_challenge_method")).isEqualTo("S256");
    }

    @Test
    void passwordAndEmailIntentsForceReauthenticationAndNameTheKeycloakAction() throws Exception {
        issue("alice-token", "alice");

        MvcResult password = mvc.perform(get("/api/v1/auth/authorize").param("intent", "UPDATE_PASSWORD"))
                .andReturn();
        MultiValueMap<String, String> pq = query(password);
        assertThat(pq.getFirst("prompt")).isEqualTo("login");
        assertThat(pq.getFirst("max_age")).isEqualTo("0");
        assertThat(pq.getFirst("kc_action")).isEqualTo("UPDATE_PASSWORD");

        MvcResult email = mvc.perform(get("/api/v1/auth/authorize").param("intent", "update_email")
                        .cookie(accessCookie("alice-token")))
                .andReturn();
        MultiValueMap<String, String> eq = query(email);
        assertThat(eq.getFirst("kc_action")).isEqualTo("UPDATE_EMAIL");
        // The address before the round trip is what tells "changed" from "pending" afterwards.
        MockHttpSession session = (MockHttpSession) email.getRequest().getSession(false);
        assertThat(session.getAttribute("auth.email_before")).isEqualTo("alice@example.test");
    }

    @Test
    void deleteIntentForcesReauthenticationWithoutAKeycloakAction() throws Exception {
        MvcResult result = mvc.perform(get("/api/v1/auth/authorize").param("intent", "DELETE_ACCOUNT"))
                .andReturn();

        MultiValueMap<String, String> q = query(result);
        assertThat(q.getFirst("prompt")).isEqualTo("login");
        assertThat(q.getFirst("max_age")).isEqualTo("0");
        assertThat(q.containsKey("kc_action")).isFalse();
    }

    // An intent nobody defined must not become a privilege: it degrades to a plain login.
    @Test
    void unknownIntentIsAPlainLogin() throws Exception {
        MvcResult result = mvc.perform(get("/api/v1/auth/authorize").param("intent", "BECOME_ADMIN"))
                .andReturn();

        MultiValueMap<String, String> q = query(result);
        assertThat(q.containsKey("prompt")).isFalse();
        assertThat(q.containsKey("kc_action")).isFalse();
        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        assertThat(session.getAttribute("auth.intent")).isEqualTo("LOGIN");
    }
}
