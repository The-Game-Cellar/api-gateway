package com.thegamecellar.apigateway.security;

import com.thegamecellar.apigateway.support.GatewayTestBase;
import org.junit.jupiter.api.Test;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class CorsTest extends GatewayTestBase {

    @Test
    void preflightFromTheConfiguredOriginIsAllowedWithCredentials() throws Exception {
        mvc.perform(options("/api/v1/library/games")
                        .header("Origin", APP_URL)
                        .header("Access-Control-Request-Method", "POST")
                        .header("Access-Control-Request-Headers", "Content-Type"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", APP_URL))
                .andExpect(header().string("Access-Control-Allow-Credentials", "true"))
                .andExpect(header().string("Access-Control-Allow-Methods", org.hamcrest.Matchers.containsString("POST")));
    }

    @Test
    void preflightFromAnyOtherOriginIsRefused() throws Exception {
        mvc.perform(options("/api/v1/library/games")
                        .header("Origin", "http://evil.test")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }

    @Test
    void actualRequestFromTheConfiguredOriginCarriesTheAllowHeader() throws Exception {
        issue("alice-token", "alice");

        mvc.perform(get("/api/v1/library/games")
                        .header("Origin", APP_URL)
                        .cookie(accessCookie("alice-token")))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", APP_URL));
    }
}
