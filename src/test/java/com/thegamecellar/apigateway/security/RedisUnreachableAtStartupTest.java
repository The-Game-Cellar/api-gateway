package com.thegamecellar.apigateway.security;

import com.thegamecellar.apigateway.support.GatewayTestBase;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// Distributed limiting switched on with no Redis to reach when the gateway starts: it must still
// start, and the limits must still hold, from memory.
@TestPropertySource(properties = {
        "recommendation.ratelimit.distributed=true",
        "RATE_LIMIT_LOGIN_REQUESTS=2",
        "RATE_LIMIT_LOGIN_WINDOW_SECONDS=3600",
})
class RedisUnreachableAtStartupTest extends GatewayTestBase {

    @DynamicPropertySource
    static void redisNobodyListensOn(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", () -> "127.0.0.1");
        registry.add("spring.data.redis.port", RedisUnreachableAtStartupTest::closedPort);
    }

    private static int closedPort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Autowired
    private ApplicationContext context;

    @Test
    void theGatewayStartsWithoutABucketStoreAndLimitsFromMemory() throws Exception {
        Object proxyManager = context.getBeanProvider(ResolvableType.forClassWithGenerics(ProxyManager.class, String.class))
                .getIfAvailable();
        assertThat(proxyManager).isNull();

        for (int i = 0; i < 2; i++) {
            mvc.perform(get("/api/v1/auth/authorize").with(r -> { r.setRemoteAddr("198.51.100.50"); return r; }))
                    .andExpect(status().isFound());
        }
        mvc.perform(get("/api/v1/auth/authorize").with(r -> { r.setRemoteAddr("198.51.100.50"); return r; }))
                .andExpect(status().isTooManyRequests());
    }
}
