package com.thegamecellar.apigateway.security;

import ch.qos.logback.classic.Level;
import com.thegamecellar.apigateway.support.GatewayTestBase;
import com.thegamecellar.apigateway.support.LogCapture;
import com.thegamecellar.apigateway.support.StubHttpServer;
import io.lettuce.core.RedisClient;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.testcontainers.containers.GenericContainer;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// The distributed path production runs: every bucket lives in Redis, so several gateway
// instances share one budget. Its own context, since the shared one keeps the limits in memory.
@TestPropertySource(properties = {
        "recommendation.ratelimit.distributed=true",
        // Short so the outage test is quick; production's is in application.yaml.
        "spring.data.redis.timeout=500ms",
        "RATE_LIMIT_LOGIN_REQUESTS=2",
        "RATE_LIMIT_LOGIN_WINDOW_SECONDS=3600",
        "RATE_LIMIT_ACCOUNT_ACTION_REQUESTS=2",
        "RATE_LIMIT_ACCOUNT_ACTION_WINDOW_SECONDS=3600",
        "RATE_LIMIT_RECOMMENDATIONS_REQUESTS=2",
        "RATE_LIMIT_RECOMMENDATIONS_WINDOW_SECONDS=3600",
        "RATE_LIMIT_EXPORT_REQUESTS=1",
        "RATE_LIMIT_EXPORT_WINDOW_SECONDS=3600",
})
class RedisRateLimitTest extends GatewayTestBase {

    // Started once and never stopped here: Testcontainers removes it at JVM exit.
    private static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);
    private static final RedisClient CLIENT;
    private static final StatefulRedisConnection<String, String> CONNECTION;

    static {
        REDIS.start();
        CLIENT = RedisClient.create("redis://" + REDIS.getHost() + ":" + REDIS.getMappedPort(6379));
        CONNECTION = CLIENT.connect();
    }

    @DynamicPropertySource
    static void redis(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
    }

    @AfterAll
    static void closeClient() {
        CONNECTION.close();
        CLIENT.shutdown();
    }

    private final RedisCommands<String, String> redis = CONNECTION.sync();

    @BeforeEach
    void emptyRedis() {
        redis.flushall();
    }

    @Test
    void theLoginBudgetIsKeptInRedisAndEnforcedFromThere() throws Exception {
        for (int i = 0; i < 2; i++) {
            mvc.perform(get("/api/v1/auth/authorize").with(r -> { r.setRemoteAddr("198.51.100.40"); return r; }))
                    .andExpect(status().isFound());
        }
        mvc.perform(get("/api/v1/auth/authorize").with(r -> { r.setRemoteAddr("198.51.100.40"); return r; }))
                .andExpect(status().isTooManyRequests());

        String key = "ratelimit:login:198.51.100.40";
        assertThat(redis.exists(key)).isEqualTo(1L);
        // Buckets expire on their own rather than piling up in Redis for every address ever seen.
        assertThat(redis.ttl(key)).isBetween(1L, 15 * 60L);

        // The state is in Redis and nowhere else: dropping the key there gives the budget back.
        redis.del(key);
        mvc.perform(get("/api/v1/auth/authorize").with(r -> { r.setRemoteAddr("198.51.100.40"); return r; }))
                .andExpect(status().isFound());
    }

    @Test
    void accountActionsRecommendationsAndExportsKeepPerUserBucketsInRedis() throws Exception {
        issue("alice-token", "alice");
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.StubResponse.json(200, "{\"access_token\":\"admin-token\",\"expires_in\":60}"));
        String userPath = "/admin/realms/" + REALM + "/users/alice";
        keycloak.on("GET", userPath, StubHttpServer.StubResponse.json(200, "{\"username\":\"alice\"}"));
        keycloak.on("GET", userPath + "/credentials", StubHttpServer.StubResponse.json(200, "[]"));
        keycloak.on("GET", userPath + "/sessions", StubHttpServer.StubResponse.json(200, "[]"));
        libraryService.on("GET", "/api/v1/library/account/export", StubHttpServer.StubResponse.json(200, "{}"));
        recommendationService.on("GET", "/api/v1/recommendations/account/export", StubHttpServer.StubResponse.json(200, "{}"));

        mvc.perform(get("/api/v1/auth/authorize").param("intent", "UPDATE_EMAIL").cookie(accessCookie("alice-token")))
                .andExpect(status().isFound());
        mvc.perform(get("/api/v1/recommendations/dashboard").cookie(accessCookie("alice-token")))
                .andExpect(status().isOk());
        mvc.perform(get("/api/v1/auth/account/export").cookie(accessCookie("alice-token")))
                .andExpect(status().isOk());
        mvc.perform(get("/api/v1/auth/account/export").cookie(accessCookie("alice-token")))
                .andExpect(status().isTooManyRequests());

        assertThat(redis.exists("ratelimit:account-action:user:alice", "ratelimit:rec:user:alice",
                "ratelimit:export:user:alice")).isEqualTo(3L);
    }

    // A Redis that hangs after startup costs each request the command timeout, then the limit is
    // counted in memory. Without the timeout every sign-in waited a minute and failed with a 500.
    @Test
    void aRedisThatHangsMidRunFallsBackToMemoryWithinTheCommandTimeout() throws Exception {
        issue("alice-token", "alice");
        REDIS.getDockerClient().pauseContainerCmd(REDIS.getContainerId()).exec();
        try (LogCapture logs = LogCapture.of(Class.forName("com.thegamecellar.apigateway.config.RateLimitBuckets"))) {
            assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
                for (int i = 0; i < 2; i++) {
                    mvc.perform(get("/api/v1/auth/authorize").with(r -> { r.setRemoteAddr("198.51.100.60"); return r; }))
                            .andExpect(status().isFound());
                }
                // The limit still holds while Redis is gone, from this instance's memory.
                mvc.perform(get("/api/v1/auth/authorize").with(r -> { r.setRemoteAddr("198.51.100.60"); return r; }))
                        .andExpect(status().isTooManyRequests());
                mvc.perform(get("/api/v1/recommendations/dashboard").cookie(accessCookie("alice-token")))
                        .andExpect(status().isOk());
            });

            assertThat(logs.messages(Level.WARN)).anySatisfy(message ->
                    assertThat(message).contains("Rate-limit store unreachable").doesNotContain("198.51.100.60"));
        } finally {
            REDIS.getDockerClient().unpauseContainerCmd(REDIS.getContainerId()).exec();
        }
    }
}
