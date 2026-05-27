package com.thegamecellar.apigateway.config;

import io.github.bucket4j.distributed.ExpirationAfterWriteStrategy;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.codec.ByteArrayCodec;
import io.lettuce.core.codec.RedisCodec;
import io.lettuce.core.codec.StringCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.Nullable;

import java.time.Duration;

// Wires a Lettuce-backed Bucket4j ProxyManager when distributed rate-limit is enabled.
// Failure mode: if Redis is unreachable at startup, beans return null and the interceptors
// transparently fall back to the in-memory Caffeine path (single-instance ceiling).
@Configuration
@ConditionalOnProperty(name = "recommendation.ratelimit.distributed", havingValue = "true")
public class RateLimitRedisConfig {

    private static final Logger log = LoggerFactory.getLogger(RateLimitRedisConfig.class);

    @Bean(destroyMethod = "shutdown")
    public RedisClient rateLimitRedisClient(
            @Value("${spring.data.redis.host:localhost}") String host,
            @Value("${spring.data.redis.port:6379}") int port,
            @Value("${spring.data.redis.password:}") String password) {
        RedisURI.Builder builder = RedisURI.builder().withHost(host).withPort(port);
        if (password != null && !password.isBlank()) {
            builder.withPassword(password.toCharArray());
        }
        return RedisClient.create(builder.build());
    }

    @Bean(destroyMethod = "close")
    @Nullable
    public StatefulRedisConnection<String, byte[]> rateLimitRedisConnection(RedisClient client) {
        try {
            RedisCodec<String, byte[]> codec = RedisCodec.of(StringCodec.UTF8, ByteArrayCodec.INSTANCE);
            return client.connect(codec);
        } catch (Exception e) {
            log.warn("Redis unreachable on startup ({}), distributed rate-limit disabled, falling back to in-memory Caffeine.", e.getMessage());
            return null;
        }
    }

    @Bean
    @Nullable
    public ProxyManager<String> rateLimitProxyManager(@Nullable StatefulRedisConnection<String, byte[]> connection) {
        if (connection == null) return null;
        return LettuceBasedProxyManager.builderFor(connection)
                .withExpirationStrategy(ExpirationAfterWriteStrategy.fixedTimeToLive(Duration.ofMinutes(15)))
                .build();
    }
}
