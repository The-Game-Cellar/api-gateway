package com.thegamecellar.apigateway.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.Duration;
import java.util.function.Supplier;

@Component
public class LoginRateLimitInterceptor implements HandlerInterceptor {

    @Value("${RATE_LIMIT_LOGIN_REQUESTS:5}")
    private int maxRequests;

    @Value("${RATE_LIMIT_LOGIN_WINDOW_SECONDS:60}")
    private int windowSeconds;

    // Distributed bucket store (Redis-backed). Present only when recommendation.ratelimit.distributed=true.
    // When null, the in-memory Caffeine fallback below carries the load -- single-instance ceiling.
    @Autowired(required = false)
    private ProxyManager<String> proxyManager;

    private final ClientIpResolver clientIpResolver;

    public LoginRateLimitInterceptor(ClientIpResolver clientIpResolver) {
        this.clientIpResolver = clientIpResolver;
    }

    private final Cache<String, Bucket> localBuckets = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofMinutes(15))
            .maximumSize(10_000)
            .build();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String ip = clientIpResolver.resolve(request);
        String key = "ratelimit:login:" + ip;
        Bucket bucket = resolveBucket(key);

        if (bucket.tryConsume(1)) {
            return true;
        }

        response.setStatus(429);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"Too many login attempts. Please try again later.\"}");
        return false;
    }

    private Bucket resolveBucket(String key) {
        Supplier<BucketConfiguration> configSupplier = this::bucketConfig;
        if (proxyManager != null) {
            return proxyManager.builder().build(key, configSupplier);
        }
        return localBuckets.get(key, k -> Bucket.builder().addLimit(configSupplier.get().getBandwidths()[0]).build());
    }

    private BucketConfiguration bucketConfig() {
        return BucketConfiguration.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(maxRequests)
                        .refillIntervally(maxRequests, Duration.ofSeconds(windowSeconds))
                        .build())
                .build();
    }
}
