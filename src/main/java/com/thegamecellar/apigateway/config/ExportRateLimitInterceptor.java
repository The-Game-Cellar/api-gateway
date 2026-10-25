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

// Per-user budget on the account export. One export fans out to three Keycloak Admin calls and
// a full read of the user's rows in two services, so a loop on it is the cheapest way for one
// account to load all three. The route is open to anonymous callers, who the controller refuses
// before any of that work, so only a signed-in request is counted.
@Component
public class ExportRateLimitInterceptor implements HandlerInterceptor {

    @Value("${RATE_LIMIT_EXPORT_REQUESTS:5}")
    private int maxRequests;

    @Value("${RATE_LIMIT_EXPORT_WINDOW_SECONDS:600}")
    private int windowSeconds;

    // Distributed bucket store (Redis-backed). Present only when recommendation.ratelimit.distributed=true.
    // When null, the in-memory Caffeine fallback below carries the load -- single-instance ceiling.
    @Autowired(required = false)
    private ProxyManager<String> proxyManager;

    private final AccessCookieUser accessCookieUser;

    public ExportRateLimitInterceptor(AccessCookieUser accessCookieUser) {
        this.accessCookieUser = accessCookieUser;
    }

    private final Cache<String, Bucket> localBuckets = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofMinutes(15))
            .maximumSize(10_000)
            .build();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String sub = accessCookieUser.subject(request);
        if (sub == null) {
            return true;
        }

        if (RateLimitBuckets.tryConsume(proxyManager, localBuckets, "ratelimit:export:user:" + sub, this::bucketConfig)) {
            return true;
        }
        response.setStatus(429);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"Too many exports. Please try again later.\"}");
        return false;
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
