package com.thegamecellar.apigateway.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.Duration;

/**
 * Per-user rate limit on /api/v1/recommendations/**. Each request triggers up to
 * 5–10 downstream calls to Game Service + Library Service, so flooding this endpoint
 * amplifies load on every backend service. Bucket key is the JWT sub claim
 * (per-authenticated-user); falls back to client IP for unauthenticated requests
 * even though those should already be rejected by Spring Security.
 */
@Component
public class RecommendationRateLimitInterceptor implements HandlerInterceptor {

    @Value("${RATE_LIMIT_RECOMMENDATIONS_REQUESTS:60}")
    private int maxRequests;

    @Value("${RATE_LIMIT_RECOMMENDATIONS_WINDOW_SECONDS:60}")
    private int windowSeconds;

    private final Cache<String, Bucket> buckets = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofMinutes(15))
            .maximumSize(10_000)
            .build();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String key = bucketKey(request);
        Bucket bucket = buckets.get(key, k -> newBucket());

        if (bucket.tryConsume(1)) {
            return true;
        }

        response.setStatus(429);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"Too many recommendation requests. Please slow down.\"}");
        return false;
    }

    private Bucket newBucket() {
        return Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(maxRequests)
                        .refillIntervally(maxRequests, Duration.ofSeconds(windowSeconds))
                        .build())
                .build();
    }

    private String bucketKey(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof JwtAuthenticationToken jwt) {
            String sub = jwt.getToken().getSubject();
            if (sub != null && !sub.isBlank()) return "user:" + sub;
        }
        return "ip:" + getClientIp(request);
    }

    private String getClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
