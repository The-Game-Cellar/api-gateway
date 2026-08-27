package com.thegamecellar.apigateway.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.thegamecellar.apigateway.controller.AuthIntent;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.Duration;
import java.util.function.Supplier;

// Two budgets on the one route that starts every hosted Keycloak flow. Anonymous starts,
// login and sign-up, count per client address, since nothing else identifies the caller.
// Account actions count per user, so someone changing their email a few times cannot spend
// the login budget of everyone behind the same address. Sign-up itself is limited where the
// account is created, by nginx on the auth host, because that form never passes through here.
@Component
public class AuthorizeRateLimitInterceptor implements HandlerInterceptor {

    @Value("${RATE_LIMIT_LOGIN_REQUESTS:5}")
    private int loginRequests;

    @Value("${RATE_LIMIT_LOGIN_WINDOW_SECONDS:60}")
    private int loginWindowSeconds;

    @Value("${RATE_LIMIT_ACCOUNT_ACTION_REQUESTS:10}")
    private int accountActionRequests;

    @Value("${RATE_LIMIT_ACCOUNT_ACTION_WINDOW_SECONDS:600}")
    private int accountActionWindowSeconds;

    // Distributed bucket store (Redis-backed). Present only when recommendation.ratelimit.distributed=true.
    // When null, the in-memory Caffeine fallback below carries the load -- single-instance ceiling.
    @Autowired(required = false)
    private ProxyManager<String> proxyManager;

    private final ClientIpResolver clientIpResolver;

    public AuthorizeRateLimitInterceptor(ClientIpResolver clientIpResolver) {
        this.clientIpResolver = clientIpResolver;
    }

    private final Cache<String, Bucket> localBuckets = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofMinutes(15))
            .maximumSize(10_000)
            .build();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        AuthIntent intent = AuthIntent.from(request.getParameter("intent"));
        Bucket bucket;
        String message;
        if (intent.isAccountAction()) {
            bucket = resolveBucket("ratelimit:account-action:" + userOrAddress(request),
                    accountActionRequests, accountActionWindowSeconds);
            message = "Too many account changes. Please try again later.";
        } else {
            bucket = resolveBucket("ratelimit:login:" + clientIpResolver.resolve(request),
                    loginRequests, loginWindowSeconds);
            message = "Too many login attempts. Please try again later.";
        }

        if (bucket.tryConsume(1)) {
            return true;
        }

        response.setStatus(429);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"" + message + "\"}");
        return false;
    }

    // The action lands on the account the cookie names, so that is the fair unit to count.
    // Without a usable cookie there is no such account, and the address is all that is left.
    private String userOrAddress(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof JwtAuthenticationToken jwt) {
            String sub = jwt.getToken().getSubject();
            if (sub != null && !sub.isBlank()) return "user:" + sub;
        }
        return "ip:" + clientIpResolver.resolve(request);
    }

    private Bucket resolveBucket(String key, int requests, int windowSeconds) {
        Supplier<BucketConfiguration> configSupplier = () -> bucketConfig(requests, windowSeconds);
        if (proxyManager != null) {
            return proxyManager.builder().build(key, configSupplier);
        }
        return localBuckets.get(key, k -> Bucket.builder().addLimit(configSupplier.get().getBandwidths()[0]).build());
    }

    private static BucketConfiguration bucketConfig(int requests, int windowSeconds) {
        return BucketConfiguration.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(requests)
                        .refillIntervally(requests, Duration.ofSeconds(windowSeconds))
                        .build())
                .build();
    }
}
