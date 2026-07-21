package com.thegamecellar.apigateway.config;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Derives the real client IP for rate-limit bucket keys.
 *
 * X-Forwarded-For is honoured only when the direct peer is a configured trusted proxy; otherwise
 * the header is attacker-controlled and ignored. Within a trusted chain the rightmost untrusted
 * entry wins, so spoofed values prepended by the client are never reached.
 */
@Component
public class ClientIpResolver {

    private static final String XFF_HEADER = "X-Forwarded-For";

    private final List<IpAddressMatcher> trustedProxies = new ArrayList<>();

    // Comma-separated single IPs or CIDR ranges of proxies allowed to set X-Forwarded-For.
    // Empty (the default) means no proxy is trusted, so the header is ignored everywhere.
    @Value("${RATE_LIMIT_TRUSTED_PROXIES:}")
    private String trustedProxiesConfig;

    @PostConstruct
    void init() {
        if (trustedProxiesConfig == null || trustedProxiesConfig.isBlank()) {
            return;
        }
        for (String entry : trustedProxiesConfig.split(",")) {
            String cidr = entry.trim();
            if (!cidr.isEmpty()) {
                trustedProxies.add(new IpAddressMatcher(cidr));
            }
        }
    }

    public String resolve(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();

        // Untrusted direct peer: the header could say anything, so bucket by the real socket address.
        if (!isTrusted(remoteAddr)) {
            return remoteAddr;
        }

        String forwarded = request.getHeader(XFF_HEADER);
        if (forwarded == null || forwarded.isBlank()) {
            return remoteAddr;
        }

        // Walk right-to-left, skipping trusted hops; first untrusted address is the real client.
        String[] chain = forwarded.split(",");
        for (int i = chain.length - 1; i >= 0; i--) {
            String candidate = chain[i].trim();
            if (!candidate.isEmpty() && !isTrusted(candidate)) {
                return candidate;
            }
        }

        // Whole chain is trusted (or empty entries only): fall back to the direct peer.
        return remoteAddr;
    }

    private boolean isTrusted(String ip) {
        for (IpAddressMatcher matcher : trustedProxies) {
            try {
                if (matcher.matches(ip)) {
                    return true;
                }
            } catch (IllegalArgumentException ignored) {
                // Malformed candidate (e.g. a spoofed non-IP token) can never be a trusted proxy.
            }
        }
        return false;
    }
}
