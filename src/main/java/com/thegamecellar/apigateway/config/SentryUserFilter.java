package com.thegamecellar.apigateway.config;

import io.sentry.Sentry;
import io.sentry.protocol.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Tags Sentry events with the Keycloak UUID, which separates "broken for one account"
 * from "broken for everyone". Nothing else about the user is sent.
 */
public class SentryUserFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof Jwt jwt) {
            User user = new User();
            // Subject only. The id comes from the validated token, never from the request.
            user.setId(jwt.getSubject());
            Sentry.setUser(user);
        }
        try {
            chain.doFilter(request, response);
        } finally {
            Sentry.setUser(null);
        }
    }
}
