package com.thegamecellar.apigateway.config;

import io.sentry.protocol.User;
import io.sentry.spring7.SentryUserProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

/**
 * Tags Sentry events with the Keycloak UUID, which separates "broken for one account"
 * from "broken for everyone". Nothing else about the user is sent.
 *
 * A provider rather than a filter: Sentry's own user filter runs innermost and rebuilds
 * the user from these beans, overwriting anything set earlier in the request.
 */
@Component
public class SentryJwtUserProvider implements SentryUserProvider {

    @Override
    public User provideUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt jwt)) {
            return null;
        }
        User user = new User();
        // Subject only. The id comes from the validated token, never from the request.
        user.setId(jwt.getSubject());
        return user;
    }
}
