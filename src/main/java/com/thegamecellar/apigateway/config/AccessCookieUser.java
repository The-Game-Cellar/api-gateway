package com.thegamecellar.apigateway.config;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

// The user an auth endpoint acts for. The security chain does not authenticate /api/v1/auth/**,
// so the access cookie, checked by the same decoder, is the only place that says who it is.
@Component
public class AccessCookieUser {

    private final JwtDecoder jwtDecoder;

    public AccessCookieUser(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    // Null when there is no cookie or the decoder rejects it: no account to count against.
    public String subject(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie cookie : cookies) {
            if ("access_token".equals(cookie.getName())) {
                try {
                    String sub = jwtDecoder.decode(cookie.getValue()).getSubject();
                    return sub == null || sub.isBlank() ? null : sub;
                } catch (JwtException e) {
                    return null;
                }
            }
        }
        return null;
    }
}
