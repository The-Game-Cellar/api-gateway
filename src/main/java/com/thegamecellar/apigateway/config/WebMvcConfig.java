package com.thegamecellar.apigateway.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    private final AuthorizeRateLimitInterceptor authorizeRateLimitInterceptor;
    private final RecommendationRateLimitInterceptor recommendationRateLimitInterceptor;

    public WebMvcConfig(AuthorizeRateLimitInterceptor authorizeRateLimitInterceptor,
                        RecommendationRateLimitInterceptor recommendationRateLimitInterceptor) {
        this.authorizeRateLimitInterceptor = authorizeRateLimitInterceptor;
        this.recommendationRateLimitInterceptor = recommendationRateLimitInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // The password grant is gone, so the surface worth limiting is the route that
        // starts every hosted flow. Callback is left out: it carries a one-time code and a
        // limit there would break a legitimate return from Keycloak.
        registry.addInterceptor(authorizeRateLimitInterceptor)
                .addPathPatterns("/api/v1/auth/authorize");
        registry.addInterceptor(recommendationRateLimitInterceptor)
                .addPathPatterns("/api/v1/recommendations/**");
    }
}
