package com.thegamecellar.apigateway.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    private final LoginRateLimitInterceptor loginRateLimitInterceptor;
    private final RecommendationRateLimitInterceptor recommendationRateLimitInterceptor;

    public WebMvcConfig(LoginRateLimitInterceptor loginRateLimitInterceptor,
                        RecommendationRateLimitInterceptor recommendationRateLimitInterceptor) {
        this.loginRateLimitInterceptor = loginRateLimitInterceptor;
        this.recommendationRateLimitInterceptor = recommendationRateLimitInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(loginRateLimitInterceptor)
                .addPathPatterns("/api/v1/auth/login", "/api/v1/auth/register");
        registry.addInterceptor(recommendationRateLimitInterceptor)
                .addPathPatterns("/api/v1/recommendations/**");
    }
}
