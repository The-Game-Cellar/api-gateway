package com.thegamecellar.apigateway.config;

import jakarta.servlet.http.Cookie;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.function.HandlerFilterFunction;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

import static org.springframework.cloud.gateway.server.mvc.filter.BeforeFilterFunctions.uri;
import static org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions.route;
import static org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctions.http;
import static org.springframework.cloud.gateway.server.mvc.predicate.GatewayRequestPredicates.path;

@Configuration
public class GatewayRoutesConfig {

    @Value("${GAME_SERVICE_URL:http://localhost:8081}")
    private String gameServiceUrl;

    @Value("${LIBRARY_SERVICE_URL:http://localhost:8082}")
    private String libraryServiceUrl;

    @Value("${RECOMMENDATION_SERVICE_URL:http://localhost:8083}")
    private String recommendationServiceUrl;

    private HandlerFilterFunction<ServerResponse, ServerResponse> cookieToBearerHeader() {
        return (request, next) -> {
            String existingAuth = request.headers().firstHeader("Authorization");
            if (existingAuth != null) {
                return next.handle(request);
            }
            Cookie[] cookies = request.servletRequest().getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("access_token".equals(cookie.getName())) {
                        String token = cookie.getValue();
                        ServerRequest modified = ServerRequest.from(request)
                                .headers(headers -> headers.set("Authorization", "Bearer " + token))
                                .build();
                        return next.handle(modified);
                    }
                }
            }
            return next.handle(request);
        };
    }

    @Bean
    public RouterFunction<ServerResponse> gameServiceRoute() {
        return route("game-service")
                .route(path("/api/v1/games/**"), http())
                .route(path("/api/v1/platforms/**"), http())
                .route(path("/api/v1/admin/**"), http())
                .filter(cookieToBearerHeader())
                .before(uri(gameServiceUrl))
                .build();
    }

    @Bean
    public RouterFunction<ServerResponse> libraryServiceRoute() {
        return route("library-service")
                .route(path("/api/v1/library/**"), http())
                .filter(cookieToBearerHeader())
                .before(uri(libraryServiceUrl))
                .build();
    }

    @Bean
    public RouterFunction<ServerResponse> recommendationServiceRoute() {
        return route("recommendation-service")
                .route(path("/api/v1/recommendations/**"), http())
                .filter(cookieToBearerHeader())
                .before(uri(recommendationServiceUrl))
                .build();
    }
}