package com.thegamecellar.apigateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.function.RouterFunction;
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

    @Bean
    public RouterFunction<ServerResponse> gameServiceRoute() {
        return route("game-service")
                .route(path("/api/v1/games/**"), http())
                .before(uri(gameServiceUrl))
                .build();
    }

    @Bean
    public RouterFunction<ServerResponse> libraryServiceRoute() {
        return route("library-service")
                .route(path("/api/v1/library/**"), http())
                .before(uri(libraryServiceUrl))
                .build();
    }

    @Bean
    public RouterFunction<ServerResponse> recommendationServiceRoute() {
        return route("recommendation-service")
                .route(path("/api/v1/recommendations/**"), http())
                .before(uri(recommendationServiceUrl))
                .build();
    }
}