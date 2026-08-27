package com.thegamecellar.apigateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.time.Duration;

// The client behind every call this service makes itself: the Keycloak token and Admin
// endpoints and library-service's purge and ledger. Proxied traffic does not use this; it
// goes through Boot's RestClient.Builder, configured by spring.http.clients.* in
// application.yaml. The factory is deliberately not a bean: Gateway MVC picks up any
// ClientHttpRequestFactory bean for the proxy, which would put these short timeouts on
// user traffic.
@Configuration
public class OutboundRestClientConfig {

    @Bean
    public RestClient outboundRestClient(@Value("${gateway.outbound.connect-timeout-ms:2000}") long connectTimeoutMs,
                                         @Value("${gateway.outbound.read-timeout-ms:5000}") long readTimeoutMs) {
        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(connectTimeoutMs))
                .build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(httpClient);
        factory.setReadTimeout(Duration.ofMillis(readTimeoutMs));
        return RestClient.builder().requestFactory(factory).build();
    }
}
