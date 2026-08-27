package com.thegamecellar.apigateway.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;
import java.util.Objects;

// The deletion ledger lives in library-service, behind the same internal path and shared
// secret as the other service-to-service calls. No user token is involved: by the time
// anything here runs, the user is disabled or gone.
@Component
public class AccountDeletionLedgerClient {

    private static final Logger log = LoggerFactory.getLogger(AccountDeletionLedgerClient.class);
    private static final String HEADER = "X-Internal-Token";

    private final RestClient restClient = RestClient.create();
    private final String baseUrl;
    private final String internalToken;

    public AccountDeletionLedgerClient(@Value("${LIBRARY_SERVICE_URL:http://localhost:8082}") String libraryServiceUrl,
                                       @Value("${security.internal.token:}") String internalToken) {
        this.baseUrl = libraryServiceUrl + "/internal/library/account-deletions";
        this.internalToken = internalToken;
        if (internalToken == null || internalToken.isBlank()) {
            log.warn("INTERNAL_SERVICE_TOKEN unset; the account deletion ledger cannot be read or updated");
        }
    }

    public List<String> pending() {
        List<Map<String, Object>> rows = restClient.get()
                .uri(baseUrl + "/pending")
                .header(HEADER, internalToken)
                .retrieve()
                .body(new ParameterizedTypeReference<>() {});
        if (rows == null) {
            return List.of();
        }
        return rows.stream()
                .map(row -> row.get("userId"))
                .filter(Objects::nonNull)
                .map(Object::toString)
                .toList();
    }

    public void complete(String userId) {
        restClient.post()
                .uri(baseUrl + "/" + userId + "/complete")
                .header(HEADER, internalToken)
                .retrieve()
                .toBodilessEntity();
    }
}
