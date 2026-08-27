package com.thegamecellar.apigateway.scheduler;

import com.thegamecellar.apigateway.client.AccountDeletionLedgerClient;
import com.thegamecellar.apigateway.client.KeycloakAdminClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

// Finishes account deletions whose library purge committed but whose identity delete never
// got confirmed. The ledger row is the only state; the attempt count is in memory and only
// decides when to escalate, so a restart merely delays the alert, never loses the deletion.
@Component
public class AccountDeletionRetryJob {

    private static final Logger log = LoggerFactory.getLogger(AccountDeletionRetryJob.class);

    private final KeycloakAdminClient keycloak;
    private final AccountDeletionLedgerClient ledger;
    private final int maxAttempts;
    private final Map<String, Integer> attempts = new ConcurrentHashMap<>();

    public AccountDeletionRetryJob(KeycloakAdminClient keycloak,
                                  AccountDeletionLedgerClient ledger,
                                  @Value("${account-deletion.retry.max-attempts:10}") int maxAttempts) {
        this.keycloak = keycloak;
        this.ledger = ledger;
        this.maxAttempts = maxAttempts;
    }

    @Scheduled(fixedDelayString = "${account-deletion.retry.fixed-delay-ms:60000}",
               initialDelayString = "${account-deletion.retry.initial-delay-ms:60000}")
    public void run() {
        List<String> pending;
        try {
            pending = ledger.pending();
        } catch (RestClientException e) {
            log.warn("Account deletion retry: ledger unreachable ({}), trying again next tick", e.getMessage());
            return;
        }
        for (String userId : pending) {
            retry(userId);
        }
    }

    private void retry(String userId) {
        try {
            keycloak.setEnabled(userId, false);
            keycloak.delete(userId);
            ledger.complete(userId);
            attempts.remove(userId);
            log.info("Account deletion retry: identity removed and ledger closed for userId={}", userId);
        } catch (RestClientException e) {
            int attempt = attempts.merge(userId, 1, Integer::sum);
            // ERROR is a Sentry event and an email; repeated at every multiple of the threshold so a
            // deletion stuck for hours keeps surfacing rather than alerting once and going quiet.
            if (attempt % maxAttempts == 0) {
                log.error("Account deletion retry: userId={} still not finished after {} attempts", userId, attempt, e);
            } else {
                log.warn("Account deletion retry: attempt {} failed for userId={}: {}", attempt, userId, e.getMessage());
            }
        }
    }
}
