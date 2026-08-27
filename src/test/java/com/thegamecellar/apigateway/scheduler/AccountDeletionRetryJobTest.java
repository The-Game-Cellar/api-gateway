package com.thegamecellar.apigateway.scheduler;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.thegamecellar.apigateway.support.GatewayTestBase;
import com.thegamecellar.apigateway.support.StubHttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import static org.assertj.core.api.Assertions.assertThat;

// The job is called by hand: the schedule's initial delay is an hour in the test profile.
class AccountDeletionRetryJobTest extends GatewayTestBase {

    private static final String PENDING_PATH = "/internal/library/account-deletions/pending";

    @Autowired
    private AccountDeletionRetryJob job;

    @Value("${account-deletion.retry.max-attempts}")
    private int maxAttempts;

    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();

    @BeforeEach
    void adminTokenAndLogCapture() {
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.StubResponse.json(200,
                "{\"access_token\":\"admin-token\",\"expires_in\":60}"));
        logs.start();
        ((Logger) LoggerFactory.getLogger(AccountDeletionRetryJob.class)).addAppender(logs);
    }

    @AfterEach
    void stopLogCapture() {
        ((Logger) LoggerFactory.getLogger(AccountDeletionRetryJob.class)).detachAppender(logs);
    }

    // Each test uses its own user so the in-memory attempt counter never carries over.
    private static String adminUserPath(String userId) {
        return "/admin/realms/" + REALM + "/users/" + userId;
    }

    private static String completePath(String userId) {
        return "/internal/library/account-deletions/" + userId + "/complete";
    }

    private void pending(String... userIds) {
        StringBuilder body = new StringBuilder("[");
        for (int i = 0; i < userIds.length; i++) {
            if (i > 0) body.append(',');
            body.append("{\"userId\":\"").append(userIds[i]).append("\",\"requestedAt\":\"2026-08-27T10:00:00\"}");
        }
        libraryService.on("GET", PENDING_PATH, StubHttpServer.StubResponse.json(200, body.append(']').toString()));
    }

    @Test
    void finishesAPendingDeletionAndClosesItsLedgerRow() {
        String user = "aaaaaaaa-0000-4000-8000-000000000001";
        pending(user);
        keycloak.on("PUT", adminUserPath(user), StubHttpServer.StubResponse.empty(204));
        keycloak.on("DELETE", adminUserPath(user), StubHttpServer.StubResponse.empty(204));
        libraryService.on("POST", completePath(user), StubHttpServer.StubResponse.empty(204));

        job.run();

        assertThat(libraryService.recorded("GET", PENDING_PATH).get(0).header("X-Internal-Token"))
                .isEqualTo("test-internal-token");
        assertThat(keycloak.recorded("PUT", adminUserPath(user)).get(0).body()).contains("\"enabled\":false");
        assertThat(keycloak.recorded("DELETE", adminUserPath(user))).hasSize(1);
        assertThat(libraryService.recorded("POST", completePath(user)).get(0).header("X-Internal-Token"))
                .isEqualTo("test-internal-token");
    }

    // The request that wrote the ledger row may have deleted the identity and then lost the
    // call that closed the row. A 404 from Keycloak is that case, and it closes the row.
    @Test
    void anIdentityThatIsAlreadyGoneCountsAsDeleted() {
        String user = "aaaaaaaa-0000-4000-8000-000000000002";
        pending(user);
        keycloak.on("PUT", adminUserPath(user), StubHttpServer.StubResponse.empty(404));
        keycloak.on("DELETE", adminUserPath(user), StubHttpServer.StubResponse.empty(404));
        libraryService.on("POST", completePath(user), StubHttpServer.StubResponse.empty(204));

        job.run();

        assertThat(libraryService.recorded("POST", completePath(user))).hasSize(1);
    }

    @Test
    void aFailedAttemptLeavesTheRowOpenAndEscalatesAtTheThreshold() {
        String user = "aaaaaaaa-0000-4000-8000-000000000003";
        pending(user);
        keycloak.on("PUT", adminUserPath(user), StubHttpServer.StubResponse.empty(204));
        keycloak.on("DELETE", adminUserPath(user), StubHttpServer.StubResponse.json(500, "{\"error\":\"down\"}"));
        libraryService.on("POST", completePath(user), StubHttpServer.StubResponse.empty(204));

        for (int i = 0; i < maxAttempts - 1; i++) {
            job.run();
        }
        assertThat(libraryService.recorded("POST", completePath(user))).isEmpty();
        assertThat(logs.list).extracting(ILoggingEvent::getLevel).doesNotContain(Level.ERROR);

        job.run();

        assertThat(libraryService.recorded("POST", completePath(user))).isEmpty();
        assertThat(logs.list).filteredOn(event -> event.getLevel() == Level.ERROR)
                .extracting(ILoggingEvent::getFormattedMessage)
                .anySatisfy(message -> assertThat(message).contains(user).contains("after " + maxAttempts + " attempts"));
    }

    @Test
    void anUnreachableLedgerTouchesNoIdentity() {
        libraryService.on("GET", PENDING_PATH, StubHttpServer.StubResponse.json(500, "{\"error\":\"down\"}"));

        job.run();

        assertThat(keycloak.recorded()).isEmpty();
    }
}
