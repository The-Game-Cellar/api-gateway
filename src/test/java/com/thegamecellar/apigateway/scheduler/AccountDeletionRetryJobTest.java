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

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

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

    // A token endpoint answering 404 is a broken realm or URL. Read as "user already gone" it
    // would close the ledger row with the identity still in Keycloak, and nothing retries a
    // closed row.
    @Test
    void aTokenEndpointAnswering404LeavesTheLedgerRowOpen() {
        String user = "aaaaaaaa-0000-4000-8000-000000000404";
        pending(user);
        forgetAdminToken();
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.StubResponse.json(404, "{\"error\":\"Realm does not exist\"}"));
        keycloak.on("PUT", adminUserPath(user), StubHttpServer.StubResponse.empty(204));
        keycloak.on("DELETE", adminUserPath(user), StubHttpServer.StubResponse.empty(204));
        libraryService.on("POST", completePath(user), StubHttpServer.StubResponse.empty(204));

        job.run();

        assertThat(keycloak.recorded("DELETE", adminUserPath(user))).isEmpty();
        assertThat(libraryService.recorded("POST", completePath(user))).isEmpty();
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

    private void identityAnswers(String user, int deleteStatus) {
        keycloak.on("PUT", adminUserPath(user), StubHttpServer.StubResponse.empty(204));
        keycloak.on("DELETE", adminUserPath(user), deleteStatus == 204
                ? StubHttpServer.StubResponse.empty(204)
                : StubHttpServer.StubResponse.json(deleteStatus, "{\"error\":\"down\"}"));
        libraryService.on("POST", completePath(user), StubHttpServer.StubResponse.empty(204));
    }

    private long errorsNaming(String user) {
        return logs.list.stream()
                .filter(event -> event.getLevel() == Level.ERROR && event.getFormattedMessage().contains(user))
                .count();
    }

    // A deletion stuck for hours keeps surfacing: the ERROR repeats at every multiple of the
    // threshold rather than firing once and going quiet.
    @Test
    void theEscalationRepeatsAtEveryMultipleOfTheThreshold() {
        String user = "aaaaaaaa-0000-4000-8000-000000000010";
        pending(user);
        identityAnswers(user, 500);

        for (int i = 0; i < 2 * maxAttempts; i++) {
            job.run();
        }

        assertThat(errorsNaming(user)).isEqualTo(2);
        assertThat(logs.list).filteredOn(event -> event.getLevel() == Level.ERROR)
                .extracting(ILoggingEvent::getFormattedMessage)
                .anySatisfy(message -> assertThat(message).contains("after " + 2 * maxAttempts + " attempts"));
    }

    // A success forgets the failures before it, so a later run of failures for the same user
    // counts from one again and does not escalate early.
    @Test
    void aSuccessResetsTheAttemptCount() {
        String user = "aaaaaaaa-0000-4000-8000-000000000011";
        pending(user);
        identityAnswers(user, 500);
        for (int i = 0; i < maxAttempts - 1; i++) {
            job.run();
        }

        identityAnswers(user, 204);
        job.run();
        assertThat(libraryService.recorded("POST", completePath(user))).hasSize(1);

        identityAnswers(user, 500);
        job.run();

        assertThat(errorsNaming(user)).isZero();
    }

    @Test
    void oneUserFailingDoesNotHoldUpTheNext() {
        String stuck = "aaaaaaaa-0000-4000-8000-000000000012";
        String next = "aaaaaaaa-0000-4000-8000-000000000013";
        pending(stuck, next);
        identityAnswers(stuck, 500);
        identityAnswers(next, 204);

        job.run();

        assertThat(libraryService.recorded("POST", completePath(stuck))).isEmpty();
        assertThat(keycloak.recorded("DELETE", adminUserPath(next))).hasSize(1);
        assertThat(libraryService.recorded("POST", completePath(next))).hasSize(1);
    }

    @Test
    void anEmptyLedgerTouchesNoIdentity() {
        libraryService.on("GET", PENDING_PATH, StubHttpServer.StubResponse.json(200, "[]"));

        job.run();

        assertThat(keycloak.recorded()).isEmpty();
        assertThat(logs.list).extracting(ILoggingEvent::getLevel).doesNotContain(Level.WARN, Level.ERROR);
    }

    // A ledger answer the job cannot read is treated like an unreachable ledger: nothing is
    // deleted on a guess, and the next run tries again.
    @Test
    void aLedgerAnswerThatIsNotAListTouchesNoIdentity() {
        libraryService.on("GET", PENDING_PATH, StubHttpServer.StubResponse.json(200, "{\"userId\":\"not-a-list\"}"));

        job.run();

        assertThat(keycloak.recorded()).isEmpty();
        assertThat(logs.list).filteredOn(event -> event.getLevel() == Level.WARN)
                .extracting(ILoggingEvent::getFormattedMessage)
                .anySatisfy(message -> assertThat(message).contains("ledger unreachable"));
    }

    @Test
    void ledgerRowsWithoutAUserIdAreSkipped() {
        String user = "aaaaaaaa-0000-4000-8000-000000000014";
        libraryService.on("GET", PENDING_PATH, StubHttpServer.StubResponse.json(200,
                "[{\"requestedAt\":\"2026-08-27T10:00:00\"},{\"userId\":null},{\"userId\":\"" + user + "\"}]"));
        identityAnswers(user, 204);

        job.run();

        assertThat(keycloak.recorded("DELETE", "/admin/realms/" + REALM + "/users/"))
                .extracting(StubHttpServer.RecordedRequest::path)
                .containsExactly(adminUserPath(user));
    }

    // The admin token itself failing is one more failed attempt, not a crash of the job.
    @Test
    void anAdminTokenTheJobCannotGetCountsAsAFailedAttempt() {
        String user = "aaaaaaaa-0000-4000-8000-000000000015";
        pending(user);
        identityAnswers(user, 204);
        forgetAdminToken();
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.StubResponse.json(500, "{\"error\":\"down\"}"));

        job.run();

        assertThat(keycloak.recorded("DELETE", adminUserPath(user))).isEmpty();
        assertThat(libraryService.recorded("POST", completePath(user))).isEmpty();
        assertThat(logs.list).filteredOn(event -> event.getLevel() == Level.WARN)
                .extracting(ILoggingEvent::getFormattedMessage)
                .anySatisfy(message -> assertThat(message).contains("attempt 1 failed").contains(user));
    }

    // The job runs on the single scheduler thread, so a Keycloak that hangs must time out
    // rather than stop every later run.
    @Test
    void aKeycloakThatNeverAnswersIsAFailedAttemptNotAHang() {
        String user = "aaaaaaaa-0000-4000-8000-000000000016";
        pending(user);
        identityAnswers(user, 204);
        keycloak.on("DELETE", adminUserPath(user), StubHttpServer.after(Duration.ofSeconds(3), StubHttpServer.StubResponse.empty(204)));

        assertTimeoutPreemptively(Duration.ofSeconds(3), () -> job.run());

        assertThat(libraryService.recorded("POST", completePath(user))).isEmpty();
        assertThat(logs.list).filteredOn(event -> event.getLevel() == Level.WARN)
                .extracting(ILoggingEvent::getFormattedMessage)
                .anySatisfy(message -> assertThat(message).contains("attempt 1 failed").contains(user));
    }

    // Two pending users is four admin calls. A token valid for a minute serves all of them.
    @Test
    void theAdminTokenIsReusedWhileItIsValid() {
        String first = "aaaaaaaa-0000-4000-8000-000000000017";
        String second = "aaaaaaaa-0000-4000-8000-000000000018";
        pending(first, second);
        identityAnswers(first, 204);
        identityAnswers(second, 204);
        forgetAdminToken();

        job.run();

        assertThat(keycloak.recorded("POST", TOKEN_PATH)).hasSize(1);
        assertThat(keycloak.recorded("DELETE", adminUserPath(second)).get(0).header("Authorization"))
                .isEqualTo("Bearer admin-token");
    }

    // A token is dropped five seconds before it expires, so one issued for five seconds is never
    // used twice: a call made on the edge of expiry would otherwise reach Keycloak already dead.
    @Test
    void aTokenWithinFiveSecondsOfExpiryIsFetchedAgain() {
        String first = "aaaaaaaa-0000-4000-8000-000000000019";
        String second = "aaaaaaaa-0000-4000-8000-000000000020";
        pending(first, second);
        identityAnswers(first, 204);
        identityAnswers(second, 204);
        forgetAdminToken();
        keycloak.on("POST", TOKEN_PATH, StubHttpServer.StubResponse.json(200,
                "{\"access_token\":\"short-lived\",\"expires_in\":5}"));

        job.run();

        // Disable and delete for each of the two users, each with a token of its own.
        assertThat(keycloak.recorded("POST", TOKEN_PATH)).hasSize(4);
    }
}
