package com.thegamecellar.apigateway.config;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.thegamecellar.apigateway.scheduler.AccountDeletionRetryJob;
import com.thegamecellar.apigateway.support.GatewayTestBase;
import com.thegamecellar.apigateway.support.StubHttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// Both outbound paths must give up on a peer that accepts the connection and never answers.
// The test profile sets read timeouts of one second; the stubs below sleep past them.
class OutboundTimeoutTest extends GatewayTestBase {

    private static final String PENDING_PATH = "/internal/library/account-deletions/pending";

    @Autowired
    private AccountDeletionRetryJob job;

    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();

    @BeforeEach
    void captureJobLog() {
        logs.start();
        ((Logger) LoggerFactory.getLogger(AccountDeletionRetryJob.class)).addAppender(logs);
    }

    @AfterEach
    void stopCapture() {
        ((Logger) LoggerFactory.getLogger(AccountDeletionRetryJob.class)).detachAppender(logs);
    }

    private static StubHttpServer.StubResponse answerAfter(Duration delay, String body) {
        try {
            Thread.sleep(delay.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return StubHttpServer.StubResponse.json(200, body);
    }

    // The job runs on Spring's single scheduler thread: a call that never returned would stop
    // every later run silently, so the read timeout is what keeps the ledger moving.
    @Test
    void theRetryJobGivesUpOnALedgerThatNeverAnswers() {
        libraryService.on("GET", PENDING_PATH, request -> answerAfter(Duration.ofSeconds(3), "[]"));

        assertTimeoutPreemptively(Duration.ofSeconds(2), () -> job.run());

        assertThat(keycloak.recorded()).isEmpty();
        assertThat(logs.list).filteredOn(event -> event.getLevel() == Level.WARN)
                .extracting(ILoggingEvent::getFormattedMessage)
                .anySatisfy(message -> assertThat(message).contains("ledger unreachable"));
    }

    @Test
    void aProxiedCallToAServiceThatNeverAnswersIsA504NotAHang() throws Exception {
        issue("token", "someone");
        gameService.on("GET", "/api/v1/games/slow", request -> answerAfter(Duration.ofSeconds(3), "{\"from\":\"game\"}"));

        assertTimeoutPreemptively(Duration.ofSeconds(2), () ->
                mvc.perform(get("/api/v1/games/slow").cookie(accessCookie("token")))
                        .andExpect(status().isGatewayTimeout())
                        .andExpect(jsonPath("$.error").value("Upstream service did not respond")));
    }
}
