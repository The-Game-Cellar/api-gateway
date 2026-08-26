package com.thegamecellar.apigateway.config;

import io.sentry.Hint;
import io.sentry.SentryEvent;
import io.sentry.protocol.Request;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SentryHeaderScrubberTest {

    private final SentryHeaderScrubber scrubber = new SentryHeaderScrubber();

    @Test
    void dropsCloudflareClientIpHeaders() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("CF-Connecting-IP", "83.68.238.159");
        headers.put("True-Client-IP", "83.68.238.159");
        headers.put("User-Agent", "Firefox");

        SentryEvent event = eventWithHeaders(headers);
        scrubber.execute(event, new Hint());

        assertThat(event.getRequest().getHeaders()).containsOnlyKeys("User-Agent");
    }

    @Test
    void matchesHeaderNamesRegardlessOfCase() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("cf-connecting-ip", "83.68.238.159");

        SentryEvent event = eventWithHeaders(headers);
        scrubber.execute(event, new Hint());

        assertThat(event.getRequest().getHeaders()).isEmpty();
    }

    @Test
    void toleratesAnEventWithoutARequest() {
        SentryEvent event = new SentryEvent();

        assertThat(scrubber.execute(event, new Hint())).isSameAs(event);
    }

    private SentryEvent eventWithHeaders(Map<String, String> headers) {
        Request request = new Request();
        request.setHeaders(headers);
        SentryEvent event = new SentryEvent();
        event.setRequest(request);
        return event;
    }
}
