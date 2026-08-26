package com.thegamecellar.apigateway.config;

import io.sentry.Hint;
import io.sentry.SentryEvent;
import io.sentry.SentryOptions;
import io.sentry.protocol.Request;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Removes the client IP that Cloudflare adds at the edge. The SDK already drops the
 * standard IP-bearing headers when send-default-pii is false, but its list is generic
 * and does not know the Cloudflare-specific ones, so they survive that filter.
 */
@Component
public class SentryHeaderScrubber implements SentryOptions.BeforeSendCallback {

    private static final Set<String> DROP = Set.of("cf-connecting-ip", "true-client-ip");

    @Override
    public SentryEvent execute(SentryEvent event, Hint hint) {
        Request request = event.getRequest();
        if (request == null) return event;
        Map<String, String> headers = request.getHeaders();
        if (headers == null) return event;

        // Copied rather than mutated: the SDK does not promise the map is modifiable.
        Map<String, String> kept = new LinkedHashMap<>();
        headers.forEach((name, value) -> {
            if (!DROP.contains(name.toLowerCase(Locale.ROOT))) kept.put(name, value);
        });
        request.setHeaders(kept);
        return event;
    }
}
