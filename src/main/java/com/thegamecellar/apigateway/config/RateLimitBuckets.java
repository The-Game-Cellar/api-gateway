package com.thegamecellar.apigateway.config;

import com.github.benmanes.caffeine.cache.Cache;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.Supplier;

// The one bucket lookup every limiter uses: Redis when the distributed store is there, memory when
// it is absent or failing. A Redis outage costs a request the store's command timeout, never the
// request itself, and the limit still holds per instance while it lasts.
final class RateLimitBuckets {

    private static final Logger log = LoggerFactory.getLogger(RateLimitBuckets.class);

    private RateLimitBuckets() {}

    static boolean tryConsume(ProxyManager<String> proxyManager, Cache<String, Bucket> localBuckets,
                              String key, Supplier<BucketConfiguration> config) {
        if (proxyManager != null) {
            try {
                return proxyManager.builder().build(key, config).tryConsume(1);
            } catch (RuntimeException e) {
                log.warn("Rate-limit store unreachable ({}), counting in memory", e.getMessage());
            }
        }
        return localBuckets.get(key, k -> Bucket.builder().addLimit(config.get().getBandwidths()[0]).build())
                .tryConsume(1);
    }
}
