package ai.authplane.sdk.core.fetching;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

import org.junit.jupiter.api.Test;

class DocumentCacheTest {

    private static final Map<String, Object> DOC_V1 = Map.of("version", "1");
    private static final Map<String, Object> DOC_V2 = Map.of("version", "2");

    /** Arbitrary fixed start time; only the deltas matter. */
    private static final long T0 = 1_700_000_000L;

    private DocumentCache cache;

    @Test
    void fetch_populatesCache() throws Exception {
        cache = cacheWith(successFetcher(DOC_V1), 300);
        cache.fetch();
        assertThat(cache.get()).isEqualTo(DOC_V1);
    }

    @Test
    void get_returnsCachedDocumentWithinTtl() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        cache = cacheWith(countingFetcher(DOC_V1, fetchCount), 300);
        cache.fetch();
        cache.get();
        cache.get();
        // Should have fetched exactly once
        assertThat(fetchCount.get()).isEqualTo(1);
    }

    @Test
    void get_usesStaleCacheOnFetchFailure() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        DocumentFetcher fetcher =
                url ->
                        CompletableFuture.supplyAsync(
                                () -> {
                                    int n = calls.incrementAndGet();
                                    if (n == 1) return new FetchResult(DOC_V1, null);
                                    throw new CompletionException(
                                            new RuntimeException("Network down"));
                                });
        TestClock clock = new TestClock();
        cache = cacheWith(fetcher, 100, clock);
        cache.fetch();

        clock.advanceSeconds(101); // past the TTL

        // get() refreshes synchronously, the refresh fails, stale is returned
        assertThat(cache.get()).isEqualTo(DOC_V1);
        assertThat(calls.get()).isEqualTo(2);
    }

    @Test
    void get_throwsWhenNoCacheAndFetchFails() {
        DocumentFetcher failing =
                url -> CompletableFuture.failedFuture(new RuntimeException("Network down"));
        cache = cacheWith(failing, 300);
        // fetch() not called — no initial cache
        assertThatThrownBy(() -> cache.get()).isInstanceOf(Exception.class);
    }

    @Test
    void onChangeCallback_calledWhenDocumentChanges() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        AtomicInteger fetchCount = new AtomicInteger();
        DocumentFetcher fetcher =
                url ->
                        CompletableFuture.supplyAsync(
                                () -> {
                                    int n = fetchCount.incrementAndGet();
                                    return new FetchResult(n == 1 ? DOC_V1 : DOC_V2, null);
                                });

        TestClock clock = new TestClock();
        cache = cacheWith(fetcher, 100, (old, next) -> calls.incrementAndGet(), clock);
        cache.fetch(); // DOC_V1
        assertThat(calls.get()).isEqualTo(0); // no change on the first fetch

        clock.advanceSeconds(101); // past the TTL

        // Expired, so get() refreshes synchronously — the callback fires inline, not on a
        // background thread, so there is nothing to wait for.
        assertThat(cache.get()).isEqualTo(DOC_V2);
        assertThat(calls.get()).isEqualTo(1);
    }

    @Test
    void forceRefresh_alwaysFetches() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        cache = cacheWith(countingFetcher(DOC_V1, fetchCount), 300);
        cache.fetch();
        cache.forceRefresh();
        assertThat(fetchCount.get()).isEqualTo(2);
    }

    @Test
    void get_triggersBackgroundRefreshAt80PercentTtl() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        TestClock clock = new TestClock();
        cache = cacheWith(countingFetcher(DOC_V1, fetchCount), 100, clock);
        cache.fetch();
        assertThat(fetchCount.get()).isEqualTo(1);

        clock.advanceSeconds(79); // just under the 80% threshold
        cache.get();
        assertThat(cache.backgroundRefreshFuture()).isNull();
        assertThat(fetchCount.get()).isEqualTo(1);

        clock.advanceSeconds(1); // exactly 80% of the 100s TTL
        cache.get();

        CompletableFuture<Void> refresh = cache.backgroundRefreshFuture();
        assertThat(refresh).as("a background refresh must have been scheduled").isNotNull();
        refresh.join(); // await the refresh itself rather than guessing a duration

        assertThat(fetchCount.get()).isEqualTo(2);
    }

    @Test
    void get_serverExpiresTtl_usesMinOfConfiguredAndServer() throws Exception {
        // Server says the document expires 10s from now; the configured TTL is 300s. The
        // effective TTL must be the server's, so the cache expires at +10 rather than +300.
        AtomicInteger fetchCount = new AtomicInteger();
        TestClock clock = new TestClock();
        DocumentFetcher fetcher =
                url -> {
                    fetchCount.incrementAndGet();
                    return CompletableFuture.completedFuture(
                            new FetchResult(DOC_V1, clock.instant().getEpochSecond() + 10));
                };
        cache = cacheWith(fetcher, 300, clock);
        cache.fetch();

        clock.advanceSeconds(5); // inside both TTLs
        cache.get();
        assertThat(fetchCount.get()).as("still fresh under the server TTL").isEqualTo(1);

        clock.advanceSeconds(6); // past the server TTL, far short of the configured one
        assertThat(cache.get()).isEqualTo(DOC_V1);
        assertThat(fetchCount.get())
                .as("the server expiry, not the configured TTL, governs")
                .isEqualTo(2);
    }

    @Test
    void setOnChangeCallback_replacesCallback() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        cache = cacheWith(successFetcher(DOC_V1), 300);
        cache.setOnChangeCallback((old, next) -> calls.incrementAndGet());
        cache.fetch();
        assertThat(calls.get()).isEqualTo(0); // no change on first fetch
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /** Manually advanced clock, so TTL expiry is driven rather than waited on. */
    private static final class TestClock extends Clock {
        private final AtomicLong nowSeconds = new AtomicLong(T0);

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochSecond(nowSeconds.get());
        }

        void advanceSeconds(long seconds) {
            nowSeconds.addAndGet(seconds);
        }
    }

    private static DocumentCache cacheWith(DocumentFetcher fetcher, int ttl) {
        return new DocumentCache(fetcher, "https://example.com/jwks", ttl, "JWKS", null);
    }

    private static DocumentCache cacheWith(DocumentFetcher fetcher, int ttl, TestClock clock) {
        return cacheWith(fetcher, ttl, null, clock);
    }

    private static DocumentCache cacheWith(
            DocumentFetcher fetcher,
            int ttl,
            BiConsumer<Map<String, Object>, Map<String, Object>> onChange,
            TestClock clock) {
        return new DocumentCache(fetcher, "https://example.com/jwks", ttl, "JWKS", onChange, clock);
    }

    private static DocumentFetcher successFetcher(Map<String, Object> doc) {
        return url -> CompletableFuture.completedFuture(new FetchResult(doc, null));
    }

    private static DocumentFetcher countingFetcher(Map<String, Object> doc, AtomicInteger counter) {
        return url ->
                CompletableFuture.supplyAsync(
                        () -> {
                            counter.incrementAndGet();
                            return new FetchResult(doc, null);
                        });
    }
}
