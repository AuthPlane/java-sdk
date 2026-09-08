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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

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

    /**
     * A server expiry that is not in the future is no expiry at all.
     *
     * <p>`Cache-Control: no-store` and `no-cache` parse to `0L`, `max-age=0` to `now`, and a stale
     * `Expires:` to a past epoch. Subtracting the cache timestamp from any of those gives a
     * negative TTL, which makes the document permanently expired: every read takes the synchronous
     * re-fetch branch, on the caller's thread. The failure backoff cannot help, because a
     * `no-store` endpoint that *answers* clears it and re-arms the expiry on the same call.
     *
     * <p>This matters now that verification reads through the metadata cache on every key lookup —
     * and does so before signature verification, so an unauthenticated caller would set the fetch
     * rate against the authorization server.
     */
    @Test
    void get_serverExpiryNotInTheFuture_fallsBackToTheConfiguredInterval() throws Exception {
        // 0L is what no-store and no-cache parse to; -1 stands for a stale Expires: header.
        for (long serverExpiry : new long[] {0L, -1L}) {
            AtomicInteger fetchCount = new AtomicInteger();
            TestClock clock = new TestClock();
            DocumentFetcher fetcher =
                    url -> {
                        fetchCount.incrementAndGet();
                        return CompletableFuture.completedFuture(
                                new FetchResult(DOC_V1, serverExpiry));
                    };
            cache = cacheWith(fetcher, 300, clock);
            cache.fetch();
            assertThat(fetchCount.get()).isEqualTo(1);

            for (int i = 0; i < 5; i++) {
                assertThat(cache.get()).isEqualTo(DOC_V1);
            }
            assertThat(fetchCount.get())
                    .as(
                            "server expiry %s must not make the document permanently expired",
                            serverExpiry)
                    .isEqualTo(1);

            clock.advanceSeconds(301);
            cache.get();
            assertThat(fetchCount.get())
                    .as("the configured interval still governs for server expiry %s", serverExpiry)
                    .isEqualTo(2);
        }
    }

    /**
     * A server expiry exactly at the cache timestamp is the max-age=0 case, and behaves the same.
     */
    @Test
    void get_serverExpiryEqualToCachedAt_fallsBackToTheConfiguredInterval() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger();
        TestClock clock = new TestClock();
        DocumentFetcher fetcher =
                url -> {
                    fetchCount.incrementAndGet();
                    return CompletableFuture.completedFuture(
                            new FetchResult(DOC_V1, clock.instant().getEpochSecond()));
                };
        cache = cacheWith(fetcher, 300, clock);
        cache.fetch();

        for (int i = 0; i < 5; i++) {
            cache.get();
        }
        assertThat(fetchCount.get()).as("max-age=0 must not cost a fetch per read").isEqualTo(1);
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

    // A regression here blocks rather than returning the wrong value, and in CI a hang is not
    // the same as a failure: it burns the job's wall clock and surfaces as a build timeout
    // instead of a named test. The bound turns it back into a failure that says what broke.
    @Test
    @Timeout(10)
    void get_whileARefreshIsInFlight_servesTheCurrentCopyInsteadOfQueueing() throws Exception {
        // The lock-free read is a semantic change to a public method, not a performance tweak:
        // once a refresh is in flight, get() returns the published document without honouring
        // expiry. That is deliberate — on the verification path the alternative is every caller
        // queueing behind one network round trip — but it is only exercised when fetchLock is
        // actually contended, which no single-threaded test does.
        CountDownLatch fetchStarted = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        AtomicInteger fetchCount = new AtomicInteger();
        TestClock clock = new TestClock();
        DocumentFetcher fetcher =
                url ->
                        CompletableFuture.supplyAsync(
                                () -> {
                                    if (fetchCount.incrementAndGet() > 1) {
                                        fetchStarted.countDown();
                                        try {
                                            releaseFetch.await();
                                        } catch (InterruptedException e) {
                                            Thread.currentThread().interrupt();
                                            throw new CompletionException(e);
                                        }
                                        return new FetchResult(DOC_V2, null);
                                    }
                                    return new FetchResult(DOC_V1, null);
                                });
        cache = cacheWith(fetcher, 100, clock);
        cache.fetch();

        clock.advanceSeconds(101); // expired, so the refresher below takes the synchronous branch

        Thread refresher =
                new Thread(
                        () -> {
                            try {
                                cache.get();
                            } catch (Exception e) {
                                throw new IllegalStateException(e);
                            }
                        });
        refresher.start();
        assertThat(fetchStarted.await(5, TimeUnit.SECONDS))
                .as("the refresh reached the fetcher and is holding fetchLock")
                .isTrue();

        // Returns while the refresh is still blocked — asserted by ordering rather than by a
        // timeout: releaseFetch has not been counted down yet, so a get() that queued behind the
        // lock could not have returned at all.
        assertThat(cache.get()).isEqualTo(DOC_V1);
        assertThat(fetchCount.get()).as("no second fetch was started").isEqualTo(2);

        releaseFetch.countDown();
        refresher.join(5_000);
        assertThat(refresher.isAlive()).isFalse();
        assertThat(cache.get()).isEqualTo(DOC_V2);
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
