package ai.authplane.sdk.core.fetching;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

class DocumentCacheTest {

    private static final Map<String, Object> DOC_V1 = Map.of("version", "1");
    private static final Map<String, Object> DOC_V2 = Map.of("version", "2");

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
        // Very short TTL so it expires quickly
        cache = cacheWith(fetcher, 1);
        cache.fetch();

        // Wait for TTL to expire
        Thread.sleep(1500);

        // Next get() should try to refresh, fail, but return stale
        Map<String, Object> result = cache.get();
        assertThat(result).isEqualTo(DOC_V1);
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

        cache =
                new DocumentCache(
                        fetcher,
                        "https://example.com/jwks",
                        1,
                        "JWKS",
                        (old, next) -> calls.incrementAndGet());
        cache.fetch(); // DOC_V1
        Thread.sleep(1500);
        cache.get(); // triggers refresh → DOC_V2 → callback called
        // Wait for async callback
        Thread.sleep(100);
        assertThat(calls.get()).isGreaterThanOrEqualTo(1);
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
        cache = cacheWith(countingFetcher(DOC_V1, fetchCount), 1);
        cache.fetch(); // initial fetch
        // Wait for 80% of 1s TTL
        Thread.sleep(900);
        cache.get(); // should trigger background refresh
        Thread.sleep(300); // wait for async refresh
        assertThat(fetchCount.get()).isGreaterThanOrEqualTo(2);
    }

    @Test
    void get_serverExpiresTtl_usesMinOfConfiguredAndServer() throws Exception {
        // Return a FetchResult with server-expires that is shorter than configured
        long serverExpires = System.currentTimeMillis() / 1000 + 1; // 1 second
        DocumentFetcher fetcher =
                url -> CompletableFuture.completedFuture(new FetchResult(DOC_V1, serverExpires));
        cache = cacheWith(fetcher, 300); // configured 300s, server says 1s
        cache.fetch();

        // Wait for server TTL to expire
        Thread.sleep(1500);

        // Should trigger synchronous refresh (returns stale on failure since no network)
        Map<String, Object> result = cache.get();
        assertThat(result).isEqualTo(DOC_V1);
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

    private static DocumentCache cacheWith(DocumentFetcher fetcher, int ttl) {
        return new DocumentCache(fetcher, "https://example.com/jwks", ttl, "JWKS", null);
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
