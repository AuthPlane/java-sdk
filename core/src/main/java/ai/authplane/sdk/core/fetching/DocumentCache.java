package ai.authplane.sdk.core.fetching;

import java.time.Clock;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Thread-safe TTL cache for a single JSON document (JWKS or OAuth metadata).
 *
 * <p>Lifecycle: 1. Call fetch() to populate the cache for the first time. 2. Subsequent get() calls
 * return the cached document. 3. At 80% of effective TTL, a background refresh is fired
 * asynchronously via the common ForkJoinPool (daemon threads — no explicit shutdown needed). 4. On
 * fetch failure, the stale document is returned (if available).
 *
 * <p>Thread-safe. The ReentrantLock prevents concurrent fetch storms.
 */
public class DocumentCache {

    private static final Logger LOG = Logger.getLogger(DocumentCache.class.getName());

    /** Background refreshes start at this fraction of the effective TTL. */
    private static final double REFRESH_THRESHOLD = 0.80;

    private final DocumentFetcher fetcher;
    private final String url;
    private final int configuredRefreshSeconds;
    private final String documentType; // "JWKS" or "metadata" — for log messages
    private final Clock clock;
    private volatile BiConsumer<Map<String, Object>, Map<String, Object>> onChangeCallback;

    private final ReentrantLock fetchLock = new ReentrantLock();

    // Guarded by fetchLock
    private Map<String, Object> cachedDocument;
    private long cachedAtEpochSeconds; // when the current cache was stored
    private Long serverExpiresAtSeconds; // from HTTP cache headers, or null

    // Written under fetchLock; volatile so the package-private accessor can read it without
    // taking fetchLock.
    private volatile CompletableFuture<Void> bgRefreshFuture;

    /**
     * @param fetcher document fetcher (SSRF-safe or direct)
     * @param url the URL to fetch
     * @param configuredRefreshSeconds configured TTL in seconds (upper bound)
     * @param documentType "JWKS" or "metadata" for log messages
     * @param onChangeCallback called with (oldDoc, newDoc) when document changes; may be null
     */
    public DocumentCache(
            DocumentFetcher fetcher,
            String url,
            int configuredRefreshSeconds,
            String documentType,
            BiConsumer<Map<String, Object>, Map<String, Object>> onChangeCallback) {

        this(
                fetcher,
                url,
                configuredRefreshSeconds,
                documentType,
                onChangeCallback,
                Clock.systemUTC());
    }

    /**
     * Test seam. Same as the public constructor, but with the time source injected so TTL expiry
     * can be driven by advancing a clock rather than by sleeping against wall time — the difference
     * between a deterministic assertion and a race with the CI runner.
     *
     * <p>The seam is {@link Clock} rather than a {@code LongSupplier} of epoch seconds, even though
     * this class represents time as {@code long} epoch seconds throughout. {@code Clock} is the
     * platform idiom, it composes ({@code Clock.fixed}, {@code Clock.offset}), and the conversion
     * cost is one call in {@code nowEpochSeconds()} — not one per use site. Several other classes
     * in the SDK still read the wall clock directly and will want the same seam; this is the shape
     * to copy.
     *
     * @param clock the time source
     */
    DocumentCache(
            DocumentFetcher fetcher,
            String url,
            int configuredRefreshSeconds,
            String documentType,
            BiConsumer<Map<String, Object>, Map<String, Object>> onChangeCallback,
            Clock clock) {

        this.fetcher = fetcher;
        this.url = url;
        this.configuredRefreshSeconds = configuredRefreshSeconds;
        this.documentType = documentType;
        this.onChangeCallback = onChangeCallback;
        this.clock = clock;
    }

    /** Returns the URL this cache fetches from. */
    public String getUrl() {
        return url;
    }

    /** Sets or replaces the callback invoked when the document changes. */
    public void setOnChangeCallback(BiConsumer<Map<String, Object>, Map<String, Object>> callback) {
        this.onChangeCallback = callback;
    }

    /**
     * Performs the initial fetch. Must be called once before get().
     *
     * @throws Exception if the fetch fails (no stale cache to fall back on)
     */
    public void fetch() throws Exception {
        fetchLock.lock();
        try {
            doFetch(false);
        } finally {
            fetchLock.unlock();
        }
    }

    /**
     * Returns the cached document, triggering a background refresh if at 80% of TTL. If the
     * document has fully expired, performs a synchronous refresh. If the refresh fails and a stale
     * document exists, returns stale.
     *
     * @throws Exception if the document is expired, no stale exists, and fetch fails
     */
    public Map<String, Object> get() throws Exception {
        fetchLock.lock();
        try {
            if (cachedDocument == null) {
                // No cache at all — must fetch now
                doFetch(false);
                return cachedDocument;
            }

            long now = nowEpochSeconds();
            long effectiveTtl = effectiveTtlSeconds();
            long age = now - cachedAtEpochSeconds;
            double fraction = effectiveTtl > 0 ? (double) age / effectiveTtl : 1.0;

            if (age >= effectiveTtl) {
                // Fully expired — refresh now
                LOG.fine(() -> documentType + " cache expired, refreshing synchronously");
                doFetch(true); // true = allow stale on failure
            } else if (fraction >= REFRESH_THRESHOLD && !backgroundRefreshScheduled()) {
                // At 80% — schedule background refresh (non-blocking)
                scheduleBackgroundRefresh();
                LOG.fine(
                        () ->
                                documentType
                                        + " cache at "
                                        + String.format("%.0f%%", fraction * 100)
                                        + " TTL, scheduled background refresh");
            } else {
                LOG.fine(
                        () ->
                                documentType
                                        + " cache hit (age="
                                        + age
                                        + "s / ttl="
                                        + effectiveTtl
                                        + "s)");
            }

            return cachedDocument;
        } finally {
            fetchLock.unlock();
        }
    }

    /** Forces a cache refresh regardless of TTL. */
    public Map<String, Object> forceRefresh() throws Exception {
        fetchLock.lock();
        try {
            doFetch(true);
            return cachedDocument;
        } finally {
            fetchLock.unlock();
        }
    }

    // -----------------------------------------------------------------------
    // Internal

    /** Must be called with fetchLock held. */
    private void doFetch(boolean allowStaleOnFailure) throws Exception {
        try {
            FetchResult result = fetcher.fetch(url).get(); // blocks until done

            Map<String, Object> oldDoc = cachedDocument;
            cachedDocument = result.document();
            cachedAtEpochSeconds = nowEpochSeconds();
            serverExpiresAtSeconds = result.expiresAt();

            LOG.info(
                    () ->
                            documentType
                                    + " fetched from "
                                    + url
                                    + " (effective TTL="
                                    + effectiveTtlSeconds()
                                    + "s)");

            // Notify on change
            if (onChangeCallback != null && oldDoc != null && !oldDoc.equals(cachedDocument)) {
                try {
                    onChangeCallback.accept(oldDoc, cachedDocument);
                } catch (Exception e) {
                    LOG.log(Level.WARNING, documentType + " change callback threw", e);
                }
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw e;
        } catch (Exception e) {
            if (allowStaleOnFailure && cachedDocument != null) {
                LOG.log(
                        Level.WARNING,
                        "Failed to refresh "
                                + documentType
                                + " from "
                                + url
                                + "; using stale cache",
                        e);
            } else {
                throw e;
            }
        }
    }

    private long effectiveTtlSeconds() {
        long configuredExpiry = cachedAtEpochSeconds + configuredRefreshSeconds;
        if (serverExpiresAtSeconds != null) {
            return Math.min(configuredExpiry, serverExpiresAtSeconds) - cachedAtEpochSeconds;
        }
        return configuredRefreshSeconds;
    }

    private boolean backgroundRefreshScheduled() {
        return bgRefreshFuture != null && !bgRefreshFuture.isDone();
    }

    /**
     * Test seam: the in-flight background refresh, or {@code null} if none has been scheduled. Lets
     * a test await the refresh it just triggered instead of guessing how long the async fetch will
     * take.
     */
    CompletableFuture<Void> backgroundRefreshFuture() {
        return bgRefreshFuture;
    }

    private void scheduleBackgroundRefresh() {
        bgRefreshFuture =
                CompletableFuture.runAsync(
                        () -> {
                            fetchLock.lock();
                            try {
                                doFetch(true);
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                            } catch (Exception e) {
                                LOG.log(
                                        Level.WARNING,
                                        "Background refresh of " + documentType + " failed",
                                        e);
                            } finally {
                                fetchLock.unlock();
                            }
                        });
    }

    private long nowEpochSeconds() {
        return clock.instant().getEpochSecond();
    }
}
