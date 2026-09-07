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
 * fetch failure, the stale document is returned (if available) and the next network attempt is
 * suppressed for a short backoff.
 *
 * <p>Thread-safe. The ReentrantLock prevents concurrent fetch storms, and {@link #get()} never
 * waits on it once a document is cached — see that method.
 */
public class DocumentCache {

    private static final Logger LOG = Logger.getLogger(DocumentCache.class.getName());

    /** Background refreshes start at this fraction of the effective TTL. */
    private static final double REFRESH_THRESHOLD = 0.80;

    /**
     * Upper bound on how long a failed refresh suppresses the next network attempt.
     *
     * <p>{@link #doFetch} advances {@code cachedAtEpochSeconds} only on success, so against an
     * endpoint that is down — or one returning a document {@link #validateFetched} rejects — the
     * cached copy stays permanently expired and every {@link #get()} would otherwise take the
     * synchronous branch: one full HTTP timeout per call. That is invisible while nothing on a
     * request path reads the cache, and is not once something does ({@code
     * AuthplaneClient.refreshMetadataIfDue}). Bounding the retry rate keeps a stale-but-serviceable
     * document cheap to read.
     */
    private static final int FAILURE_BACKOFF_SECONDS = 30;

    private final DocumentFetcher fetcher;
    private final String url;
    private final int configuredRefreshSeconds;
    private final String documentType; // "JWKS" or "metadata" — for log messages
    private final Clock clock;
    private volatile BiConsumer<Map<String, Object>, Map<String, Object>> onChangeCallback;

    private final ReentrantLock fetchLock = new ReentrantLock();

    // Written under fetchLock. Volatile so get() can serve it without waiting for a fetch that
    // another thread is already performing.
    private volatile Map<String, Object> cachedDocument;

    // Guarded by fetchLock
    private long cachedAtEpochSeconds; // when the current cache was stored
    private Long serverExpiresAtSeconds; // from HTTP cache headers, or null
    private long retryNotBeforeEpochSeconds; // set after a failed refresh; 0 = no backoff

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
     * document exists, returns stale and suppresses the next attempt for {@value
     * #FAILURE_BACKOFF_SECONDS} seconds (or the configured interval, whichever is shorter).
     *
     * <p>Once a document is cached this never blocks on another thread's fetch: if {@code
     * fetchLock} is held it returns the copy currently published instead of queueing behind a
     * network round trip. Callers on a request path — verification reads through the metadata cache
     * before every key lookup — would otherwise serialize on an exclusive lock for the length of an
     * HTTP timeout. The uncontended path is unchanged.
     *
     * @throws Exception if the document is expired, no stale exists, and fetch fails
     */
    public Map<String, Object> get() throws Exception {
        Map<String, Object> current = cachedDocument;
        if (current == null) {
            fetchLock.lock();
        } else if (!fetchLock.tryLock()) {
            LOG.fine(() -> documentType + " refresh in flight elsewhere; serving the current copy");
            return current;
        }
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

            if (now < retryNotBeforeEpochSeconds) {
                LOG.fine(
                        () ->
                                documentType
                                        + " refresh backing off after a failed attempt (retry in "
                                        + (retryNotBeforeEpochSeconds - now)
                                        + "s); serving the cached copy");
            } else if (age >= effectiveTtl) {
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

    /**
     * Validation hook for subclasses, applied to a freshly fetched document before it is published
     * to the cache and before the change callback sees it. The default implementation accepts
     * everything.
     *
     * <p>Rejecting here rather than at read time is what keeps a bad refresh from displacing a good
     * document: the previously cached copy stays in place and, where a stale fallback is permitted,
     * keeps being served. It also means a listener wired to the change callback — jwks_uri
     * rotation, say — is only ever handed a document that passed validation.
     *
     * @param document the freshly fetched document
     * @throws Exception to reject the document
     */
    protected void validateFetched(Map<String, Object> document) throws Exception {}

    /** Must be called with fetchLock held. */
    private void doFetch(boolean allowStaleOnFailure) throws Exception {
        try {
            FetchResult result = fetcher.fetch(url).get(); // blocks until done
            validateFetched(result.document());

            Map<String, Object> oldDoc = cachedDocument;
            cachedDocument = result.document();
            cachedAtEpochSeconds = nowEpochSeconds();
            serverExpiresAtSeconds = result.expiresAt();
            retryNotBeforeEpochSeconds = 0;

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
            retryNotBeforeEpochSeconds = nowEpochSeconds() + failureBackoffSeconds();
            if (allowStaleOnFailure && cachedDocument != null) {
                LOG.log(
                        Level.WARNING,
                        "Failed to refresh "
                                + documentType
                                + " from "
                                + url
                                + "; using stale cache for up to "
                                + failureBackoffSeconds()
                                + "s before retrying",
                        e);
            } else {
                throw e;
            }
        }
    }

    /**
     * Backoff applied after a failed refresh, never longer than the configured interval — a cache
     * asked to refresh every 5 seconds must not be pinned to a 30-second retry floor.
     *
     * <p>Exposed as a static so the one caller outside this class that retries a network operation
     * on the verification path — the {@code jwks_uri} rebind in {@code AuthplaneClient}, which
     * builds a fresh cache per attempt and so has no instance state to carry a backoff on — applies
     * the same policy rather than a second copy of it.
     *
     * @param configuredRefreshSeconds the refresh interval the backoff is being applied to
     * @return seconds to wait before the next attempt, at least 1
     */
    public static long failureBackoffSeconds(long configuredRefreshSeconds) {
        return Math.max(1, Math.min(FAILURE_BACKOFF_SECONDS, configuredRefreshSeconds));
    }

    private long failureBackoffSeconds() {
        return failureBackoffSeconds(configuredRefreshSeconds);
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
