package ai.authplane.sdk.core;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * In-memory cache for OAuth token responses with a TTL buffer and a bounded, least-recently-used
 * eviction policy.
 *
 * <p>Package-private — internal component used by {@link AuthplaneClient}. Configured via {@link
 * TokenCacheConfig}.
 */
final class TokenCache {

    private static final Logger LOG = Logger.getLogger(TokenCache.class.getName());

    private final int ttlBufferSeconds;
    private final int defaultTtlSeconds;
    private final Map<String, CachedToken> cache;

    TokenCache(TokenCacheConfig config) {
        this.ttlBufferSeconds = config.ttlBufferSeconds();
        this.defaultTtlSeconds = config.defaultTtlSeconds();
        int maxEntries = config.maxEntries();
        // Access-ordered LinkedHashMap evicts the least-recently-used entry once the size
        // exceeds maxEntries (via removeEldestEntry below). This must stay a synchronized
        // LinkedHashMap, NOT a ConcurrentHashMap: ConcurrentHashMap has no access ordering and
        // no removeEldestEntry hook, so swapping it in to reduce lock contention would silently
        // drop the LRU bound. The single-monitor cost is irrelevant here — the cache is touched
        // at AS-call cadence, not per request.
        this.cache =
                Collections.synchronizedMap(
                        new LinkedHashMap<>(16, 0.75f, true) {
                            @Override
                            protected boolean removeEldestEntry(
                                    Map.Entry<String, CachedToken> eldest) {
                                // Strictly greater-than: the put that overflows is already in, so
                                // the map briefly holds maxEntries+1 before evicting the eldest,
                                // capping at maxEntries. Do NOT change to >= — that caps at
                                // maxEntries-1 and breaks the configured bound.
                                return size() > maxEntries;
                            }
                        });
    }

    /**
     * Returns a cached token for the given cache key, or null if not cached or expired.
     *
     * <p>Evicting an expired entry is a deliberately non-atomic get-then-remove: the backing
     * synchronized map locks each call individually, but the eviction uses {@code remove(key,
     * cached)} (conditional compare-and-remove), so a concurrent {@link #put} of a fresh token is
     * never clobbered. The only effect of a race is two callers briefly seeing the same expired
     * entry — both return null, which is correct. Don't build an atomicity invariant on this
     * method.
     */
    TokenResponse get(String key) {
        CachedToken cached = cache.get(key);
        if (cached == null) return null;
        long now = System.currentTimeMillis() / 1000L;
        if (now >= cached.expiresAt) {
            cache.remove(key, cached);
            LOG.fine(() -> "Token cache miss (expired) for key: " + key);
            return null;
        }
        LOG.fine(() -> "Token cache hit for key: " + key);
        return cached.response;
    }

    /** Caches a token response using its expires_in to compute the expiry. */
    void put(String key, TokenResponse response) {
        long now = System.currentTimeMillis() / 1000L;
        int expiresIn = response.expiresIn() != null ? response.expiresIn() : 0;
        long ttlSeconds = expiresIn > 0 ? expiresIn : defaultTtlSeconds;
        long expiresAt = now + ttlSeconds - ttlBufferSeconds;
        if (expiresAt <= now) {
            LOG.fine(() -> "Token TTL too short to cache for key: " + key);
            return;
        }
        cache.put(key, new CachedToken(response, expiresAt));
        LOG.fine(() -> "Cached token for key: " + key + " (expires in " + (expiresAt - now) + "s)");
    }

    void clear() {
        cache.clear();
    }

    int size() {
        return cache.size();
    }

    private record CachedToken(TokenResponse response, long expiresAt) {}
}
