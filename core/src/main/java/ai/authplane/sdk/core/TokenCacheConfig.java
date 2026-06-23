package ai.authplane.sdk.core;

/**
 * Configuration for the in-process OAuth token cache.
 *
 * <p>The cache stores the SDK's own outbound tokens (client-credentials and token-exchange
 * results), keyed by request parameters. It is bounded: at most {@link #maxEntries()} entries are
 * retained, evicting the least-recently-used entry when full, in addition to time-based expiry
 * driven by {@link #ttlBufferSeconds()} and {@link #defaultTtlSeconds()}.
 *
 * @param ttlBufferSeconds evict cached tokens this many seconds before their actual expiry; must
 *     not be negative
 * @param defaultTtlSeconds fallback TTL applied when the AS response omits {@code expires_in}; must
 *     be positive
 * @param maxEntries maximum number of cached tokens before least-recently-used eviction kicks in;
 *     must be positive
 */
public record TokenCacheConfig(int ttlBufferSeconds, int defaultTtlSeconds, int maxEntries) {

    /** Default TTL buffer (seconds) applied before a token's actual expiry. */
    public static final int DEFAULT_TTL_BUFFER_SECONDS = 30;

    /** Default fallback TTL (seconds) when {@code expires_in} is absent. */
    public static final int DEFAULT_TTL_SECONDS = 3600;

    /** Default maximum number of cached tokens. */
    public static final int DEFAULT_MAX_ENTRIES = 10_000;

    /** Validates that all values are within acceptable bounds. */
    public TokenCacheConfig {
        if (ttlBufferSeconds < 0) {
            throw new IllegalArgumentException(
                    "ttlBufferSeconds must not be negative, got " + ttlBufferSeconds);
        }
        if (defaultTtlSeconds <= 0) {
            throw new IllegalArgumentException(
                    "defaultTtlSeconds must be positive, got " + defaultTtlSeconds);
        }
        if (maxEntries <= 0) {
            throw new IllegalArgumentException("maxEntries must be positive, got " + maxEntries);
        }
    }

    /** Returns the default configuration. */
    public static TokenCacheConfig defaults() {
        return new TokenCacheConfig(
                DEFAULT_TTL_BUFFER_SECONDS, DEFAULT_TTL_SECONDS, DEFAULT_MAX_ENTRIES);
    }

    /**
     * Convenience factory using the default {@link #DEFAULT_MAX_ENTRIES} capacity.
     *
     * @param ttlBufferSeconds evict cached tokens this many seconds before expiry
     * @param defaultTtlSeconds fallback TTL when {@code expires_in} is absent
     * @return a configuration with default maxEntries
     */
    public static TokenCacheConfig of(int ttlBufferSeconds, int defaultTtlSeconds) {
        return new TokenCacheConfig(ttlBufferSeconds, defaultTtlSeconds, DEFAULT_MAX_ENTRIES);
    }
}
