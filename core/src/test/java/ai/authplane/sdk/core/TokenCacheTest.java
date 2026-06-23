package ai.authplane.sdk.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for TokenCache.
 *
 * <p>TokenCache is package-private, so this test must be in the same package.
 */
class TokenCacheTest {

    private TokenCache cache;

    @BeforeEach
    void setUp() {
        // TTL buffer of 30 seconds, default TTL 3600s
        cache = new TokenCache(TokenCacheConfig.of(30, 3600));
    }

    // -----------------------------------------------------------------------
    // get() returns null for missing key
    // -----------------------------------------------------------------------

    @Test
    void get_missingKey_returnsNull() {
        assertThat(cache.get("nonexistent")).isNull();
    }

    // -----------------------------------------------------------------------
    // put() + get() round-trip
    // -----------------------------------------------------------------------

    @Test
    void put_thenGet_returnsToken() {
        TokenResponse response =
                new TokenResponse("access-token-123", "Bearer", 3600, List.of("read"), null);
        cache.put("key1", response);

        TokenResponse retrieved = cache.get("key1");
        assertThat(retrieved).isNotNull();
        assertThat(retrieved.accessToken()).isEqualTo("access-token-123");
        assertThat(retrieved.tokenType()).isEqualTo("Bearer");
        assertThat(retrieved.expiresIn()).isEqualTo(3600);
    }

    @Test
    void put_differentKeys_areIndependent() {
        TokenResponse resp1 = new TokenResponse("tok-1", "Bearer", 3600, null, null);
        TokenResponse resp2 = new TokenResponse("tok-2", "Bearer", 3600, null, null);

        cache.put("key1", resp1);
        cache.put("key2", resp2);

        assertThat(cache.get("key1").accessToken()).isEqualTo("tok-1");
        assertThat(cache.get("key2").accessToken()).isEqualTo("tok-2");
        assertThat(cache.size()).isEqualTo(2);
    }

    // -----------------------------------------------------------------------
    // Expired entries return null
    // -----------------------------------------------------------------------

    @Test
    void get_expiredEntry_returnsNull() {
        // expiresIn=1 with a buffer of 30 means the effective TTL is negative.
        // The token should not be cached at all.
        TokenResponse response = new TokenResponse("short-lived", "Bearer", 1, null, null);
        cache.put("short", response);

        // With a 30s buffer, a 1s token won't be cached (expiresAt <= now)
        assertThat(cache.get("short")).isNull();
    }

    // -----------------------------------------------------------------------
    // TTL buffer is applied
    // -----------------------------------------------------------------------

    @Test
    void put_ttlBuffer_isApplied() {
        // With a 30s buffer, a token with 31s expiry should be cached but
        // with only 1 second of effective cache lifetime
        TokenResponse response = new TokenResponse("buffered", "Bearer", 31, null, null);
        cache.put("buffered", response);

        // Should still be cached (31 - 30 = 1 second remaining)
        assertThat(cache.get("buffered")).isNotNull();
    }

    @Test
    void put_ttlExactlyEqualsBuffer_notCached() {
        // expiresIn = buffer means expiresAt = now → not cached
        TokenResponse response = new TokenResponse("exact", "Bearer", 30, null, null);
        cache.put("exact", response);

        assertThat(cache.get("exact")).isNull();
    }

    @Test
    void put_ttlLessThanBuffer_notCached() {
        TokenResponse response = new TokenResponse("too-short", "Bearer", 10, null, null);
        cache.put("too-short", response);

        assertThat(cache.get("too-short")).isNull();
    }

    // -----------------------------------------------------------------------
    // Tokens without usable expires_in use the default TTL
    // -----------------------------------------------------------------------

    @Test
    void put_nullExpiresIn_usesDefaultTtl() {
        TokenResponse response = new TokenResponse("no-expiry", "Bearer", null, null, null);
        cache.put("no-expiry", response);

        assertThat(cache.get("no-expiry")).isNotNull();
        assertThat(cache.size()).isEqualTo(1);
    }

    @Test
    void put_zeroExpiresIn_usesDefaultTtl() {
        TokenResponse response = new TokenResponse("zero-expiry", "Bearer", 0, null, null);
        cache.put("zero-expiry", response);

        assertThat(cache.get("zero-expiry")).isNotNull();
    }

    @Test
    void put_negativeExpiresIn_usesDefaultTtl() {
        TokenResponse response = new TokenResponse("negative-expiry", "Bearer", -1, null, null);
        cache.put("negative-expiry", response);

        assertThat(cache.get("negative-expiry")).isNotNull();
    }

    @Test
    void put_nullExpiresIn_usesDefaultTtlWhenConfigured() {
        TokenCache cacheWithDefaultTtl = new TokenCache(TokenCacheConfig.of(30, 120));
        TokenResponse response = new TokenResponse("default-expiry", "Bearer", null, null, null);

        cacheWithDefaultTtl.put("default-expiry", response);

        assertThat(cacheWithDefaultTtl.get("default-expiry")).isNotNull();
    }

    @Test
    void put_zeroExpiresIn_usesDefaultTtlWhenConfigured() {
        TokenCache cacheWithDefaultTtl = new TokenCache(TokenCacheConfig.of(30, 120));
        TokenResponse response = new TokenResponse("zero-default-expiry", "Bearer", 0, null, null);

        cacheWithDefaultTtl.put("zero-default-expiry", response);

        assertThat(cacheWithDefaultTtl.get("zero-default-expiry")).isNotNull();
    }

    @Test
    void put_defaultTtlShorterThanBuffer_notCached() {
        TokenCache cacheWithShortDefaultTtl = new TokenCache(TokenCacheConfig.of(30, 20));
        TokenResponse response =
                new TokenResponse("short-default-expiry", "Bearer", null, null, null);

        cacheWithShortDefaultTtl.put("short-default-expiry", response);

        assertThat(cacheWithShortDefaultTtl.get("short-default-expiry")).isNull();
    }

    // -----------------------------------------------------------------------
    // clear() removes all entries
    // -----------------------------------------------------------------------

    @Test
    void get_entryThatExpiresWhileCached_isEvictedOnAccess() throws Exception {
        // 32s expiry with 30s buffer → effective cache TTL is 2s.
        // Wait > 2s, then get(): the `now >= cached.expiresAt` branch fires
        // and the entry is removed from the map. Covers the expired-entry
        // eviction path in get() that the synchronous tests above miss.
        TokenResponse response = new TokenResponse("ttl-2s", "Bearer", 32, null, null);
        cache.put("ttl-2s", response);
        assertThat(cache.get("ttl-2s")).isNotNull();

        Thread.sleep(2_500);

        assertThat(cache.get("ttl-2s")).isNull();
        assertThat(cache.size()).isEqualTo(0);
    }

    @Test
    void clear_removesAllEntries() {
        cache.put("a", new TokenResponse("tok-a", "Bearer", 3600, null, null));
        cache.put("b", new TokenResponse("tok-b", "Bearer", 3600, null, null));
        assertThat(cache.size()).isEqualTo(2);

        cache.clear();

        assertThat(cache.size()).isEqualTo(0);
        assertThat(cache.get("a")).isNull();
        assertThat(cache.get("b")).isNull();
    }

    // -----------------------------------------------------------------------
    // Bounded LRU eviction
    // -----------------------------------------------------------------------

    @Test
    void put_overCapacity_boundsSize() {
        TokenCache bounded = new TokenCache(new TokenCacheConfig(30, 3600, 3));
        for (int i = 0; i < 10; i++) {
            bounded.put("key-" + i, new TokenResponse("tok-" + i, "Bearer", 3600, null, null));
        }
        assertThat(bounded.size()).isEqualTo(3);
    }

    @Test
    void put_overCapacity_evictsLeastRecentlyUsed() {
        TokenCache bounded = new TokenCache(new TokenCacheConfig(30, 3600, 2));
        bounded.put("a", new TokenResponse("tok-a", "Bearer", 3600, null, null));
        bounded.put("b", new TokenResponse("tok-b", "Bearer", 3600, null, null));

        // Touch "a" so "b" becomes the least-recently-used entry.
        assertThat(bounded.get("a")).isNotNull();

        bounded.put("c", new TokenResponse("tok-c", "Bearer", 3600, null, null));

        assertThat(bounded.size()).isEqualTo(2);
        assertThat(bounded.get("a")).isNotNull();
        assertThat(bounded.get("c")).isNotNull();
        assertThat(bounded.get("b")).isNull();
    }
}
