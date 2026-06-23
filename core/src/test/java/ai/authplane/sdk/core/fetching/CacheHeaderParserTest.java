package ai.authplane.sdk.core.fetching;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** Unit tests for CacheHeaderParser — RFC 7234 cache header parsing. */
class CacheHeaderParserTest {

    // -----------------------------------------------------------------------
    // No headers
    // -----------------------------------------------------------------------

    @Test
    void parseExpiresAt_noHeaders_returnsNull() {
        assertThat(CacheHeaderParser.parseExpiresAt(Map.of())).isNull();
    }

    @Test
    void parseExpiresAt_unrelatedHeaders_returnsNull() {
        assertThat(CacheHeaderParser.parseExpiresAt(Map.of("content-type", "application/json")))
                .isNull();
    }

    // -----------------------------------------------------------------------
    // Cache-Control: no-store / no-cache
    // -----------------------------------------------------------------------

    @Test
    void parseExpiresAt_noStore_returnsZero() {
        Long result = CacheHeaderParser.parseExpiresAt(Map.of("cache-control", "no-store"));
        assertThat(result).isEqualTo(0L);
    }

    @Test
    void parseExpiresAt_noCache_returnsZero() {
        Long result = CacheHeaderParser.parseExpiresAt(Map.of("cache-control", "no-cache"));
        assertThat(result).isEqualTo(0L);
    }

    @Test
    void parseExpiresAt_noCacheUpperCase_returnsZero() {
        Long result = CacheHeaderParser.parseExpiresAt(Map.of("cache-control", "NO-CACHE"));
        assertThat(result).isEqualTo(0L);
    }

    @Test
    void parseExpiresAt_noStoreWithOtherDirectives_returnsZero() {
        Long result =
                CacheHeaderParser.parseExpiresAt(
                        Map.of("cache-control", "public, no-store, max-age=300"));
        assertThat(result).isEqualTo(0L);
    }

    // -----------------------------------------------------------------------
    // Cache-Control: max-age
    // -----------------------------------------------------------------------

    @Test
    void parseExpiresAt_maxAge300_returnsNowPlus300() {
        long before = System.currentTimeMillis() / 1000L;
        Long result = CacheHeaderParser.parseExpiresAt(Map.of("cache-control", "max-age=300"));
        long after = System.currentTimeMillis() / 1000L;
        assertThat(result).isBetween(before + 300, after + 300);
    }

    @Test
    void parseExpiresAt_maxAge3600_returnsNowPlus3600() {
        long before = System.currentTimeMillis() / 1000L;
        Long result = CacheHeaderParser.parseExpiresAt(Map.of("cache-control", "max-age=3600"));
        long after = System.currentTimeMillis() / 1000L;
        assertThat(result).isBetween(before + 3600, after + 3600);
    }

    @Test
    void parseExpiresAt_maxAgeWithPublicDirective_returnsNowPlusMaxAge() {
        long before = System.currentTimeMillis() / 1000L;
        Long result =
                CacheHeaderParser.parseExpiresAt(Map.of("cache-control", "public, max-age=600"));
        long after = System.currentTimeMillis() / 1000L;
        assertThat(result).isBetween(before + 600, after + 600);
    }

    @Test
    void parseExpiresAt_maxAgeWithCommaSuffix_returnsNowPlusMaxAge() {
        long before = System.currentTimeMillis() / 1000L;
        Long result =
                CacheHeaderParser.parseExpiresAt(
                        Map.of("cache-control", "max-age=900, must-revalidate"));
        long after = System.currentTimeMillis() / 1000L;
        assertThat(result).isBetween(before + 900, after + 900);
    }

    @Test
    void parseExpiresAt_maxAgeZero_returnsNow() {
        long before = System.currentTimeMillis() / 1000L;
        Long result = CacheHeaderParser.parseExpiresAt(Map.of("cache-control", "max-age=0"));
        long after = System.currentTimeMillis() / 1000L;
        assertThat(result).isBetween(before, after);
    }

    @Test
    void parseExpiresAt_invalidMaxAge_returnsNull() {
        assertThat(CacheHeaderParser.parseExpiresAt(Map.of("cache-control", "max-age=abc")))
                .isNull();
    }

    @Test
    void parseExpiresAt_maxAgeUppercase_returnsNowPlusValue() {
        // Cache-Control is case-insensitive; the header name is already lowercased by the caller
        long before = System.currentTimeMillis() / 1000L;
        Long result = CacheHeaderParser.parseExpiresAt(Map.of("cache-control", "MAX-AGE=120"));
        long after = System.currentTimeMillis() / 1000L;
        // the implementation lowercases the value before searching, so max-age=120 is found
        assertThat(result).isBetween(before + 120, after + 120);
    }

    // -----------------------------------------------------------------------
    // Expires header
    // -----------------------------------------------------------------------

    @Test
    void parseExpiresAt_validExpiresHeader_returnsEpochSecond() {
        // Build the date programmatically to avoid hardcoding the wrong day-of-week
        ZonedDateTime future = ZonedDateTime.of(2099, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC);
        String headerValue = DateTimeFormatter.RFC_1123_DATE_TIME.format(future);
        Map<String, String> headers = Map.of("expires", headerValue);

        Long result = CacheHeaderParser.parseExpiresAt(headers);
        assertThat(result).isEqualTo(future.toEpochSecond());
    }

    @Test
    void parseExpiresAt_invalidExpiresHeader_returnsNull() {
        assertThat(CacheHeaderParser.parseExpiresAt(Map.of("expires", "not-a-date"))).isNull();
    }

    @Test
    void parseExpiresAt_emptyExpiresHeader_returnsNull() {
        assertThat(CacheHeaderParser.parseExpiresAt(Map.of("expires", ""))).isNull();
    }

    // -----------------------------------------------------------------------
    // Cache-Control takes priority over Expires
    // -----------------------------------------------------------------------

    @Test
    void parseExpiresAt_cacheControlTakesPriorityOverExpires() {
        long before = System.currentTimeMillis() / 1000L;
        ZonedDateTime farFuture = ZonedDateTime.of(2099, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC);
        String expiresValue = DateTimeFormatter.RFC_1123_DATE_TIME.format(farFuture);

        Map<String, String> headers =
                Map.of("cache-control", "max-age=300", "expires", expiresValue);
        Long result = CacheHeaderParser.parseExpiresAt(headers);
        long after = System.currentTimeMillis() / 1000L;

        // Should return max-age=300 result, not the 2099 Expires value
        assertThat(result).isBetween(before + 300, after + 300);
    }
}
