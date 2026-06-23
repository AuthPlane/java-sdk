package ai.authplane.sdk.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class TokenCacheConfigTest {

    @Test
    void defaults_haveExpectedValues() {
        TokenCacheConfig config = TokenCacheConfig.defaults();
        assertThat(config.ttlBufferSeconds()).isEqualTo(30);
        assertThat(config.defaultTtlSeconds()).isEqualTo(3600);
        assertThat(config.maxEntries()).isEqualTo(10_000);
    }

    @Test
    void of_usesDefaultMaxEntries() {
        TokenCacheConfig config = TokenCacheConfig.of(15, 120);
        assertThat(config.ttlBufferSeconds()).isEqualTo(15);
        assertThat(config.defaultTtlSeconds()).isEqualTo(120);
        assertThat(config.maxEntries()).isEqualTo(TokenCacheConfig.DEFAULT_MAX_ENTRIES);
    }

    @Test
    void negativeTtlBuffer_rejected() {
        assertThatThrownBy(() -> new TokenCacheConfig(-1, 3600, 10))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ttlBufferSeconds must not be negative");
    }

    @Test
    void nonPositiveDefaultTtl_rejected() {
        assertThatThrownBy(() -> new TokenCacheConfig(30, 0, 10))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("defaultTtlSeconds must be positive");
    }

    @Test
    void nonPositiveMaxEntries_rejected() {
        assertThatThrownBy(() -> new TokenCacheConfig(30, 3600, 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maxEntries must be positive");
    }

    @Test
    void zeroTtlBuffer_allowed() {
        TokenCacheConfig config = new TokenCacheConfig(0, 3600, 10);
        assertThat(config.ttlBufferSeconds()).isEqualTo(0);
    }
}
