package ai.authplane.sdk.core.dpop;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class DPoPProofOptionsTest {

    @Test
    void defaults_returnsEmptyStrings() {
        DPoPProofOptions opts = DPoPProofOptions.defaults();
        assertThat(opts.nonce()).isEmpty();
        assertThat(opts.accessToken()).isEmpty();
    }

    @Test
    void constructor_normalizesNullNonceToEmpty() {
        DPoPProofOptions opts = new DPoPProofOptions(null, "token");
        assertThat(opts.nonce()).isEmpty();
        assertThat(opts.accessToken()).isEqualTo("token");
    }

    @Test
    void constructor_normalizesNullAccessTokenToEmpty() {
        DPoPProofOptions opts = new DPoPProofOptions("nonce-x", null);
        assertThat(opts.nonce()).isEqualTo("nonce-x");
        assertThat(opts.accessToken()).isEmpty();
    }

    @Test
    void constructor_normalizesBothNullsToEmpty() {
        DPoPProofOptions opts = new DPoPProofOptions(null, null);
        assertThat(opts.nonce()).isEmpty();
        assertThat(opts.accessToken()).isEmpty();
    }

    @Test
    void constructor_preservesNonNullValues() {
        DPoPProofOptions opts = new DPoPProofOptions("n", "at");
        assertThat(opts.nonce()).isEqualTo("n");
        assertThat(opts.accessToken()).isEqualTo("at");
    }
}
