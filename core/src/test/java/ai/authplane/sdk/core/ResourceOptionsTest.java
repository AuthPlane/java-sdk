package ai.authplane.sdk.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;

/** Unit tests for ResourceOptions and its Builder. */
class ResourceOptionsTest {

    // -----------------------------------------------------------------------
    // defaults() returns sensible defaults
    // -----------------------------------------------------------------------

    @Test
    void defaults_returnsRs256AndEs256() {
        ResourceOptions opts = ResourceOptions.defaults();
        assertThat(opts.allowedAlgorithms()).containsExactlyInAnyOrder("RS256", "ES256");
    }

    @Test
    void defaults_clockSkewIs30Seconds() {
        ResourceOptions opts = ResourceOptions.defaults();
        assertThat(opts.clockSkewSeconds()).isEqualTo(30);
    }

    @Test
    void defaults_revocationCheckerIsNull() {
        ResourceOptions opts = ResourceOptions.defaults();
        assertThat(opts.revocationChecker()).isNull();
    }

    @Test
    void defaults_useBuiltinRevocationCheckerIsFalse() {
        ResourceOptions opts = ResourceOptions.defaults();
        assertThat(opts.useBuiltinRevocationChecker()).isFalse();
    }

    // -----------------------------------------------------------------------
    // Builder allows customization
    // -----------------------------------------------------------------------

    @Test
    void builder_allowedAlgorithms_customized() {
        ResourceOptions opts =
                ResourceOptions.builder().allowedAlgorithms(List.of("RS256", "RS384")).build();
        assertThat(opts.allowedAlgorithms()).containsExactly("RS256", "RS384");
    }

    @Test
    void builder_clockSkewSeconds_customized() {
        ResourceOptions opts = ResourceOptions.builder().clockSkewSeconds(60).build();
        assertThat(opts.clockSkewSeconds()).isEqualTo(60);
    }

    @Test
    void builder_revocationChecker_customized() {
        RevocationChecker checker = (token, jti) -> false;
        ResourceOptions opts = ResourceOptions.builder().revocationChecker(checker).build();
        assertThat(opts.revocationChecker()).isSameAs(checker);
        assertThat(opts.useBuiltinRevocationChecker()).isFalse();
    }

    @Test
    void builder_useBuiltinRevocationChecker_sets_flag() {
        ResourceOptions opts = ResourceOptions.builder().useBuiltinRevocationChecker().build();
        assertThat(opts.useBuiltinRevocationChecker()).isTrue();
        assertThat(opts.revocationChecker()).isNull();
    }

    // -----------------------------------------------------------------------
    // Mutual exclusion: useBuiltinRevocationChecker + custom checker
    // -----------------------------------------------------------------------

    @Test
    void builder_builtinThenCustom_throwsIllegalState() {
        ResourceOptions.Builder builder = ResourceOptions.builder().useBuiltinRevocationChecker();

        assertThatThrownBy(() -> builder.revocationChecker((token, jti) -> false))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Built-in introspection");
    }

    @Test
    void builder_customThenBuiltin_throwsIllegalState() {
        ResourceOptions.Builder builder =
                ResourceOptions.builder().revocationChecker((token, jti) -> false);

        assertThatThrownBy(builder::useBuiltinRevocationChecker)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("custom RevocationChecker");
    }

    // -----------------------------------------------------------------------
    // allowedAlgorithms is immutable
    // -----------------------------------------------------------------------

    @Test
    void allowedAlgorithms_returnedList_isImmutable() {
        ResourceOptions opts = ResourceOptions.defaults();
        assertThatThrownBy(() -> opts.allowedAlgorithms().add("RS384"))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
