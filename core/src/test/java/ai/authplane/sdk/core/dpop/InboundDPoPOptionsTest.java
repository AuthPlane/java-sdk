package ai.authplane.sdk.core.dpop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Set;

import org.junit.jupiter.api.Test;

class InboundDPoPOptionsTest {

    @Test
    void defaults_uses300sMaxAgeAnd30sSkew() {
        InboundDPoPOptions opts = InboundDPoPOptions.defaults(new InMemoryDPoPReplayStore());
        assertThat(opts.maxProofAgeSeconds()).isEqualTo(300);
        assertThat(opts.clockSkewSeconds()).isEqualTo(30);
        assertThat(opts.allowedProofAlgorithms()).containsExactlyInAnyOrder("RS256", "ES256");
    }

    @Test
    void constructor_rejectsNullReplayStore() {
        assertThatThrownBy(() -> new InboundDPoPOptions(null, 300, 30, Set.of("RS256", "ES256")))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("replayStore");
    }

    @Test
    void constructor_rejectsZeroMaxProofAge() {
        assertThatThrownBy(
                        () ->
                                new InboundDPoPOptions(
                                        new InMemoryDPoPReplayStore(), 0, 30, Set.of("RS256")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maxProofAgeSeconds must be positive");
    }

    @Test
    void constructor_rejectsNegativeMaxProofAge() {
        assertThatThrownBy(
                        () ->
                                new InboundDPoPOptions(
                                        new InMemoryDPoPReplayStore(), -1, 30, Set.of("RS256")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void constructor_acceptsZeroClockSkew() {
        InboundDPoPOptions opts =
                new InboundDPoPOptions(new InMemoryDPoPReplayStore(), 300, 0, Set.of("RS256"));
        assertThat(opts.clockSkewSeconds()).isZero();
    }

    @Test
    void constructor_rejectsNegativeClockSkew() {
        assertThatThrownBy(
                        () ->
                                new InboundDPoPOptions(
                                        new InMemoryDPoPReplayStore(), 300, -1, Set.of("RS256")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("clockSkewSeconds");
    }

    @Test
    void constructor_substitutesDefaultsForNullAlgorithms() {
        InboundDPoPOptions opts =
                new InboundDPoPOptions(new InMemoryDPoPReplayStore(), 300, 30, null);
        assertThat(opts.allowedProofAlgorithms()).containsExactlyInAnyOrder("RS256", "ES256");
    }

    @Test
    void constructor_rejectsEmptyAlgorithms() {
        assertThatThrownBy(
                        () ->
                                new InboundDPoPOptions(
                                        new InMemoryDPoPReplayStore(), 300, 30, Set.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("non-empty");
    }

    @Test
    void constructor_rejectsUnsafeAlgorithms() {
        assertThatThrownBy(
                        () ->
                                new InboundDPoPOptions(
                                        new InMemoryDPoPReplayStore(), 300, 30, Set.of("HS256")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("HS256");
    }

    @Test
    void constructor_rejectsNoneAlgorithm() {
        assertThatThrownBy(
                        () ->
                                new InboundDPoPOptions(
                                        new InMemoryDPoPReplayStore(), 300, 30, Set.of("none")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("none");
    }

    @Test
    void constructor_preservesCustomAlgorithms() {
        InboundDPoPOptions opts =
                new InboundDPoPOptions(new InMemoryDPoPReplayStore(), 300, 30, Set.of("RS256"));
        assertThat(opts.allowedProofAlgorithms()).containsExactly("RS256");
    }

    @Test
    void defaults_areNotRequired() {
        InboundDPoPOptions opts = InboundDPoPOptions.defaults(new InMemoryDPoPReplayStore());
        assertThat(opts.required()).isFalse();
    }

    @Test
    void withRequired_flipsRequiredFlagAndPreservesOtherFields() {
        InboundDPoPOptions base =
                new InboundDPoPOptions(new InMemoryDPoPReplayStore(), 120, 5, Set.of("ES256"));
        InboundDPoPOptions required = base.withRequired(true);

        assertThat(required.required()).isTrue();
        assertThat(required.maxProofAgeSeconds()).isEqualTo(120);
        assertThat(required.clockSkewSeconds()).isEqualTo(5);
        assertThat(required.allowedProofAlgorithms()).containsExactly("ES256");
        assertThat(base.required()).isFalse();
    }

    @Test
    void allowedProofAlgorithms_isImmutable() {
        InboundDPoPOptions opts = InboundDPoPOptions.defaults(new InMemoryDPoPReplayStore());
        assertThatThrownBy(() -> opts.allowedProofAlgorithms().add("HS256"))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
