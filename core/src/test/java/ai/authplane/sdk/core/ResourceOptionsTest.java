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
    // resourceMetadataUrl — the advertised PRM URL override
    // -----------------------------------------------------------------------

    @Test
    void defaults_resourceMetadataUrlIsNull() {
        // null is what makes AuthplaneResource.resourceMetadataUrl() fall back to the derived,
        // resource-hosted URL — the default topology.
        assertThat(ResourceOptions.defaults().resourceMetadataUrl()).isNull();
    }

    @Test
    void builder_resourceMetadataUrl_customized() {
        ResourceOptions opts =
                ResourceOptions.builder()
                        .resourceMetadataUrl(
                                "https://auth.example.com/.well-known/oauth-protected-resource/mcp")
                        .build();
        assertThat(opts.resourceMetadataUrl())
                .isEqualTo("https://auth.example.com/.well-known/oauth-protected-resource/mcp");
    }

    @Test
    void builder_resourceMetadataUrl_relativeReference_throwsIllegalArgument() {
        // The value is spliced into a header that reaches unauthenticated clients; a relative
        // reference names no document they can fetch.
        assertThatThrownBy(
                        () ->
                                ResourceOptions.builder()
                                        .resourceMetadataUrl(
                                                "/.well-known/oauth-protected-resource/mcp"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("it has no scheme");
    }

    @Test
    void builder_resourceMetadataUrl_nonHttpScheme_throwsIllegalArgument() {
        assertThatThrownBy(() -> ResourceOptions.builder().resourceMetadataUrl("urn:example:prm"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not http or https");
    }

    @Test
    void builder_resourceMetadataUrl_noHost_throwsIllegalArgument() {
        assertThatThrownBy(
                        () ->
                                ResourceOptions.builder()
                                        .resourceMetadataUrl(
                                                "https:///.well-known/oauth-protected-resource"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("it names no host");
    }

    @Test
    void builder_resourceMetadataUrl_userinfo_throwsIllegalArgumentAndElidesTheCredential() {
        // URI.getHost() is "auth.example.com" for this shape, so the host gate alone lets it
        // through — and the value is then advertised in every 401 and 403 to unauthenticated
        // callers, which is exactly what the identifier's own userinfo gate exists to stop.
        assertThatThrownBy(
                        () ->
                                ResourceOptions.builder()
                                        .resourceMetadataUrl(
                                                "https://svc:s3cr3t@auth.example.com/.well-known/oauth-protected-resource/mcp"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("resourceMetadataUrl")
                .hasMessageContaining("userinfo")
                .hasMessageNotContaining("s3cr3t");
    }

    @Test
    void builder_resourceMetadataUrl_fragment_throwsIllegalArgument() {
        // A fragment is never sent to the server, so it names a document the client fetches
        // without it — the advertised URL and the one retrieved disagree.
        assertThatThrownBy(
                        () ->
                                ResourceOptions.builder()
                                        .resourceMetadataUrl(
                                                "https://auth.example.com/.well-known/oauth-protected-resource/mcp#frag"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("resourceMetadataUrl")
                .hasMessageContaining("fragment");
    }

    @Test
    void builder_resourceMetadataUrl_null_throwsNpe() {
        assertThatThrownBy(() -> ResourceOptions.builder().resourceMetadataUrl(null))
                .isInstanceOf(NullPointerException.class);
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
