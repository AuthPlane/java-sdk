package ai.authplane.sdk.core.prm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.LIST;

import java.net.URI;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class ProtectedResourceMetadataTest {

    @Test
    void wellKnownPath_rootResource() {
        assertThat(ProtectedResourceMetadata.wellKnownPath(URI.create("https://api.example.com")))
                .isEqualTo("/.well-known/oauth-protected-resource");
    }

    @Test
    void wellKnownPath_resourceWithPath() {
        assertThat(
                        ProtectedResourceMetadata.wellKnownPath(
                                URI.create("https://api.example.com/mcp")))
                .isEqualTo("/.well-known/oauth-protected-resource/mcp");
    }

    @Test
    void wellKnownPath_resourceWithTrailingSlash_stripped() {
        // The terminating slash is stripped only when deriving the well-known path (RFC 9728
        // §3.1); the resource identifier itself is compared verbatim. "/mcp/" →
        // ".../oauth-protected-resource/mcp".
        assertThat(
                        ProtectedResourceMetadata.wellKnownPath(
                                URI.create("https://api.example.com/mcp/")))
                .isEqualTo("/.well-known/oauth-protected-resource/mcp");
    }

    @Test
    void wellKnownPath_rootResourceWithTrailingSlash() {
        // A root resource carrying only a terminating slash (path "/") derives the bare
        // well-known path — exercises the path.equals("/") branch (RFC 9728 §3.1).
        assertThat(ProtectedResourceMetadata.wellKnownPath(URI.create("https://api.example.com/")))
                .isEqualTo("/.well-known/oauth-protected-resource");
    }

    @Test
    void urnStyleResource_isAccepted() {
        // RFC 8707 §2 permits non-http(s) resource indicators. A urn: identifier must not be
        // rejected by any http(s)+authority validator — it is stored verbatim.
        var prm =
                ProtectedResourceMetadata.builder()
                        .resource("urn:example:api")
                        .authorizationServer("https://auth.example.com")
                        .build();
        assertThat(prm.getResource()).isEqualTo("urn:example:api");
        assertThat(prm.toMap().get("resource")).isEqualTo("urn:example:api");
    }

    @Test
    void urnStyleResource_cannotDeriveAPrmUrl() {
        // The identifier is stored verbatim (above), but there is no PRM URL to derive from an
        // opaque URI: it has no authority and no hierarchical path. Deriving anyway produced
        // "urn://null/.well-known/oauth-protected-resource", which AuthplaneResource.prmUrl()
        // hands straight to the resource_metadata parameter of the 401 challenge.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.wellKnownPath(
                                        URI.create("urn:example:api")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("hierarchical resource identifier");

        assertThatThrownBy(() -> ProtectedResourceMetadata.wellKnownUrl("urn:example:api"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("hierarchical resource identifier");
    }

    @Test
    void schemeRelativeResource_cannotDeriveAPrmUrl() {
        // A scheme-relative reference is neither opaque nor authority-less, so it cleared a gate
        // that tested only those two. The derivation then read a null scheme and emitted
        // "null://api.example.com/.well-known/oauth-protected-resource/mcp", which
        // AuthplaneResource.prmUrl() hands straight to the resource_metadata parameter of the
        // 401 challenge — a URL no client can resolve.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.wellKnownPath(
                                        URI.create("//api.example.com/mcp")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("a scheme and an authority");

        assertThatThrownBy(() -> ProtectedResourceMetadata.wellKnownUrl("//api.example.com/mcp"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("a scheme and an authority");
    }

    @Test
    void wellKnownPath_stripsEveryTerminatingSlash() {
        // Stripping only one slash made wellKnownPath and wellKnownUrl disagree on a doubled
        // slash — the exact invariant this pair is supposed to hold.
        assertThat(
                        ProtectedResourceMetadata.wellKnownPath(
                                URI.create("https://api.example.com/mcp//")))
                .isEqualTo("/.well-known/oauth-protected-resource/mcp");
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://api.example.com/mcp//"))
                .isEqualTo("https://api.example.com/.well-known/oauth-protected-resource/mcp");
    }

    @Test
    void wellKnownPath_preservesPercentEncodedOctets() {
        // getPath() decodes, so "%2F" collapsed to "/" and the derived path named a different
        // resource than the identifier does (RFC 3986 §3.3).
        assertThat(
                        ProtectedResourceMetadata.wellKnownPath(
                                URI.create("https://api.example.com/a%2Fb")))
                .isEqualTo("/.well-known/oauth-protected-resource/a%2Fb");
    }

    @Test
    void wellKnownPath_resourceWithDeepPath() {
        assertThat(
                        ProtectedResourceMetadata.wellKnownPath(
                                URI.create("https://api.example.com/v2/mcp")))
                .isEqualTo("/.well-known/oauth-protected-resource/v2/mcp");
    }

    @Test
    void wellKnownUrl_returnsFullUrl() {
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://api.example.com"))
                .isEqualTo("https://api.example.com/.well-known/oauth-protected-resource");
    }

    @Test
    void wellKnownUrl_pathWithTrailingSlash_stripped() {
        // wellKnownUrl applies its own terminating-slash strip before deriving the path, so a
        // trailing-slash resource URL still resolves to the slash-less well-known document.
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://api.example.com/mcp/"))
                .isEqualTo("https://api.example.com/.well-known/oauth-protected-resource/mcp");
    }

    @Test
    void wellKnownUrl_preservesRawAuthority() {
        // getAuthority() percent-decodes, so "u%40b@" derived "u@b@" — an authority structurally
        // different from the one the identifier names (two '@' delimiters instead of one). The
        // raw-preservation rule applies to the authority exactly as it does to the path.
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://u%40b@api.example.com/mcp"))
                .isEqualTo(
                        "https://u%40b@api.example.com/.well-known/oauth-protected-resource/mcp");
    }

    @Test
    void toMap_containsAllRequiredFields() {
        var prm =
                ProtectedResourceMetadata.builder()
                        .resource("https://api.example.com")
                        .authorizationServer("https://auth.example.com")
                        .scopes(List.of("read:data", "write:data"))
                        .build();

        Map<String, Object> doc = prm.toMap();
        assertThat(doc).containsKey("resource");
        assertThat(doc).containsKey("authorization_servers");
        assertThat(doc).containsKey("bearer_methods_supported");
        assertThat(doc).containsKey("scopes_supported");
    }

    @Test
    void toMap_authorizationServersIsList() {
        var prm =
                ProtectedResourceMetadata.builder()
                        .resource("https://api.example.com")
                        .authorizationServer("https://auth.example.com")
                        .build();
        Object as = prm.toMap().get("authorization_servers");
        assertThat(as).asInstanceOf(LIST).containsExactly("https://auth.example.com");
    }

    @Test
    void toMap_bearerMethodsIsHeader() {
        var prm =
                ProtectedResourceMetadata.builder()
                        .resource("https://api.example.com")
                        .authorizationServer("https://auth.example.com")
                        .build();
        assertThat(prm.toMap().get("bearer_methods_supported"))
                .asInstanceOf(LIST)
                .containsExactly("header");
    }

    @Test
    void builder_requiresResource() {
        assertThatNullPointerException()
                .isThrownBy(
                        () ->
                                ProtectedResourceMetadata.builder()
                                        .authorizationServer("https://auth.example.com")
                                        .build());
    }

    @Test
    void builder_requiresAuthorizationServer() {
        assertThatNullPointerException()
                .isThrownBy(
                        () ->
                                ProtectedResourceMetadata.builder()
                                        .resource("https://api.example.com")
                                        .build());
    }

    @Test
    void toMap_isUnmodifiable() {
        var prm =
                ProtectedResourceMetadata.builder()
                        .resource("https://api.example.com")
                        .authorizationServer("https://auth.example.com")
                        .build();
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> prm.toMap().put("extra", "value"));
    }

    @Test
    void wellKnownUrl_trailingSlash_stripped() {
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://api.example.com/"))
                .isEqualTo("https://api.example.com/.well-known/oauth-protected-resource");
    }

    @Test
    void toJson_producesValidJson() {
        var prm =
                ProtectedResourceMetadata.builder()
                        .resource("https://api.example.com")
                        .authorizationServer("https://auth.example.com")
                        .scopes(List.of("read:data", "write:data"))
                        .build();
        String json = prm.toJson();
        assertThat(json).contains("\"resource\":\"https://api.example.com\"");
        assertThat(json).contains("\"authorization_servers\":[\"https://auth.example.com\"]");
        assertThat(json).contains("\"scopes_supported\":[\"read:data\",\"write:data\"]");
    }

    @Test
    void getters_returnConstructedValues() {
        var prm =
                ProtectedResourceMetadata.builder()
                        .resource("https://api.example.com")
                        .authorizationServer("https://auth.example.com")
                        .scopes(List.of("read:data"))
                        .build();
        assertThat(prm.getResource()).isEqualTo("https://api.example.com");
        assertThat(prm.getAuthorizationServers()).containsExactly("https://auth.example.com");
        assertThat(prm.getBearerMethodsSupported()).containsExactly("header");
        assertThat(prm.getScopesSupported()).containsExactly("read:data");
    }
}
