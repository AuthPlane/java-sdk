package ai.authplane.sdk.core.prm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
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
    void wellKnownPath_rootResourceWithTrailingSlash() {
        assertThat(ProtectedResourceMetadata.wellKnownPath(URI.create("https://api.example.com/")))
                .isEqualTo("/.well-known/oauth-protected-resource");
    }

    @Test
    void wellKnownPath_resourceWithTrailingSlash_dropped() {
        assertThat(
                        ProtectedResourceMetadata.wellKnownPath(
                                URI.create("https://api.example.com/mcp/")))
                .isEqualTo("/.well-known/oauth-protected-resource/mcp");
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
    void wellKnownUrl_pathWithTrailingSlash_stripped() {
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://api.example.com/mcp/"))
                .isEqualTo("https://api.example.com/.well-known/oauth-protected-resource/mcp");
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
