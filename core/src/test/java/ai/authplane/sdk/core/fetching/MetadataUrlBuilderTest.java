package ai.authplane.sdk.core.fetching;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class MetadataUrlBuilderTest {

    @Test
    void issuerWithNoPath() {
        assertThat(MetadataUrlBuilder.buildMetadataUrl("https://auth.example.com"))
                .isEqualTo("https://auth.example.com/.well-known/oauth-authorization-server");
    }

    @Test
    void issuerWithTrailingSlash_pathIsPreserved() {
        // RFC 8414 §3 — pure insertion; the issuer's path (here "/") is kept verbatim.
        assertThat(MetadataUrlBuilder.buildMetadataUrl("https://auth.example.com/"))
                .isEqualTo("https://auth.example.com/.well-known/oauth-authorization-server/");
    }

    @Test
    void issuerPathWithTrailingSlash_pathIsPreserved() {
        assertThat(MetadataUrlBuilder.buildMetadataUrl("https://auth.example.com/tenant/"))
                .isEqualTo(
                        "https://auth.example.com/.well-known/oauth-authorization-server/tenant/");
    }

    @Test
    void issuerWithSinglePathSegment() {
        assertThat(MetadataUrlBuilder.buildMetadataUrl("https://auth.example.com/tenant1"))
                .isEqualTo(
                        "https://auth.example.com/.well-known/oauth-authorization-server/tenant1");
    }

    @Test
    void issuerWithMultiplePathSegments() {
        assertThat(MetadataUrlBuilder.buildMetadataUrl("https://auth.example.com/org/tenant1"))
                .isEqualTo(
                        "https://auth.example.com/.well-known/oauth-authorization-server/org/tenant1");
    }

    @Test
    void issuerWithPort() {
        assertThat(MetadataUrlBuilder.buildMetadataUrl("https://auth.example.com:8443/tenant1"))
                .isEqualTo(
                        "https://auth.example.com:8443/.well-known/oauth-authorization-server/tenant1");
    }

    @Test
    void doesNotAppendWellKnownToPath() {
        // Wrong: https://auth.example.com/tenant1/.well-known/oauth-authorization-server
        // Right: https://auth.example.com/.well-known/oauth-authorization-server/tenant1
        String url = MetadataUrlBuilder.buildMetadataUrl("https://auth.example.com/tenant1");
        assertThat(url).doesNotContain("/tenant1/.well-known");
        assertThat(url).contains("/.well-known/oauth-authorization-server/tenant1");
    }
}
