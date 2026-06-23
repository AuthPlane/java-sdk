package ai.authplane.sdk.core.fetching;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.junit.jupiter.api.Test;

import ai.authplane.sdk.core.errors.MetadataFetchException;

/**
 * Coverage for MetadataCache's RFC 8414 validation paths — issuer match, endpoint URL
 * absoluteness/scheme checks, and the various error wrappings that the happy-path AuthplaneClient
 * tests don't exercise.
 */
class MetadataCacheTest {

    private static final String ISSUER = "https://auth.example.com";

    private static MetadataCache cacheWith(Map<String, Object> doc, boolean allowHttp) {
        DocumentFetcher fetcher =
                url -> CompletableFuture.completedFuture(new FetchResult(doc, null));
        return new MetadataCache(
                fetcher,
                ISSUER + "/.well-known/oauth-authorization-server",
                300,
                ISSUER,
                allowHttp,
                null);
    }

    @Test
    void getJwksUri_validMetadata_returnsJwksUri() throws Exception {
        MetadataCache cache =
                cacheWith(
                        Map.of("issuer", ISSUER, "jwks_uri", "https://auth.example.com/jwks"),
                        false);

        assertThat(cache.getJwksUri()).isEqualTo("https://auth.example.com/jwks");
    }

    @Test
    void getJwksUri_normalizesTrailingSlashOnIssuer() throws Exception {
        // Metadata declares issuer with trailing slash; configured value doesn't.
        // normalizeIssuer should strip the slash before comparison.
        MetadataCache cache =
                cacheWith(
                        Map.of("issuer", ISSUER + "/", "jwks_uri", "https://auth.example.com/jwks"),
                        false);

        assertThat(cache.getJwksUri()).isEqualTo("https://auth.example.com/jwks");
    }

    @Test
    void getJwksUri_missingJwksUri_throws() {
        MetadataCache cache = cacheWith(Map.of("issuer", ISSUER), false);

        assertThatThrownBy(cache::getJwksUri)
                .isInstanceOf(MetadataFetchException.class)
                .hasMessageContaining("jwks_uri");
    }

    @Test
    void getJwksUri_emptyJwksUri_throws() {
        MetadataCache cache = cacheWith(Map.of("issuer", ISSUER, "jwks_uri", "  "), false);

        assertThatThrownBy(cache::getJwksUri)
                .isInstanceOf(MetadataFetchException.class)
                .hasMessageContaining("jwks_uri");
    }

    @Test
    void getJwksUri_jwksUriNotString_throws() {
        MetadataCache cache = cacheWith(Map.of("issuer", ISSUER, "jwks_uri", 42), false);

        assertThatThrownBy(cache::getJwksUri).isInstanceOf(MetadataFetchException.class);
    }

    @Test
    void getJwksUri_missingIssuer_throws() {
        MetadataCache cache = cacheWith(Map.of("jwks_uri", "https://x/y"), false);

        assertThatThrownBy(cache::getJwksUri)
                .isInstanceOf(MetadataFetchException.class)
                .hasMessageContaining("issuer");
    }

    @Test
    void getJwksUri_emptyIssuer_throws() {
        MetadataCache cache = cacheWith(Map.of("issuer", "   ", "jwks_uri", "https://x/y"), false);

        assertThatThrownBy(cache::getJwksUri)
                .isInstanceOf(MetadataFetchException.class)
                .hasMessageContaining("issuer");
    }

    @Test
    void getJwksUri_issuerMismatch_throws() {
        MetadataCache cache =
                cacheWith(
                        Map.of(
                                "issuer", "https://other-issuer.example.com",
                                "jwks_uri", "https://x/y"),
                        false);

        assertThatThrownBy(cache::getJwksUri)
                .isInstanceOf(MetadataFetchException.class)
                .hasMessageContaining("issuer mismatch");
    }

    @Test
    void getJwksUri_endpointHttpRejectedWhenAllowHttpFalse() {
        MetadataCache cache =
                cacheWith(
                        Map.of("issuer", ISSUER, "jwks_uri", "http://insecure.example/jwks"),
                        false);

        assertThatThrownBy(cache::getJwksUri)
                .isInstanceOf(MetadataFetchException.class)
                .hasMessageContaining("absolute HTTPS URL");
    }

    @Test
    void getJwksUri_endpointHttpAcceptedWhenAllowHttpTrue() throws Exception {
        MetadataCache cache =
                cacheWith(Map.of("issuer", ISSUER, "jwks_uri", "http://localhost:9000/jwks"), true);

        assertThat(cache.getJwksUri()).isEqualTo("http://localhost:9000/jwks");
    }

    @Test
    void getJwksUri_endpointMissingScheme_throws() {
        MetadataCache cache = cacheWith(Map.of("issuer", ISSUER, "jwks_uri", "//x/y"), false);

        assertThatThrownBy(cache::getJwksUri)
                .isInstanceOf(MetadataFetchException.class)
                .hasMessageContaining("absolute HTTPS URL");
    }

    @Test
    void getJwksUri_endpointInvalidUri_throws() {
        MetadataCache cache =
                cacheWith(
                        Map.of("issuer", ISSUER, "jwks_uri", "https://host with spaces/jwks"),
                        false);

        assertThatThrownBy(cache::getJwksUri).isInstanceOf(MetadataFetchException.class);
    }

    @Test
    void getJwksUri_validatesAllEndpointFields() {
        MetadataCache cache =
                cacheWith(
                        Map.of(
                                "issuer", ISSUER,
                                "jwks_uri", "https://x/y",
                                "token_endpoint", "http://insecure.example/token"),
                        false);

        // token_endpoint validation should fail before getJwksUri returns
        assertThatThrownBy(cache::getJwksUri)
                .isInstanceOf(MetadataFetchException.class)
                .hasMessageContaining("token_endpoint");
    }

    @Test
    void getJwksUri_emptyEndpointFieldsAreIgnored() throws Exception {
        // Blank values for optional endpoints should be silently skipped
        java.util.HashMap<String, Object> doc = new java.util.HashMap<>();
        doc.put("issuer", ISSUER);
        doc.put("jwks_uri", "https://auth.example.com/jwks");
        doc.put("introspection_endpoint", "");
        doc.put("revocation_endpoint", "   ");

        MetadataCache cache = cacheWith(doc, false);

        assertThat(cache.getJwksUri()).isEqualTo("https://auth.example.com/jwks");
    }

    @Test
    void getJwksUri_fetcherThrowsRuntime_wrappedInMetadataFetchException() {
        DocumentFetcher fetcher =
                url -> CompletableFuture.failedFuture(new RuntimeException("boom"));
        MetadataCache cache =
                new MetadataCache(fetcher, ISSUER + "/.well-known/", 300, ISSUER, false, null);

        assertThatThrownBy(cache::getJwksUri).isInstanceOf(MetadataFetchException.class);
    }
}
