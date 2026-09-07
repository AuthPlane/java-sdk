package ai.authplane.sdk.core.fetching;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import ai.authplane.sdk.core.TestFixtures;
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
    void getJwksUri_trailingSlashIssuerMismatch_rejected() {
        // RFC 8414 §3.3: issuer is compared byte-for-byte. Metadata declares the issuer with a
        // trailing slash; the configured value does not — the SDK must NOT reconcile them.
        MetadataCache cache =
                cacheWith(
                        Map.of("issuer", ISSUER + "/", "jwks_uri", "https://auth.example.com/jwks"),
                        false);

        assertThatThrownBy(cache::getJwksUri)
                .isInstanceOf(MetadataFetchException.class)
                .hasMessageContaining("issuer mismatch");
    }

    @Test
    void getJwksUri_issuerWithConfiguredTrailingSlash_verifies() throws Exception {
        // Identifiers are compared verbatim (RFC 8414 §3.3): when the configured issuer itself
        // carries a trailing slash and the metadata's iss matches it byte-for-byte, verification
        // succeeds.
        DocumentFetcher fetcher =
                url ->
                        CompletableFuture.completedFuture(
                                new FetchResult(
                                        Map.of(
                                                "issuer",
                                                ISSUER + "/",
                                                "jwks_uri",
                                                "https://auth.example.com/jwks"),
                                        null));
        MetadataCache cache =
                new MetadataCache(
                        fetcher,
                        ISSUER + "/.well-known/oauth-authorization-server",
                        300,
                        ISSUER + "/",
                        false,
                        null);

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

    // -----------------------------------------------------------------------
    // Validation at fetch time rather than read time
    //
    // The cases above all reject on the *first* fetch, which passed whether validation ran before
    // or after the document was published. What follows is the part that only fetch-time
    // validation gets right: a refresh that returns an invalid document must leave the good one in
    // place and must not reach the change callback, which is what rebinds key retrieval.
    // -----------------------------------------------------------------------

    @Test
    void refreshWithWrongIssuer_keepsServingTheLastValidDocument() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        AtomicInteger callbackCalls = new AtomicInteger();
        TestFixtures.AdvanceableClock clock = new TestFixtures.AdvanceableClock();
        DocumentFetcher fetcher =
                url ->
                        CompletableFuture.completedFuture(
                                new FetchResult(
                                        fetches.incrementAndGet() == 1
                                                ? Map.of(
                                                        "issuer",
                                                        ISSUER,
                                                        "jwks_uri",
                                                        ISSUER + "/jwks")
                                                : Map.of(
                                                        "issuer", "https://evil.example.com",
                                                        "jwks_uri",
                                                                "https://evil.example.com/jwks"),
                                        null));
        MetadataCache cache =
                new MetadataCache(
                        fetcher,
                        ISSUER + "/.well-known/oauth-authorization-server",
                        100,
                        ISSUER,
                        false,
                        (old, next) -> callbackCalls.incrementAndGet(),
                        clock);
        cache.fetch();

        clock.advanceSeconds(101); // past the TTL, so the read below re-fetches

        assertThat(cache.getJwksUri())
                .as("the rejected refresh must not displace the good document")
                .isEqualTo(ISSUER + "/jwks");
        assertThat(fetches.get()).as("the refresh was attempted").isEqualTo(2);
        assertThat(callbackCalls.get())
                .as("a document that failed validation must not reach the change callback")
                .isZero();
    }

    @Test
    void refreshWithoutJwksUri_keepsServingTheLastValidDocument() throws Exception {
        // Same shape as the wrong-issuer case, on the one field the refresh mechanism itself runs
        // on. Presence used to be checked at read time, so a document without jwks_uri passed
        // validation, was published, and displaced the good one — after which
        // AuthplaneClient.refreshMetadataIfDue had nothing left to reconcile the binding against
        // and every verification raised the failure again, on the request path, with nothing to
        // rate-limit it: the fetch had succeeded, so no backoff applied.
        AtomicInteger fetches = new AtomicInteger();
        AtomicInteger callbackCalls = new AtomicInteger();
        TestFixtures.AdvanceableClock clock = new TestFixtures.AdvanceableClock();
        DocumentFetcher fetcher =
                url ->
                        CompletableFuture.completedFuture(
                                new FetchResult(
                                        fetches.incrementAndGet() == 1
                                                ? Map.of(
                                                        "issuer",
                                                        ISSUER,
                                                        "jwks_uri",
                                                        ISSUER + "/jwks")
                                                : Map.of("issuer", ISSUER),
                                        null));
        MetadataCache cache =
                new MetadataCache(
                        fetcher,
                        ISSUER + "/.well-known/oauth-authorization-server",
                        100,
                        ISSUER,
                        false,
                        (old, next) -> callbackCalls.incrementAndGet(),
                        clock);
        cache.fetch();

        clock.advanceSeconds(101); // past the TTL, so the read below re-fetches

        assertThat(cache.getJwksUri())
                .as("the rejected refresh must not displace the good document")
                .isEqualTo(ISSUER + "/jwks");
        assertThat(fetches.get()).as("the refresh was attempted").isEqualTo(2);
        assertThat(callbackCalls.get())
                .as("a document that failed validation must not reach the change callback")
                .isZero();

        // And the rejection is now a failed refresh, so it backs off like one rather than being
        // re-raised on every read.
        assertThat(cache.getJwksUri()).isEqualTo(ISSUER + "/jwks");
        assertThat(fetches.get()).as("the rejected refresh backs off").isEqualTo(2);
    }

    @Test
    void refreshFailure_isNotRetriedOnEveryRead() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        TestFixtures.AdvanceableClock clock = new TestFixtures.AdvanceableClock();
        DocumentFetcher fetcher =
                url ->
                        fetches.incrementAndGet() == 1
                                ? CompletableFuture.completedFuture(
                                        new FetchResult(
                                                Map.of(
                                                        "issuer",
                                                        ISSUER,
                                                        "jwks_uri",
                                                        ISSUER + "/jwks"),
                                                null))
                                : CompletableFuture.failedFuture(new RuntimeException("down"));
        MetadataCache cache =
                new MetadataCache(
                        fetcher,
                        ISSUER + "/.well-known/oauth-authorization-server",
                        100,
                        ISSUER,
                        false,
                        null,
                        clock);
        cache.fetch();

        clock.advanceSeconds(101);

        for (int i = 0; i < 5; i++) {
            assertThat(cache.getJwksUri()).isEqualTo(ISSUER + "/jwks");
        }
        assertThat(fetches.get())
                .as("a failed refresh backs off instead of retrying on every read")
                .isEqualTo(2);

        clock.advanceSeconds(31); // past the backoff
        assertThat(cache.getJwksUri()).isEqualTo(ISSUER + "/jwks");
        assertThat(fetches.get()).as("the retry resumes once the backoff elapses").isEqualTo(3);
    }

    /** Manually advanced clock, so TTL expiry is driven rather than waited on. */
}
