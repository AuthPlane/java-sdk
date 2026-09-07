package ai.authplane.sdk.core.fetching;

import java.net.URI;
import java.time.Clock;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiConsumer;
import java.util.logging.Logger;

import ai.authplane.sdk.core.errors.MetadataFetchException;

/**
 * Cache for OAuth Authorization Server Metadata (RFC 8414).
 *
 * <p>Extracts and validates the {@code jwks_uri} field. Validates issuer and endpoint URLs
 * internally when metadata is fetched. Triggers the change callback when the document changes,
 * allowing the caller to detect jwks_uri rotation and restart the JwksCache.
 */
public class MetadataCache extends DocumentCache {

    private static final Logger LOG = Logger.getLogger(MetadataCache.class.getName());

    private static final String[] ENDPOINT_FIELDS = {
        "jwks_uri", "token_endpoint", "introspection_endpoint", "revocation_endpoint"
    };

    private final String expectedIssuer;
    private final boolean allowHttp;

    /**
     * Constructs a metadata cache bound to a specific authorization-server metadata URL.
     *
     * @param fetcher transport used to retrieve the document
     * @param metadataUrl absolute URL of the AS metadata document (RFC 8414)
     * @param refreshSeconds background refresh interval
     * @param expectedIssuer issuer the discovered document must match exactly
     * @param allowHttp whether plain-HTTP endpoint URLs are permitted (dev mode only)
     * @param onChangeCallback invoked when the cached document changes; receives (previous,
     *     current)
     */
    public MetadataCache(
            DocumentFetcher fetcher,
            String metadataUrl,
            int refreshSeconds,
            String expectedIssuer,
            boolean allowHttp,
            BiConsumer<Map<String, Object>, Map<String, Object>> onChangeCallback) {
        this(
                fetcher,
                metadataUrl,
                refreshSeconds,
                expectedIssuer,
                allowHttp,
                onChangeCallback,
                Clock.systemUTC());
    }

    /**
     * Same as the six-argument constructor, but with the time source used for TTL evaluation
     * supplied by the caller.
     *
     * <p>Supported public API, not a test seam — see {@link JwksCache#JwksCache(DocumentFetcher,
     * String, int, java.util.function.BiConsumer, Clock)}. The parameter count is inherited from
     * the six-argument constructor this one extends; a builder would fix it for both, which is a
     * change to make on its own rather than folded into a behavioural fix.
     *
     * @param clock time source; pass {@link Clock#systemUTC()} unless driving TTL expiry
     *     deterministically
     */
    @SuppressWarnings("checkstyle:ParameterNumber")
    public MetadataCache(
            DocumentFetcher fetcher,
            String metadataUrl,
            int refreshSeconds,
            String expectedIssuer,
            boolean allowHttp,
            BiConsumer<Map<String, Object>, Map<String, Object>> onChangeCallback,
            Clock clock) {
        super(fetcher, metadataUrl, refreshSeconds, "metadata", onChangeCallback, clock);
        // Required: the RFC 8414 §3.3 comparison in validateMetadata() dereferences this. Without
        // the check a null surfaces as a bare NPE from the first metadata read rather than as a
        // contract violation at construction.
        this.expectedIssuer =
                Objects.requireNonNull(expectedIssuer, "expectedIssuer must not be null");
        this.allowHttp = allowHttp;
    }

    /**
     * Validates every freshly fetched document, so an invalid one is never published to the cache
     * and never reaches the change callback.
     *
     * <p>Validating at fetch time rather than at read time matters once metadata is re-read under
     * ordinary traffic: a refresh that returns a document with the wrong issuer must not displace
     * the good one, and — because the change callback rebinds JWKS fetching to the document's
     * {@code jwks_uri} — must not be able to point key retrieval somewhere new either.
     */
    @Override
    protected void validateFetched(Map<String, Object> document) throws MetadataFetchException {
        validateMetadata(document);
    }

    /**
     * Returns the {@code jwks_uri} from the current (or freshly fetched) metadata.
     *
     * <p>A read, not a check: {@code validateMetadata} rejects a document without a usable {@code
     * jwks_uri} before it reaches the cache, so anything served from here has one. The failure this
     * used to raise is now raised at fetch time, which is what keeps an invalid refresh from
     * displacing the document being served.
     *
     * @throws MetadataFetchException if the metadata is unavailable
     */
    public String getJwksUri() throws Exception {
        String jwksUri = (String) getMetadata().get("jwks_uri");
        LOG.fine(() -> "jwks_uri from metadata: " + jwksUri);
        return jwksUri;
    }

    private Map<String, Object> getMetadata() throws MetadataFetchException {
        try {
            // Whatever the cache returns has already passed validateFetched().
            return get();
        } catch (MetadataFetchException e) {
            throw e;
        } catch (Exception e) {
            throw new MetadataFetchException(
                    "Failed to fetch OAuth server metadata: " + e.getMessage(), e);
        }
    }

    /**
     * Validates the metadata document: issuer must match the configured value, and endpoint URLs
     * must be absolute HTTPS URLs (or HTTP when {@code allowHttp} is true).
     */
    private void validateMetadata(Map<String, Object> metadata) throws MetadataFetchException {
        // Validate issuer
        Object issuerObj = metadata.get("issuer");
        if (!(issuerObj instanceof String issuer) || issuer.isBlank()) {
            throw new MetadataFetchException(
                    "OAuth server metadata is missing or has empty 'issuer' field");
        }

        // RFC 8414 §3.3: the issuer is compared byte-for-byte against the configured value.
        // No trailing-slash reconciliation — a difference in the terminating slash is a mismatch.
        if (!expectedIssuer.equals(issuer)) {
            throw new MetadataFetchException(
                    "OAuth server metadata issuer mismatch: expected '"
                            + expectedIssuer
                            + "', got '"
                            + issuer
                            + "'");
        }

        // RFC 8414 §2 marks jwks_uri OPTIONAL — REQUIRED is OpenID Connect Discovery, a
        // different document. This SDK requires it anyway: every verification path builds a
        // JwtValidator, and introspection is layered on top of JWT validation rather than
        // offered as an alternative to it, so a document without jwks_uri is one this SDK
        // cannot use. Checking presence here rather than at read time is the same move as the
        // rest of this change: a document the SDK cannot use must not displace the one already
        // being served.
        // It is also the field the refresh mechanism itself runs on — with jwks_uri gone,
        // AuthplaneClient.refreshMetadataIfDue has nothing to reconcile the binding against, so a
        // later rotation would not be followed even after the AS fixed its document.
        Object jwksUri = metadata.get("jwks_uri");
        if (!(jwksUri instanceof String jwksUriStr) || jwksUriStr.isBlank()) {
            throw new MetadataFetchException(
                    "OAuth server metadata is missing or has empty 'jwks_uri' field");
        }

        // Validate endpoint URLs (RFC 8414 §2: endpoints MUST be absolute HTTPS URLs)
        for (String field : ENDPOINT_FIELDS) {
            Object value = metadata.get(field);
            if (value instanceof String urlStr && !urlStr.isBlank()) {
                validateEndpointUrl(field, urlStr);
            }
        }
    }

    /**
     * Checks that the given URL is absolute (has a scheme and host). When {@code allowHttp} is
     * false, also requires the scheme to be HTTPS.
     */
    private void validateEndpointUrl(String field, String value) throws MetadataFetchException {
        URI uri;
        try {
            uri = URI.create(value);
        } catch (IllegalArgumentException e) {
            throw new MetadataFetchException(
                    "OAuth server metadata field '"
                            + field
                            + "' must be an absolute HTTPS URL, got '"
                            + value
                            + "'");
        }

        String scheme = uri.getScheme();
        String host = uri.getHost();
        if (scheme == null || host == null || host.isBlank()) {
            throw new MetadataFetchException(
                    "OAuth server metadata field '"
                            + field
                            + "' must be an absolute HTTPS URL, got '"
                            + value
                            + "'");
        }

        if (!allowHttp && !"https".equalsIgnoreCase(scheme)) {
            throw new MetadataFetchException(
                    "OAuth server metadata field '"
                            + field
                            + "' must be an absolute HTTPS URL, got '"
                            + value
                            + "'");
        }
    }
}
