package ai.authplane.sdk.core.fetching;

import java.net.URI;
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
        super(fetcher, metadataUrl, refreshSeconds, "metadata", onChangeCallback);
        // Required: the RFC 8414 §3.3 comparison in getJwksUri() dereferences this. Without the
        // check a null surfaces as a bare NPE from the first metadata read rather than as a
        // contract violation at construction.
        this.expectedIssuer =
                Objects.requireNonNull(expectedIssuer, "expectedIssuer must not be null");
        this.allowHttp = allowHttp;
    }

    /**
     * Returns the {@code jwks_uri} from the current (or freshly fetched) metadata.
     *
     * @throws MetadataFetchException if the metadata is unavailable or missing jwks_uri
     */
    public String getJwksUri() throws Exception {
        Map<String, Object> metadata = getMetadata();

        Object jwksUri = metadata.get("jwks_uri");
        if (!(jwksUri instanceof String jwksUriStr) || jwksUriStr.isBlank()) {
            throw new MetadataFetchException(
                    "OAuth server metadata is missing or has empty 'jwks_uri' field");
        }

        LOG.fine(() -> "jwks_uri from metadata: " + jwksUriStr);
        return jwksUriStr;
    }

    private Map<String, Object> getMetadata() throws MetadataFetchException {
        Map<String, Object> metadata;
        try {
            metadata = get();
        } catch (MetadataFetchException e) {
            throw e;
        } catch (Exception e) {
            throw new MetadataFetchException(
                    "Failed to fetch OAuth server metadata: " + e.getMessage(), e);
        }
        validateMetadata(metadata);
        return metadata;
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
