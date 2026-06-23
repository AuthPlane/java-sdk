package ai.authplane.sdk.core.fetching;

import java.net.URI;

/**
 * Builds the RFC 8414 Authorization Server Metadata discovery URL.
 *
 * <p>The .well-known segment is inserted after the authority, before any issuer path component (RFC
 * 8414 §3).
 *
 * <p>Thread-safe — all methods are stateless.
 */
public final class MetadataUrlBuilder {

    private static final String WELL_KNOWN = "/.well-known/oauth-authorization-server";

    private MetadataUrlBuilder() {}

    /**
     * Builds the metadata URL for the given issuer.
     *
     * <p>Examples: "https://auth.example.com" →
     * "https://auth.example.com/.well-known/oauth-authorization-server"
     * "https://auth.example.com/t1" →
     * "https://auth.example.com/.well-known/oauth-authorization-server/t1"
     * "https://auth.example.com/a/b" →
     * "https://auth.example.com/.well-known/oauth-authorization-server/a/b"
     *
     * @param issuer the issuer URI (no trailing slash required)
     * @return the metadata discovery URL
     */
    public static String buildMetadataUrl(String issuer) {
        URI uri =
                URI.create(
                        issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer);

        String scheme = uri.getScheme();
        String authority = uri.getAuthority(); // host[:port]
        String path = uri.getPath(); // may be null or ""

        StringBuilder sb = new StringBuilder();
        sb.append(scheme).append("://").append(authority).append(WELL_KNOWN);

        if (path != null && !path.isEmpty() && !path.equals("/")) {
            // Strip leading slash (WELL_KNOWN already starts with /)
            String cleanPath = path.startsWith("/") ? path.substring(1) : path;
            if (!cleanPath.isEmpty()) {
                sb.append("/").append(cleanPath);
            }
        }

        return sb.toString();
    }
}
