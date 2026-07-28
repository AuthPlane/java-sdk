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
     * <p>The well-known segment is inserted between the authority and the issuer's path — a pure
     * string insertion (RFC 8414 §3) that preserves the path exactly, including any trailing slash.
     *
     * <p>Examples: "https://auth.example.com" →
     * "https://auth.example.com/.well-known/oauth-authorization-server"
     * "https://auth.example.com/t1" →
     * "https://auth.example.com/.well-known/oauth-authorization-server/t1"
     * "https://auth.example.com/t1/" →
     * "https://auth.example.com/.well-known/oauth-authorization-server/t1/"
     *
     * @param issuer the issuer URI
     * @return the metadata discovery URL
     */
    public static String buildMetadataUrl(String issuer) {
        URI uri = URI.create(issuer);

        String scheme = uri.getScheme();
        String authority = uri.getRawAuthority(); // host[:port]
        String path = uri.getRawPath(); // may be null or ""

        StringBuilder sb = new StringBuilder();
        sb.append(scheme).append("://").append(authority).append(WELL_KNOWN);
        if (path != null) {
            sb.append(path);
        }
        return sb.toString();
    }
}
