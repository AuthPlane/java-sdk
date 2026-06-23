package ai.authplane.sdk.core.fetching.ssrf;

import java.net.InetAddress;
import java.util.List;

/**
 * A URL that has passed SSRF validation: scheme checked, hostname resolved to IPs, and all IPs
 * verified against the IP blocklist.
 *
 * <p>The resolved IPs are used for DNS-pinned connections. The original hostname is used for the
 * TLS SNI and Host header.
 */
public record ValidatedUrl(
        /** The original URL string as supplied by the caller. */
        String originalUrl,

        /** Scheme: "https" or "http" (only "http" if explicitly allowed). */
        String scheme,

        /** Original hostname from the URL — used for Host header and TLS SNI. */
        String hostname,

        /** Port, explicitly stated or inferred from scheme (443/80). */
        int port,

        /** URL path including query string. Empty string if path is "/". */
        String path,

        /** All IP addresses the hostname resolved to, validated and deduplicated. */
        List<InetAddress> resolvedIps) {
    public ValidatedUrl {
        resolvedIps = List.copyOf(resolvedIps);
    }
}
