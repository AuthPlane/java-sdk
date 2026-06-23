package ai.authplane.sdk.core.fetching.ssrf;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.logging.Logger;

import ai.authplane.sdk.core.fetching.FetchSettings;

/**
 * Validates a URL for SSRF safety: 1. Checks scheme (HTTPS required unless allowHttp=true) 2.
 * Resolves hostname to IP addresses 3. Validates each IP against the blocklist
 *
 * <p>Returns ValidatedUrl on success. Throws SsrfException on any failure. Thread-safe — all
 * methods are stateless.
 */
public final class UrlValidator {

    private static final Logger LOG = Logger.getLogger(UrlValidator.class.getName());

    private UrlValidator() {}

    /**
     * Validates the given URL under the given settings.
     *
     * @param url the URL to validate
     * @param settings the SSRF configuration
     * @return a ValidatedUrl ready for DNS-pinned connections
     * @throws SsrfException if the URL fails any validation check
     */
    public static ValidatedUrl validate(String url, FetchSettings settings) {
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new SsrfException("Malformed URL: " + url, e);
        }

        String scheme = validateScheme(uri, settings);
        String hostname = uri.getHost();
        if (hostname == null || hostname.isBlank()) {
            throw new SsrfException("URL has no hostname: " + url);
        }

        int port = resolvePort(uri, scheme);
        String path = buildPath(uri);

        List<InetAddress> resolvedIps = resolveAndValidate(hostname, settings);

        return new ValidatedUrl(url, scheme, hostname, port, path, resolvedIps);
    }

    // -----------------------------------------------------------------------

    private static String validateScheme(URI uri, FetchSettings settings) {
        String scheme = uri.getScheme();
        if (scheme == null) {
            throw new SsrfException("URL has no scheme");
        }
        scheme = scheme.toLowerCase();
        return switch (scheme) {
            case "https" -> "https";
            case "http" -> {
                if (!settings.allowHttp()) {
                    throw new SsrfException(
                            "HTTP is not allowed in production. Use HTTPS or enable dev mode.");
                }
                yield "http";
            }
            default -> throw new SsrfException("Unsupported URL scheme: " + scheme);
        };
    }

    private static int resolvePort(URI uri, String scheme) {
        int port = uri.getPort();
        if (port == -1) {
            return "https".equals(scheme) ? 443 : 80;
        }
        return port;
    }

    private static String buildPath(URI uri) {
        String path = uri.getRawPath();
        if (path == null || path.isEmpty()) path = "/";
        String query = uri.getRawQuery();
        if (query != null && !query.isEmpty()) {
            path = path + "?" + query;
        }
        return path;
    }

    private static List<InetAddress> resolveAndValidate(String hostname, FetchSettings settings) {
        InetAddress[] resolved;
        try {
            resolved = InetAddress.getAllByName(hostname);
        } catch (UnknownHostException e) {
            throw new SsrfException("DNS resolution failed for: " + hostname, e);
        }

        if (resolved.length == 0) {
            throw new SsrfException("DNS returned no addresses for: " + hostname);
        }

        // Deduplicate preserving order, then validate each IP
        var seen = new LinkedHashSet<InetAddress>();
        for (InetAddress addr : resolved) {
            seen.add(addr);
        }

        var validated = new ArrayList<InetAddress>();
        for (InetAddress addr : seen) {
            if (!IpValidator.isAllowed(addr, settings)) {
                throw new SsrfException(
                        String.format(
                                "SSRF blocked: %s resolved to blocked IP %s",
                                hostname, addr.getHostAddress()));
            }
            validated.add(addr);
            LOG.fine(() -> "DNS resolved " + hostname + " → " + addr.getHostAddress());
        }

        return validated;
    }
}
