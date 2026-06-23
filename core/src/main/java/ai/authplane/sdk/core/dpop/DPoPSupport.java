package ai.authplane.sdk.core.dpop;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

final class DPoPSupport {

    private DPoPSupport() {}

    static String normalizeHtu(String url) {
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new InvalidDPoPProofException("DPoP URL must be absolute", e);
        }

        if (uri.getScheme() == null || uri.getHost() == null) {
            throw new InvalidDPoPProofException("DPoP URL must be absolute");
        }

        String scheme = uri.getScheme().toLowerCase();
        String host = uri.getHost().toLowerCase();
        int port = uri.getPort();
        boolean keepPort = port != -1 && !isDefaultPort(scheme, port);
        // Use the raw (still percent-encoded) path. RFC 3986 §6.2.2.2 allows decoding only
        // unreserved characters for comparison, so reserved ones must stay encoded — an encoded
        // "%2F" is not equivalent to "/". getPath() decodes everything and could conflate distinct
        // request targets, weakening the RFC 9449 §4.3 #9 htu binding. Both the proof's htu and the
        // request URL pass through here, so the comparison stays consistent.
        String rawPath = uri.getRawPath();
        String path = (rawPath == null || rawPath.isEmpty()) ? "/" : rawPath;

        StringBuilder normalized = new StringBuilder().append(scheme).append("://").append(host);
        if (keepPort) {
            normalized.append(':').append(port);
        }
        normalized.append(path);
        return normalized.toString();
    }

    static String originKey(String url) {
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new InvalidDPoPProofException("DPoP URL must be absolute", e);
        }

        if (uri.getScheme() == null || uri.getHost() == null) {
            throw new InvalidDPoPProofException("DPoP URL must be absolute");
        }

        int port = uri.getPort();
        if (port == -1) {
            port = "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
        }
        return uri.getScheme().toLowerCase() + "://" + uri.getHost().toLowerCase() + ":" + port;
    }

    static String computeAth(String accessToken) {
        try {
            byte[] hash =
                    MessageDigest.getInstance("SHA-256")
                            .digest(accessToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute DPoP ath", e);
        }
    }

    private static boolean isDefaultPort(String scheme, int port) {
        return ("https".equals(scheme) && port == 443) || ("http".equals(scheme) && port == 80);
    }
}
