package ai.authplane.sdk.core.http;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Small, framework-agnostic helpers for reading HTTP request headers supplied as a {@code
 * Map<String, List<String>>}. Header-name matching is case-insensitive (per RFC 9110 §5.1).
 *
 * <p>Shared by the MCP and Spring adapters so bearer/DPoP token extraction behaves identically
 * everywhere.
 */
public final class HttpHeaders {

    private static final String BEARER_SCHEME = "Bearer ";
    private static final String DPOP_SCHEME = "DPoP ";

    private HttpHeaders() {}

    /**
     * Returns all non-null values for the given header name (case-insensitive). Never null.
     *
     * <p>Values are collected in the iteration order of {@code headers} (and of each matching
     * entry's value list). HTTP header names are unique after case-folding, so in practice this is
     * the single matching entry's values in order; the overall order across distinct keys is only
     * as stable as the supplied map's iteration order.
     *
     * @param headers the request headers
     * @param name the header name to match
     * @return the matching values; empty if none
     */
    public static List<String> values(Map<String, List<String>> headers, String name) {
        List<String> result = new ArrayList<>();
        if (headers == null) {
            return result;
        }
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(name)) {
                List<String> vals = entry.getValue();
                if (vals != null) {
                    for (String v : vals) {
                        if (v != null) {
                            result.add(v);
                        }
                    }
                }
            }
        }
        return result;
    }

    /**
     * Returns the first non-blank value for the given header name (case-insensitive), or null.
     *
     * @param headers the request headers
     * @param name the header name to match
     * @return the first non-blank value, or null if none
     */
    public static String firstValue(Map<String, List<String>> headers, String name) {
        for (String v : values(headers, name)) {
            if (!v.isBlank()) {
                return v;
            }
        }
        return null;
    }

    /**
     * Extracts the access token from the {@code Authorization} header, accepting both the {@code
     * Bearer} and (RFC 9449) {@code DPoP} schemes.
     *
     * @param headers the request headers
     * @return the token, or null if no usable Authorization header is present
     */
    public static String accessToken(Map<String, List<String>> headers) {
        return tokenFromAuthorization(firstValue(headers, "Authorization"));
    }

    /**
     * Extracts the access token from a raw {@code Authorization} header value, accepting both the
     * {@code Bearer} and {@code DPoP} schemes (case-insensitive).
     *
     * @param authorization the raw Authorization header value (nullable)
     * @return the token, or null if absent/blank/unrecognized scheme
     */
    public static String tokenFromAuthorization(String authorization) {
        if (authorization == null) {
            return null;
        }
        String trimmed = authorization.strip();
        for (String scheme : new String[] {BEARER_SCHEME, DPOP_SCHEME}) {
            if (trimmed.regionMatches(true, 0, scheme, 0, scheme.length())) {
                String token = trimmed.substring(scheme.length()).strip();
                return token.isEmpty() ? null : token;
            }
        }
        return null;
    }
}
