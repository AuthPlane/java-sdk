package ai.authplane.sdk.core.fetching;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Parses RFC 7234 HTTP cache headers to determine a server-suggested expiry time.
 *
 * <p>A {@code null} return means the server expressed no cacheable preference, and the caller's
 * configured interval governs. That is what {@code no-store} and {@code no-cache} return: they say
 * the response should not be reused, which for a document this SDK must keep serving is not an
 * expiry it can honour — the caller falls back to its own interval rather than treating the
 * document as permanently stale. Both siblings model it the same way, as go's zero {@code
 * time.Time} and ts's {@code undefined}.
 *
 * <p>A non-null return is an absolute expiry, and {@code DocumentCache} shortens its configured TTL
 * to it when it is in the future. An expiry already in the past — a stale {@code Expires:}, or
 * {@code max-age=0} — is discarded there for the same reason.
 *
 * <p>Thread-safe — all methods are stateless.
 */
public final class CacheHeaderParser {

    private static final Logger LOG = Logger.getLogger(CacheHeaderParser.class.getName());

    private CacheHeaderParser() {}

    /**
     * Extracts the server-suggested expiry as a Unix epoch second, or null if the server did not
     * provide cache directives.
     *
     * @param headers response headers with lower-cased header names
     * @return Unix epoch seconds of expiry, or {@code null} when the server expressed no usable
     *     preference — no cache headers, an unparseable value, or {@code no-store}/{@code no-cache}
     */
    public static Long parseExpiresAt(Map<String, String> headers) {
        String cacheControl = headers.get("cache-control");
        if (cacheControl != null) {
            String cc = cacheControl.toLowerCase();

            // no-store / no-cache → no usable preference, not "expired now".
            //
            // These used to return 0L, which DocumentCache read as an absolute expiry at the
            // epoch: subtracting the cache timestamp gave a TTL of about -1.7e9, the document was
            // expired on every read, and every read paid a synchronous fetch. The cache now
            // discards a non-future expiry, which made the 0L sentinel indistinguishable from
            // null — it carried no information while the javadoc still claimed it meant
            // "immediately expired". Returning null says the thing that is true.
            if (cc.contains("no-store") || cc.contains("no-cache")) {
                return null;
            }

            // max-age=N
            int maxAgeIdx = cc.indexOf("max-age=");
            if (maxAgeIdx != -1) {
                String rest = cc.substring(maxAgeIdx + "max-age=".length());
                // Find end of numeric value (comma, space, or end of string)
                int end = rest.length();
                for (int i = 0; i < rest.length(); i++) {
                    char c = rest.charAt(i);
                    if (!Character.isDigit(c)) {
                        end = i;
                        break;
                    }
                }
                try {
                    long maxAge = Long.parseLong(rest.substring(0, end));
                    return System.currentTimeMillis() / 1000L + maxAge;
                } catch (NumberFormatException e) {
                    LOG.fine("Could not parse max-age from Cache-Control: " + cacheControl);
                }
            }
        }

        // Expires: <HTTP-date>
        String expires = headers.get("expires");
        if (expires != null) {
            try {
                ZonedDateTime dt =
                        ZonedDateTime.parse(expires.trim(), DateTimeFormatter.RFC_1123_DATE_TIME);
                return dt.toEpochSecond();
            } catch (DateTimeParseException e) {
                LOG.fine("Could not parse Expires header: " + expires);
            }
        }

        return null; // no server preference
    }
}
