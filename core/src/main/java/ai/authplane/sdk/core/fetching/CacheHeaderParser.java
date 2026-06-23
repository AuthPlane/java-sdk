package ai.authplane.sdk.core.fetching;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Parses RFC 7234 HTTP cache headers to determine a server-suggested expiry time.
 *
 * <p>The effective cache TTL used by DocumentCache is: effectiveTTL = min(configuredTTL,
 * serverExpiry) where serverExpiry is the value returned by this class.
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
     * @return Unix epoch seconds of expiry, 0 for no-store/no-cache, or null
     */
    public static Long parseExpiresAt(Map<String, String> headers) {
        String cacheControl = headers.get("cache-control");
        if (cacheControl != null) {
            String cc = cacheControl.toLowerCase();

            // no-store or no-cache → treat as immediately expired
            if (cc.contains("no-store") || cc.contains("no-cache")) {
                return 0L;
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
