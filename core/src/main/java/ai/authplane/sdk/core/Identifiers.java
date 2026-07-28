package ai.authplane.sdk.core;

import java.net.URI;

/**
 * Validation for resource and issuer identifiers.
 *
 * <p>RFC 8414 §3.3 and RFC 9728 §3.3 require the advertised issuer/resource to be identical to the
 * configured value — a simple string comparison, not RFC 3986 equivalence. The SDK therefore never
 * rewrites an identifier: well-known URLs are formed by inserting the well-known path segment
 * between the authority and the identifier's path (RFC 8414 §3 / RFC 9728 §3), and validation
 * rejects structurally unusable identifiers instead of repairing them.
 *
 * <p>Thread-safe — all methods are stateless.
 */
public final class Identifiers {

    private Identifiers() {}

    /**
     * Validates that {@code value} is an absolute http(s) URI with an authority and no fragment
     * (RFC 8707 §2 forbids fragments in resource identifiers). Returns {@code value} unchanged —
     * trailing slashes, host case, and explicit ports are all legal identifier variations and are
     * preserved verbatim.
     *
     * @param value the identifier to validate
     * @param label name used in error messages (e.g. "issuer", "resource")
     * @return {@code value}, unchanged
     * @throws IllegalArgumentException when the identifier is structurally invalid
     */
    public static String requireValidIdentifier(String value, String label) {
        URI uri;
        try {
            uri = URI.create(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(label + " is not a valid URI: '" + value + "'", e);
        }
        String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equals("https") || scheme.equals("http"))) {
            throw new IllegalArgumentException(
                    label + " must be an absolute http or https URI: '" + value + "'");
        }
        if (uri.getRawAuthority() == null || uri.getRawAuthority().isEmpty()) {
            throw new IllegalArgumentException(
                    label + " must include an authority: '" + value + "'");
        }
        if (uri.getRawFragment() != null) {
            throw new IllegalArgumentException(
                    label + " must not contain a fragment: '" + value + "'");
        }
        return value;
    }
}
