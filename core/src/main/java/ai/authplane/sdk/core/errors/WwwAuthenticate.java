package ai.authplane.sdk.core.errors;

import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

import ai.authplane.sdk.core.dpop.DPoPException;
import ai.authplane.sdk.core.dpop.DPoPNotSupportedException;
import ai.authplane.sdk.core.dpop.MultipleDpopProofsException;

/**
 * Builds RFC 6750 §3 {@code WWW-Authenticate} header values from SDK exceptions.
 *
 * <p>Maps SDK errors to the correct error code and authentication scheme:
 *
 * <ul>
 *   <li>{@link InsufficientScopeException} → {@code insufficient_scope}
 *   <li>{@link MultipleDpopProofsException} → {@code DPoP} scheme with {@code invalid_dpop_proof}
 *       (RFC 9449 §7.1 — the spec-defined error code for §4.3 proof-validation failures)
 *   <li>Other {@link DPoPException} subclasses → {@code DPoP} scheme with {@code invalid_token},
 *       except {@link DPoPNotSupportedException} (the resource does not support DPoP, so it
 *       challenges with {@code Bearer})
 *   <li>All other {@link AuthplaneException} → {@code Bearer} scheme with {@code invalid_token}
 * </ul>
 *
 * <p>Every interpolated value (realm, error_description, scope, resource_metadata) is sanitised:
 * control characters (incl. CR/LF) are stripped (RFC 9110 §5.6.4 — they cannot appear inside a
 * quoted-string anyway, and letting CR/LF through would allow header injection) and backslash +
 * double-quote escaped.
 *
 * <p>Example output: {@code Bearer error="invalid_token", error_description="Token expired"}
 */
public final class WwwAuthenticate {

    private WwwAuthenticate() {}

    /**
     * Optional challenge parameters for {@link #of(AuthplaneException, ChallengeOptions)}.
     *
     * <p>All fields are optional; pass {@link #empty()} when no extra parameters are needed. Empty
     * strings and empty scope lists are treated as absent.
     *
     * @param realm RFC 6750 §3 {@code realm} parameter — typically the resource URL
     * @param resourceMetadataUrl RFC 9728 §5.3 {@code resource_metadata} parameter — absolute URL
     *     to the Protected Resource Metadata document so clients can discover the authorization
     *     server
     * @param scope RFC 6750 §3 {@code scope} parameter — space-joined into a single quoted-string;
     *     primarily emitted alongside {@code insufficient_scope} so the client knows which scopes
     *     it must obtain
     */
    public record ChallengeOptions(String realm, String resourceMetadataUrl, List<String> scope) {

        private static final ChallengeOptions EMPTY = new ChallengeOptions(null, null, List.of());

        public ChallengeOptions {
            scope = scope == null ? List.of() : List.copyOf(scope);
        }

        /** Returns a shared empty options instance (no realm, no PRM URL, no scope). */
        public static ChallengeOptions empty() {
            return EMPTY;
        }

        /** Returns a copy with {@code realm} replaced. */
        public ChallengeOptions withRealm(String newRealm) {
            return new ChallengeOptions(newRealm, resourceMetadataUrl, scope);
        }

        /** Returns a copy with {@code resourceMetadataUrl} replaced. */
        public ChallengeOptions withResourceMetadataUrl(String url) {
            return new ChallengeOptions(realm, url, scope);
        }

        /** Returns a copy with {@code scope} replaced. */
        public ChallengeOptions withScope(List<String> newScope) {
            return new ChallengeOptions(realm, resourceMetadataUrl, newScope);
        }
    }

    /** C0 control characters (incl. CR/LF) and DEL — illegal in an HTTP header field-value. */
    private static final Pattern CONTROL_CHARS = Pattern.compile("[\\x00-\\x1f\\x7f]");

    /**
     * Escapes a string for use inside an HTTP quoted-string (RFC 9110 §5.6.4). All control
     * characters (C0 range incl. CR/LF, plus DEL) are stripped — they are illegal in a header
     * field-value and CR/LF would otherwise enable header injection; backslashes and double quotes
     * are then escaped with a preceding backslash.
     */
    static String escapeQuotedString(String value) {
        if (value == null) return "";
        // Strip control chars first, then escape the backslash before the quote so the backslash it
        // introduces ahead of `"` isn't double-escaped on a later pass.
        return CONTROL_CHARS
                .matcher(value)
                .replaceAll("")
                .replace("\\", "\\\\")
                .replace("\"", "\\\"");
    }

    /**
     * Builds a {@code WWW-Authenticate} header value for the given error.
     *
     * @param error the SDK exception
     * @return the header value
     */
    public static String of(AuthplaneException error) {
        return of(error, ChallengeOptions.empty());
    }

    /**
     * Builds a {@code WWW-Authenticate} header value for the given error, including an optional
     * realm. Convenience overload equivalent to {@code of(error,
     * ChallengeOptions.empty().withRealm(realm))}.
     *
     * @param error the SDK exception
     * @param realm the realm parameter (empty string to omit)
     * @return the header value
     */
    public static String of(AuthplaneException error, String realm) {
        return of(error, ChallengeOptions.empty().withRealm(realm));
    }

    /**
     * Builds a {@code WWW-Authenticate} header value for the given error and challenge options.
     * Emits, in order: scheme, {@code realm} (if set), {@code error}, {@code error_description},
     * {@code scope} (if non-empty), {@code resource_metadata} (if set). Every interpolated value is
     * sanitised via {@link #escapeQuotedString(String)}.
     *
     * @param error the SDK exception (must not be null)
     * @param options optional challenge parameters; use {@link ChallengeOptions#empty()} when none
     *     are needed
     * @return the header value
     */
    public static String of(AuthplaneException error, ChallengeOptions options) {
        Objects.requireNonNull(error, "error must not be null");
        Objects.requireNonNull(options, "options must not be null");

        String errorCode = errorCodeFor(error);
        String scheme = schemeFor(error);

        StringBuilder sb = new StringBuilder(scheme).append(' ');
        if (options.realm() != null && !options.realm().isEmpty()) {
            sb.append("realm=\"").append(escapeQuotedString(options.realm())).append("\", ");
        }
        sb.append("error=\"").append(errorCode).append("\"");
        sb.append(", error_description=\"")
                .append(escapeQuotedString(error.getMessage()))
                .append("\"");
        if (!options.scope().isEmpty()) {
            sb.append(", scope=\"")
                    .append(escapeQuotedString(String.join(" ", options.scope())))
                    .append("\"");
        }
        if (options.resourceMetadataUrl() != null && !options.resourceMetadataUrl().isEmpty()) {
            sb.append(", resource_metadata=\"")
                    .append(escapeQuotedString(options.resourceMetadataUrl()))
                    .append("\"");
        }
        return sb.toString();
    }

    /**
     * Returns the {@code error} parameter value (RFC 6750 §3.1 / RFC 9449 §7.1) that should be
     * emitted for the given SDK exception. Adapter code that builds framework-specific error
     * responses (e.g. Spring Security's {@code OAuth2Error}) should use this rather than picking an
     * error code itself.
     *
     * @param error the SDK exception
     * @return one of {@code insufficient_scope}, {@code invalid_dpop_proof}, {@code invalid_token}
     */
    public static String errorCodeFor(AuthplaneException error) {
        if (error instanceof InsufficientScopeException) {
            return "insufficient_scope";
        }
        if (error instanceof MultipleDpopProofsException) {
            return "invalid_dpop_proof";
        }
        return "invalid_token";
    }

    /**
     * Returns the authentication scheme name ({@code DPoP} or {@code Bearer}) that should be
     * emitted on the {@code WWW-Authenticate} challenge for the given SDK exception. DPoP-related
     * failures challenge with {@code DPoP} per RFC 9449 §7.1, except {@link
     * DPoPNotSupportedException} which falls back to {@code Bearer} (the resource does not
     * advertise DPoP support).
     *
     * @param error the SDK exception
     * @return {@code "DPoP"} or {@code "Bearer"}
     */
    public static String schemeFor(AuthplaneException error) {
        return error instanceof DPoPException && !(error instanceof DPoPNotSupportedException)
                ? "DPoP"
                : "Bearer";
    }
}
