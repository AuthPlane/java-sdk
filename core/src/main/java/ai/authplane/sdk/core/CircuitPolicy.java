package ai.authplane.sdk.core;

import java.io.IOException;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ai.authplane.sdk.core.errors.TokenExchangeException;
import ai.authplane.sdk.core.fetching.ssrf.SsrfException;

/**
 * Decides whether a failure from AS token/introspection/revocation flows should increment the
 * circuit breaker, distinguishing OAuth business errors (which do not trip it) from infrastructure
 * failures (which do).
 */
public final class CircuitPolicy {

    private static final Pattern OAUTH_POST_HTTP_STATUS =
            Pattern.compile("OAuth POST failed: HTTP (\\d+)");

    /** OAuth {@code error} values where the AS responded correctly — do not trip the breaker. */
    private static final Set<String> OAUTH_ERRORS_NO_CIRCUIT =
            Set.of(
                    "consent_required",
                    "interaction_required",
                    "invalid_grant",
                    "invalid_scope",
                    "invalid_dpop_proof",
                    "invalid_request",
                    "unsupported_grant_type");

    private static final int MAX_CAUSE_DEPTH = 8;

    private CircuitPolicy() {}

    /**
     * Returns true if this failure should call {@link CircuitBreaker#recordFailure()}.
     *
     * @param t the caught throwable (possibly wrapped)
     */
    public static boolean shouldTrip(Throwable t) {
        return shouldTrip(t, 0);
    }

    private static boolean shouldTrip(Throwable t, int depth) {
        if (t == null || depth > MAX_CAUSE_DEPTH) {
            return false;
        }
        if (t instanceof SsrfException) {
            return false;
        }
        if (t instanceof TokenExchangeException tex) {
            return shouldTripTokenExchange(tex, depth);
        }
        if (t instanceof IOException) {
            return shouldTripIOException((IOException) t);
        }
        return true;
    }

    private static boolean shouldTripTokenExchange(TokenExchangeException tex, int depth) {
        String code = tex.oauthError();
        if (code == null && tex.getCause() != null) {
            return shouldTrip(tex.getCause(), depth + 1);
        }
        if (code == null) {
            return true;
        }
        if (OAUTH_ERRORS_NO_CIRCUIT.contains(code)) {
            return false;
        }
        if ("invalid_client".equals(code)
                || "unauthorized_client".equals(code)
                || "server_error".equals(code)) {
            return true;
        }
        return false;
    }

    /**
     * Introspection/revocation use {@link
     * ai.authplane.sdk.core.oauth.OAuthPostSupport#requireSuccessStatus} which throws {@link
     * IOException} without OAuth body — use HTTP status only.
     */
    private static boolean shouldTripIOException(IOException e) {
        Matcher m = OAUTH_POST_HTTP_STATUS.matcher(String.valueOf(e.getMessage()));
        if (m.find()) {
            try {
                int status = Integer.parseInt(m.group(1));
                if (status >= 500) {
                    return true;
                }
                // Introspection/revocation do not parse OAuth JSON; 401/403 often mean bad client
                // auth (invalid_client). Other 4xx are usually per-request OAuth errors.
                if (status == 401 || status == 403) {
                    return true;
                }
                if (status >= 400) {
                    return false;
                }
            } catch (NumberFormatException ignored) {
                // fall through
            }
        }
        return true;
    }
}
