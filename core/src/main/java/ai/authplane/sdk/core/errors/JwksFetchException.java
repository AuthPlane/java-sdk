package ai.authplane.sdk.core.errors;

import java.io.Serial;

/**
 * Thrown when the JWKS endpoint cannot be fetched and no cached JWKS is available to fall back on.
 *
 * <p>If a stale cache exists, the SDK uses it silently (logs a warning) and does NOT throw this
 * exception. This exception only occurs when there is no cached JWKS at all and the fetch fails.
 *
 * <p>Maps to HTTP 401.
 */
public class JwksFetchException extends AuthplaneException {

    @Serial private static final long serialVersionUID = 1L;

    public JwksFetchException(String message) {
        super(message);
    }

    public JwksFetchException(String message, Throwable cause) {
        super(message, cause);
    }
}
