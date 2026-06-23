package ai.authplane.sdk.core.errors;

import java.io.Serial;

/**
 * Base exception for all Authplane SDK errors.
 *
 * <p>HTTP mapping (for framework adapters): InsufficientScopeException → 403 Forbidden All other
 * subclasses → 401 Unauthorized
 */
public class AuthplaneException extends RuntimeException {

    @Serial private static final long serialVersionUID = 1L;

    public AuthplaneException(String message) {
        super(message);
    }

    public AuthplaneException(String message, Throwable cause) {
        super(message, cause);
    }
}
