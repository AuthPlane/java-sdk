package ai.authplane.sdk.core.errors;

import java.io.Serial;

/**
 * Thrown when the Authorization Server answers a token request with {@code invalid_target} (RFC
 * 8707 §2.2, HTTP 400).
 *
 * <p>The {@code resource} parameter did not match a resource granted to the token byte for byte — a
 * trailing slash or a different scheme is enough. The AS responded correctly, so this does not
 * count toward the circuit breaker.
 */
public final class InvalidTargetException extends TokenExchangeException {

    @Serial private static final long serialVersionUID = 1L;

    /**
     * @param message human-readable message (the AS {@code error_description} when present)
     */
    public InvalidTargetException(String message) {
        super(message, "invalid_target");
    }
}
