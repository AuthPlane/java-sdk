package ai.authplane.sdk.core.errors;

import java.io.Serial;

/**
 * Thrown when JWT signature verification fails, or when the {@code kid} in the token header cannot
 * be found in the JWKS (even after a forced refresh). Maps to HTTP 401.
 */
public class InvalidSignatureException extends AuthplaneException {

    @Serial private static final long serialVersionUID = 1L;

    public InvalidSignatureException(String message) {
        super(message);
    }

    public InvalidSignatureException(String message, Throwable cause) {
        super(message, cause);
    }
}
