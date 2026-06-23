package ai.authplane.sdk.core.errors;

import java.io.Serial;

/** Thrown when the JWT {@code exp} claim is in the past (beyond clock skew). Maps to HTTP 401. */
public class TokenExpiredException extends AuthplaneException {

    @Serial private static final long serialVersionUID = 1L;

    public TokenExpiredException(String message) {
        super(message);
    }

    public TokenExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
}
