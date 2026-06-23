package ai.authplane.sdk.core.errors;

import java.io.Serial;

/**
 * Thrown when a token's {@code jti} is found to be revoked via RFC 7662 introspection or a custom
 * revocation checker. Maps to HTTP 401.
 */
public class TokenRevokedException extends AuthplaneException {

    @Serial private static final long serialVersionUID = 1L;

    public TokenRevokedException(String message) {
        super(message);
    }
}
