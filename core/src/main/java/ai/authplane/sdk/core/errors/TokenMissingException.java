package ai.authplane.sdk.core.errors;

import java.io.Serial;

/** Thrown when no Bearer token is present in the request. Maps to HTTP 401. */
public class TokenMissingException extends AuthplaneException {

    @Serial private static final long serialVersionUID = 1L;

    public TokenMissingException(String message) {
        super(message);
    }
}
