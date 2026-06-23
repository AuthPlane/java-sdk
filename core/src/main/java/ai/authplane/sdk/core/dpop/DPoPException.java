package ai.authplane.sdk.core.dpop;

import java.io.Serial;

import ai.authplane.sdk.core.errors.AuthplaneException;

/**
 * Base exception for all DPoP-related errors.
 *
 * <p>Callers who need to handle any DPoP failure uniformly can catch this single type instead of
 * the four concrete subclasses.
 */
public class DPoPException extends AuthplaneException {

    @Serial private static final long serialVersionUID = 1L;

    public DPoPException(String message) {
        super(message);
    }

    public DPoPException(String message, Throwable cause) {
        super(message, cause);
    }
}
