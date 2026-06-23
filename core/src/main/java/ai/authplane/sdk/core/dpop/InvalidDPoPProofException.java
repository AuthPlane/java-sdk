package ai.authplane.sdk.core.dpop;

import java.io.Serial;

/** Thrown when a DPoP proof is malformed or fails validation. */
public class InvalidDPoPProofException extends DPoPException {

    @Serial private static final long serialVersionUID = 1L;

    public InvalidDPoPProofException(String message) {
        super(message);
    }

    public InvalidDPoPProofException(String message, Throwable cause) {
        super(message, cause);
    }
}
