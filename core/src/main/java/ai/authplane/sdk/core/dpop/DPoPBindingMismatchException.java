package ai.authplane.sdk.core.dpop;

import java.io.Serial;

/** Thrown when a DPoP proof does not match the token sender binding. */
public class DPoPBindingMismatchException extends DPoPException {

    @Serial private static final long serialVersionUID = 1L;

    public DPoPBindingMismatchException(String message) {
        super(message);
    }
}
