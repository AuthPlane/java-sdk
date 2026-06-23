package ai.authplane.sdk.core.dpop;

import java.io.Serial;

/** Thrown when a DPoP proof jti is replayed within the accepted validity window. */
public class DPoPReplayDetectedException extends DPoPException {

    @Serial private static final long serialVersionUID = 1L;

    public DPoPReplayDetectedException(String message) {
        super(message);
    }
}
