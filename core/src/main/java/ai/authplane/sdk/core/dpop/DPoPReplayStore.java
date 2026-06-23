package ai.authplane.sdk.core.dpop;

import java.time.Instant;

/** Atomic replay store for inbound DPoP proof validation. */
public interface DPoPReplayStore {

    /**
     * Stores the given jti until the supplied expiry if it has not already been seen.
     *
     * @param jti proof JWT ID
     * @param expiresAt instant after which the replay entry may be evicted
     * @return true when the jti was stored for first use, false when it was already present
     */
    boolean storeIfAbsent(String jti, Instant expiresAt);
}
