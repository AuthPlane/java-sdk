package ai.authplane.sdk.core.dpop;

import java.util.Map;
import java.util.Objects;

/**
 * Validated DPoP proof result returned alongside {@link ai.authplane.sdk.core.VerificationResult}.
 *
 * @param jti unique proof identifier
 * @param htm normalized HTTP method from the accepted proof
 * @param htu normalized target URL from the accepted proof
 * @param iat issued-at time in Unix epoch seconds
 * @param exp optional expiration time in Unix epoch seconds
 * @param keyThumbprint RFC 7638 thumbprint of the accepted proof key
 * @param raw immutable snapshot of the accepted proof claims. Modifications are unsupported and
 *     callers must not attempt to mutate the returned structure.
 */
public record VerifiedDPoPProof(
        String jti,
        String htm,
        String htu,
        long iat,
        Long exp,
        String keyThumbprint,
        Map<String, Object> raw) {

    /** Validates required fields and makes a defensive copy of the raw claims map. */
    public VerifiedDPoPProof {
        Objects.requireNonNull(jti, "jti must not be null");
        Objects.requireNonNull(htm, "htm must not be null");
        Objects.requireNonNull(htu, "htu must not be null");
        Objects.requireNonNull(keyThumbprint, "keyThumbprint must not be null");
        raw = raw != null ? Map.copyOf(raw) : Map.of();
    }
}
