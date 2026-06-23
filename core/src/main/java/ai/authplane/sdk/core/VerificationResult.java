package ai.authplane.sdk.core;

import java.util.Objects;

import ai.authplane.sdk.core.dpop.VerifiedDPoPProof;

/**
 * Unified verifier result for bearer and DPoP-bound tokens.
 *
 * @param claims verified access-token claims
 * @param dpopProof validated DPoP proof details when inbound DPoP validation ran and succeeded;
 *     {@code null} for bearer-only verification
 */
public record VerificationResult(VerifiedClaims claims, VerifiedDPoPProof dpopProof) {

    public VerificationResult {
        Objects.requireNonNull(claims, "claims must not be null");
    }

    /** Returns {@code true} if the result includes a validated DPoP proof. */
    public boolean hasDpopProof() {
        return dpopProof != null;
    }

    /** Creates a bearer-only verification result. */
    public static VerificationResult bearer(VerifiedClaims claims) {
        return new VerificationResult(claims, null);
    }

    /** Creates a verification result that includes an accepted DPoP proof. */
    public static VerificationResult dpop(VerifiedClaims claims, VerifiedDPoPProof proof) {
        return new VerificationResult(
                claims, Objects.requireNonNull(proof, "proof must not be null"));
    }
}
