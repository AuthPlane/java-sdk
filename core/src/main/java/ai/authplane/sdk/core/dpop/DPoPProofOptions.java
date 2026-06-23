package ai.authplane.sdk.core.dpop;

/**
 * Optional per-proof inputs for outbound DPoP proof generation.
 *
 * @param nonce DPoP nonce to embed in the proof, or empty when none is required
 * @param accessToken access token to bind through {@code ath}, or empty when not needed
 */
public record DPoPProofOptions(String nonce, String accessToken) {

    public DPoPProofOptions {
        nonce = nonce != null ? nonce : "";
        accessToken = accessToken != null ? accessToken : "";
    }

    /** Returns empty proof options with no nonce and no access-token binding. */
    public static DPoPProofOptions defaults() {
        return new DPoPProofOptions("", "");
    }
}
