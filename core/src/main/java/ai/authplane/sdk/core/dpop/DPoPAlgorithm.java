package ai.authplane.sdk.core.dpop;

import com.nimbusds.jose.JWSAlgorithm;

/** Supported asymmetric algorithms for DPoP proof generation and validation. */
public enum DPoPAlgorithm {
    ES256(JWSAlgorithm.ES256, "ES256"),
    RS256(JWSAlgorithm.RS256, "RS256");

    private final JWSAlgorithm jwsAlgorithm;
    private final String value;

    DPoPAlgorithm(JWSAlgorithm jwsAlgorithm, String value) {
        this.jwsAlgorithm = jwsAlgorithm;
        this.value = value;
    }

    /** Nimbus JOSE algorithm identifier used for signing and verification. */
    public JWSAlgorithm jwsAlgorithm() {
        return jwsAlgorithm;
    }

    /** Wire-format algorithm value, for example {@code ES256}. */
    public String value() {
        return value;
    }

    /** Parses a supported DPoP algorithm name. */
    public static DPoPAlgorithm fromValue(String value) {
        for (DPoPAlgorithm candidate : values()) {
            if (candidate.value.equals(value)) {
                return candidate;
            }
        }
        throw new IllegalArgumentException("Unsupported DPoP algorithm: " + value);
    }
}
