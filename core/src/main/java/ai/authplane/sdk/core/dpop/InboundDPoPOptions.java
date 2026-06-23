package ai.authplane.sdk.core.dpop;

import java.util.Objects;
import java.util.Set;

import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.ResourceOptions;

/**
 * Verifier-scoped inbound DPoP validation configuration (RFC 9449 §7.1, RFC 9728 §2).
 *
 * <p>Passing any instance — even a default-constructed one — to {@link
 * ResourceOptions.Builder#inboundDPoP(InboundDPoPOptions)} is the on/off switch for advertising
 * DPoP in the resource's Protected Resource Metadata ({@code dpop_signing_alg_values_supported} and
 * {@code dpop_bound_access_tokens_required}) and for verify-time enforcement. Leaving it unset
 * ({@code null}) keeps DPoP fields out of the PRM and makes the resource reject any DPoP signal at
 * verify time. See {@link AuthplaneResource#verify(String, VerificationRequestContext)} for the
 * three enforcement modes.
 *
 * @param replayStore replay detector used for accepted proof {@code jti} values
 * @param maxProofAgeSeconds maximum proof age accepted from {@code iat}
 * @param clockSkewSeconds allowable clock skew for proof time validation
 * @param allowedProofAlgorithms accepted JOSE {@code alg} values for DPoP proofs; also advertised
 *     as {@code dpop_signing_alg_values_supported}. Only the asymmetric algorithms {@code RS256}
 *     and {@code ES256} are permitted. Pass {@code null} to accept the defaults; an empty set or
 *     any other algorithm (e.g. {@code none}, {@code HS256}) is rejected at construction.
 * @param required when {@code true} ("Required" mode), the resource advertises {@code
 *     dpop_bound_access_tokens_required: true} and rejects bearer-only access tokens at verify
 *     time. When {@code false} ("Supported" mode), the resource advertises DPoP capability but
 *     still accepts bearer-only tokens.
 */
public record InboundDPoPOptions(
        DPoPReplayStore replayStore,
        int maxProofAgeSeconds,
        int clockSkewSeconds,
        Set<String> allowedProofAlgorithms,
        boolean required) {

    /** Algorithms permitted for DPoP proofs — asymmetric only (RFC 9449 §7.1, RFC 8725). */
    private static final Set<String> SUPPORTED_PROOF_ALGORITHMS = Set.of("RS256", "ES256");

    /** Validates that all options are within acceptable bounds. */
    public InboundDPoPOptions {
        Objects.requireNonNull(replayStore, "replayStore must not be null");
        if (maxProofAgeSeconds <= 0) {
            throw new IllegalArgumentException(
                    "maxProofAgeSeconds must be positive, got " + maxProofAgeSeconds);
        }
        if (clockSkewSeconds < 0) {
            throw new IllegalArgumentException(
                    "clockSkewSeconds must not be negative, got " + clockSkewSeconds);
        }
        allowedProofAlgorithms = validateAlgorithms(allowedProofAlgorithms);
    }

    /**
     * Convenience constructor for the "Supported" mode ({@code required == false}).
     *
     * @param replayStore replay detector for accepted proof {@code jti} values
     * @param maxProofAgeSeconds maximum proof age accepted from {@code iat}
     * @param clockSkewSeconds allowable clock skew for proof time validation
     * @param allowedProofAlgorithms accepted DPoP proof algorithms, or {@code null} for defaults
     */
    public InboundDPoPOptions(
            DPoPReplayStore replayStore,
            int maxProofAgeSeconds,
            int clockSkewSeconds,
            Set<String> allowedProofAlgorithms) {
        this(replayStore, maxProofAgeSeconds, clockSkewSeconds, allowedProofAlgorithms, false);
    }

    private static Set<String> validateAlgorithms(Set<String> algorithms) {
        if (algorithms == null) {
            return SUPPORTED_PROOF_ALGORITHMS;
        }
        if (algorithms.isEmpty()) {
            throw new IllegalArgumentException(
                    "allowedProofAlgorithms must be non-empty; pass null to accept the default "
                            + SUPPORTED_PROOF_ALGORITHMS);
        }
        for (String alg : algorithms) {
            if (!SUPPORTED_PROOF_ALGORITHMS.contains(alg)) {
                throw new IllegalArgumentException(
                        "Unsupported DPoP proof algorithm '"
                                + alg
                                + "'; only "
                                + SUPPORTED_PROOF_ALGORITHMS
                                + " are permitted");
            }
        }
        return Set.copyOf(algorithms);
    }

    /** Returns the default inbound settings ("Supported" mode) using the supplied replay store. */
    public static InboundDPoPOptions defaults(DPoPReplayStore replayStore) {
        return new InboundDPoPOptions(replayStore, 300, 30, SUPPORTED_PROOF_ALGORITHMS, false);
    }

    /**
     * Returns a copy of these options with the {@code required} flag set to the given value.
     *
     * @param required whether DPoP-bound access tokens are mandatory at this resource
     * @return a new options instance differing only in the {@code required} flag
     */
    public InboundDPoPOptions withRequired(boolean required) {
        return new InboundDPoPOptions(
                replayStore,
                maxProofAgeSeconds,
                clockSkewSeconds,
                allowedProofAlgorithms,
                required);
    }
}
