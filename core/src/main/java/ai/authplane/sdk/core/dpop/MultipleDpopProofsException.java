package ai.authplane.sdk.core.dpop;

import java.io.Serial;

/**
 * Thrown when a verification request carries more than one {@code DPoP} HTTP header field.
 *
 * <p>RFC 9449 §4.3 #1: receiving servers MUST ensure "there is not more than one {@code DPoP} HTTP
 * request header field." A request with multiple proofs is structurally ambiguous — an attacker
 * could bundle a stolen but valid proof alongside a forged one — so the rejection happens before
 * any proof-content validation runs.
 *
 * <p>Per RFC 9449 §7.1, the {@code WWW-Authenticate} challenge emitted for this rejection carries
 * {@code error="invalid_dpop_proof"}.
 */
public class MultipleDpopProofsException extends DPoPException {

    @Serial private static final long serialVersionUID = 1L;

    public MultipleDpopProofsException(String message) {
        super(message);
    }

    public MultipleDpopProofsException(String message, Throwable cause) {
        super(message, cause);
    }
}
