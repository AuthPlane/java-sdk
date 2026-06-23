package ai.authplane.sdk.core.dpop;

import java.io.Serial;

/**
 * Thrown when a request carries a DPoP signal — a DPoP-bound access token ({@code cnf.jkt}) or a
 * DPoP proof header — but the resource has not been configured to support DPoP via {@link
 * InboundDPoPOptions}.
 *
 * <p>RFC 9449 §6 defines how DPoP-supporting resources validate the proof binding but does not
 * prescribe behavior for resources that have not opted into DPoP. This SDK fails closed: accepting
 * a DPoP-bound token without validating the binding would silently drop sender-binding (the very
 * property DPoP is meant to provide), and applying ad-hoc defaults that were never advertised in
 * the Protected Resource Metadata would be surprising to clients. Rejecting up front is the
 * defensive choice.
 *
 * <p>Because the resource does not support DPoP, the resulting {@code WWW-Authenticate} challenge
 * uses the {@code Bearer} scheme — challenging with {@code DPoP} would advertise a capability the
 * resource lacks. It still maps to HTTP 401.
 */
public class DPoPNotSupportedException extends DPoPException {

    @Serial private static final long serialVersionUID = 1L;

    public DPoPNotSupportedException(String message) {
        super(message);
    }
}
