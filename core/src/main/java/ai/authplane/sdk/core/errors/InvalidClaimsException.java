package ai.authplane.sdk.core.errors;

import java.io.Serial;

/**
 * Thrown when JWT claims fail validation: - Required claim is missing (iss, aud, sub, client_id,
 * exp, nbf, iat, jti) - Issuer does not match configured issuer - Audience does not match
 * configured resource - {@code typ} header is not "at+jwt" - Algorithm not in the allowed list -
 * {@code iat} is more than clock_skew seconds in the future Maps to HTTP 401.
 */
public class InvalidClaimsException extends AuthplaneException {

    @Serial private static final long serialVersionUID = 1L;

    public InvalidClaimsException(String message) {
        super(message);
    }

    public InvalidClaimsException(String message, Throwable cause) {
        super(message, cause);
    }
}
