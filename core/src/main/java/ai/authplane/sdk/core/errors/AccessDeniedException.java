package ai.authplane.sdk.core.errors;

import java.io.Serial;

/**
 * Thrown when the Authorization Server answers a token request with {@code access_denied} (HTTP
 * 403).
 *
 * <p>On a cross-client token exchange this means the operator has not allowlisted the exchanging
 * client on the target Resource ({@code policy.exchange.allowed_client_ids}). Unlike {@link
 * ConsentRequiredException}, re-prompting the user does not fix it; the Resource policy must be
 * changed. The AS responded correctly, so this does not count toward the circuit breaker.
 *
 * <p>The simple name collides with Spring Security's {@code
 * org.springframework.security.access.AccessDeniedException}, which the Spring adapter throws for
 * an authorization failure. Both are unchecked, so catching the wrong one compiles and catches
 * nothing; import this one by its full name in any class that also uses Spring Security's.
 */
public final class AccessDeniedException extends TokenExchangeException {

    @Serial private static final long serialVersionUID = 1L;

    /**
     * @param message human-readable message (the AS {@code error_description} when present)
     */
    public AccessDeniedException(String message) {
        super(message, "access_denied");
    }
}
