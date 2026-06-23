package ai.authplane.sdk.core;

/**
 * Custom revocation checker for JWT tokens.
 *
 * <p>Implement this interface to plug in your own revocation logic (e.g. a Redis blocklist,
 * database lookup, or external API call).
 *
 * <p>The checker is invoked after all cryptographic validation succeeds. Return {@code true} to
 * reject the token as revoked; return {@code false} to accept it. Any exception thrown is
 * propagated to the caller of {@link AuthplaneResource#verify(String)}.
 *
 * <p>Both the raw token string and its {@code jti} claim are provided. Custom checkers that only
 * need the identifier can simply ignore {@code rawToken}.
 *
 * @see ResourceOptions.Builder#revocationChecker(RevocationChecker)
 */
@FunctionalInterface
public interface RevocationChecker {

    /**
     * Returns {@code true} if the token should be considered revoked.
     *
     * @param rawToken the compact serialization of the JWT (for use with RFC 7662 POST)
     * @param jti the JWT unique identifier ({@code jti} claim)
     * @return {@code true} to reject the token, {@code false} to accept it
     * @throws Exception on any error (propagated to the {@code verify()} caller)
     */
    boolean isRevoked(String rawToken, String jti) throws Exception;

    /** Returns a no-op checker that always accepts tokens (revocation disabled). */
    static RevocationChecker noOp() {
        return (token, jti) -> false;
    }
}
