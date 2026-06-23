package ai.authplane.sdk.core;

import java.util.logging.Logger;

/**
 * Built-in revocation checker that delegates to {@link AuthplaneClient#introspect(String)}.
 *
 * <p>Implements {@link RevocationChecker} so it plugs into the verifier's revocation path alongside
 * custom checkers.
 *
 * <p>Fails open on client exceptions (network errors, missing endpoint, circuit breaker open). A
 * successful introspection response rejects the token unless {@code active} is explicitly {@code
 * true}.
 *
 * <p>Package-private — created by {@link AuthplaneResource} when {@link
 * ResourceOptions#useBuiltinRevocationChecker()} is set.
 */
class IntrospectionChecker implements RevocationChecker {

    private static final Logger LOG = Logger.getLogger(IntrospectionChecker.class.getName());

    private final AuthplaneClient client;

    IntrospectionChecker(AuthplaneClient client) {
        this.client = client;
    }

    /**
     * Returns {@code true} if the token is not active according to RFC 7662 introspection.
     *
     * <p>Exceptions propagate to the verifier, which applies the fail-open/closed policy configured
     * via {@link ResourceOptions.Builder#failClosed()}.
     *
     * @param rawToken the raw JWT string to introspect
     * @param jti the {@code jti} claim (for logging)
     */
    @Override
    public boolean isRevoked(String rawToken, String jti) throws Exception {
        var resp = client.introspect(rawToken).get();
        return !resp.active();
    }
}
