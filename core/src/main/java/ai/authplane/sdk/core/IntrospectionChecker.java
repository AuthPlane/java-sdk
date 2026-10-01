package ai.authplane.sdk.core;

import java.util.concurrent.atomic.AtomicBoolean;
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
 * <p>authserver 0.1.2 and later answer {@code active: false} unless the introspecting client is
 * confidential and is either the client the token was issued to or a runtime-client of the resource
 * named in {@code aud}. A checker built without credentials, or with the wrong ones, therefore
 * rejects every token as revoked; both cases are logged so the cause is not silent.
 *
 * <p>Package-private — created by {@link AuthplaneResource} when {@link
 * ResourceOptions#useBuiltinRevocationChecker()} is set.
 */
class IntrospectionChecker implements RevocationChecker {

    private static final Logger LOG = Logger.getLogger(IntrospectionChecker.class.getName());

    private final AuthplaneClient client;
    private final AtomicBoolean ownershipWarned = new AtomicBoolean();

    IntrospectionChecker(AuthplaneClient client) {
        this.client = client;
        if (client.authProvider == null) {
            LOG.warning(
                    "Built-in introspection checker configured without an AuthProvider: authserver"
                            + " >= 0.1.2 answers active=false to unauthenticated introspection, so"
                            + " every token will be rejected as revoked. Set authProvider(new"
                            + " ASCredentials(clientId, clientSecret)) on the client builder to a"
                            + " confidential client that is the issuing client or a runtime-client"
                            + " of this resource.");
        }
    }

    /**
     * Returns {@code true} if the token is not active according to RFC 7662 introspection.
     *
     * <p>Exceptions propagate to the verifier, which applies the fail-open/closed policy configured
     * via {@link ResourceOptions.Builder#failClosed()}.
     *
     * <p>The token reaching this method has already passed local JWT verification, so an {@code
     * active=false} answer is either a real revocation or the AS not recognising this resource
     * server as the token's owner. The first such answer is logged once per checker with the
     * runtime-client requirement; later ones are not, so a busy server is not flooded.
     *
     * @param rawToken the raw JWT string to introspect
     * @param jti the {@code jti} claim (for logging)
     */
    @Override
    public boolean isRevoked(String rawToken, String jti) throws Exception {
        var resp = client.introspect(rawToken).get();
        if (resp.active()) {
            return false;
        }
        if (ownershipWarned.compareAndSet(false, true)) {
            LOG.warning(
                    "Introspection returned active=false for jti='"
                            + jti
                            + "' although the token passed local JWT verification. Unless the"
                            + " token was revoked, the AS did not recognise this resource server"
                            + " as the token's owner: authserver >= 0.1.2 answers active=false"
                            + " unless the introspecting client is the issuing client or a"
                            + " runtime-client of the resource named in aud. Register it with:"
                            + " authserver admin resource runtime-client add --client-id"
                            + " <rs-client-id> --slug <resource-slug>. Logged once per checker.");
        }
        return true;
    }
}
