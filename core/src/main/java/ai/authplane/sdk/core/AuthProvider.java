package ai.authplane.sdk.core;

import java.util.Map;

/**
 * Supplies the HTTP authentication headers used when the SDK calls the Authorization Server (the
 * RFC 6749 client-credentials grant, RFC 7662 introspection, RFC 8693 token exchange, and RFC 7009
 * revocation).
 *
 * <p>{@link #authHeaders()} is invoked once per AS request, so an implementation may return
 * different headers over time — e.g. to rotate a client secret, refresh a signed client assertion,
 * or supply mTLS-derived headers — without rebuilding the client.
 *
 * <p>The built-in {@link ASCredentials} implements HTTP Basic authentication from a static {@code
 * clientId}/{@code clientSecret} for the common case.
 */
public interface AuthProvider {

    /**
     * Returns the authentication headers to attach to an Authorization Server request. Called once
     * per request.
     *
     * @return a map of header names to values; empty if no authentication headers are needed
     */
    Map<String, String> authHeaders();
}
