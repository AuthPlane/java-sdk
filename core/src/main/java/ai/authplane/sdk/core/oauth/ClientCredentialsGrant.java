package ai.authplane.sdk.core.oauth;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ai.authplane.sdk.core.AuthProvider;
import ai.authplane.sdk.core.TokenResponse;
import ai.authplane.sdk.core.dpop.DPoPProvider;
import ai.authplane.sdk.core.errors.TokenExchangeException;
import ai.authplane.sdk.core.fetching.HttpTransport;
import ai.authplane.sdk.core.fetching.RawPostResponse;

/** Stateless RFC 6749 §4.4 client credentials grant implementation. */
public final class ClientCredentialsGrant {

    private ClientCredentialsGrant() {}

    /**
     * Performs an RFC 6749 §4.4 client credentials grant with list-based scopes and multiple
     * resource indicators (RFC 8707).
     *
     * <p>Scopes are joined with a space separator. Each resource indicator is emitted as a separate
     * {@code resource} form parameter per RFC 8707.
     *
     * @param tokenEndpoint the AS token endpoint URL
     * @param scopes list of scopes to request (null or empty → omit scope parameter)
     * @param resources list of resource indicators (null or empty → omit resource parameters)
     * @param authProvider supplies client authentication headers (required)
     * @param transport HTTP transport to use
     * @return the token response
     * @throws TokenExchangeException on any error
     */
    public static TokenResponse execute(
            String tokenEndpoint,
            List<String> scopes,
            List<String> resources,
            AuthProvider authProvider,
            HttpTransport transport)
            throws Exception {
        return execute(tokenEndpoint, scopes, resources, authProvider, transport, null);
    }

    /**
     * Performs an RFC 6749 §4.4 client credentials grant with DPoP support.
     *
     * @param tokenEndpoint the AS token endpoint URL
     * @param scopes list of scopes to request (null or empty → omit scope parameter)
     * @param resources list of resource indicators (null or empty → omit resource parameters)
     * @param authProvider supplies client authentication headers (required)
     * @param transport HTTP transport to use
     * @param dpopProvider DPoP provider (nullable — omits DPoP if null)
     * @return the token response
     * @throws TokenExchangeException on any error
     */
    public static TokenResponse execute(
            String tokenEndpoint,
            List<String> scopes,
            List<String> resources,
            AuthProvider authProvider,
            HttpTransport transport,
            DPoPProvider dpopProvider)
            throws Exception {

        List<Map.Entry<String, String>> formData = new ArrayList<>();
        formData.add(new AbstractMap.SimpleEntry<>("grant_type", "client_credentials"));

        if (scopes != null && !scopes.isEmpty()) {
            List<String> nonNull = new ArrayList<>();
            for (String s : scopes) {
                if (s != null && !s.isBlank()) {
                    nonNull.add(s);
                }
            }
            if (!nonNull.isEmpty()) {
                formData.add(new AbstractMap.SimpleEntry<>("scope", String.join(" ", nonNull)));
            }
        }

        if (resources != null) {
            for (String r : resources) {
                if (r != null && !r.isBlank()) {
                    formData.add(new AbstractMap.SimpleEntry<>("resource", r));
                }
            }
        }

        RawPostResponse response =
                OAuthPostSupport.postForm(
                        tokenEndpoint, formData, authProvider, transport, dpopProvider);
        return TokenResponseParser.parse(
                "Client authProvider", response, false, dpopProvider != null);
    }
}
