package ai.authplane.sdk.core.oauth;

import java.util.LinkedHashMap;
import java.util.Map;

import ai.authplane.sdk.core.AuthProvider;
import ai.authplane.sdk.core.dpop.DPoPProvider;
import ai.authplane.sdk.core.fetching.HttpTransport;
import ai.authplane.sdk.core.fetching.RawPostResponse;

/** Stateless RFC 7009 token revocation implementation. */
public final class Revocation {

    private Revocation() {}

    /**
     * Performs an RFC 7009 token revocation.
     *
     * <p>Per RFC 7009, the revocation endpoint returns HTTP 200 even if the token was not found or
     * already revoked. Callers should not inspect the response body.
     *
     * @param revocationEndpoint the AS revocation endpoint URL
     * @param token the token to revoke
     * @param tokenTypeHint hint about the token type (e.g. "access_token"), nullable
     * @param authProvider supplies client authentication headers, or null for none
     * @param transport HTTP transport to use
     * @throws Exception on network errors
     */
    public static void revoke(
            String revocationEndpoint,
            String token,
            String tokenTypeHint,
            AuthProvider authProvider,
            HttpTransport transport)
            throws Exception {
        revoke(revocationEndpoint, token, tokenTypeHint, authProvider, transport, null);
    }

    /** Revokes a token at the given endpoint, optionally using DPoP proof. */
    public static void revoke(
            String revocationEndpoint,
            String token,
            String tokenTypeHint,
            AuthProvider authProvider,
            HttpTransport transport,
            DPoPProvider dpopProvider)
            throws Exception {

        Map<String, String> formData = new LinkedHashMap<>();
        formData.put("token", token);
        if (tokenTypeHint != null && !tokenTypeHint.isBlank()) {
            formData.put("token_type_hint", tokenTypeHint);
        }

        RawPostResponse response =
                OAuthPostSupport.postForm(
                        revocationEndpoint, formData, authProvider, transport, dpopProvider);
        OAuthPostSupport.requireSuccessStatus(response, revocationEndpoint);
    }
}
