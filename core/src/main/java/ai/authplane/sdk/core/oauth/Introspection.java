package ai.authplane.sdk.core.oauth;

import java.util.Map;

import com.nimbusds.jose.util.JSONObjectUtils;

import ai.authplane.sdk.core.AuthProvider;
import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.dpop.DPoPProvider;
import ai.authplane.sdk.core.fetching.HttpTransport;
import ai.authplane.sdk.core.fetching.RawPostResponse;

/**
 * Stateless RFC 7662 token introspection implementation. Called internally by {@link
 * AuthplaneClient}.
 */
public final class Introspection {

    private Introspection() {}

    /**
     * Performs RFC 7662 token introspection against the given endpoint.
     *
     * @param introspectionEndpoint the AS introspection endpoint URL
     * @param rawToken the raw JWT string to submit
     * @param authProvider supplies client authentication headers, or null for none
     * @param transport HTTP transport to use
     * @return an {@link IntrospectionResponse} with the active status and raw response
     * @throws Exception on network or parsing errors
     */
    public static IntrospectionResponse introspect(
            String introspectionEndpoint,
            String rawToken,
            AuthProvider authProvider,
            HttpTransport transport)
            throws Exception {
        return introspect(introspectionEndpoint, rawToken, authProvider, transport, null);
    }

    /**
     * Introspects a token at the given endpoint, optionally using a DPoP proof.
     *
     * @param introspectionEndpoint the AS introspection endpoint URL
     * @param rawToken the raw JWT string to submit
     * @param authProvider supplies client authentication headers, or null for none
     * @param transport HTTP transport to use
     * @param dpopProvider DPoP provider (nullable — omits DPoP if null)
     * @return an {@link IntrospectionResponse} with the active status and raw response
     * @throws Exception on network or parsing errors
     */
    public static IntrospectionResponse introspect(
            String introspectionEndpoint,
            String rawToken,
            AuthProvider authProvider,
            HttpTransport transport,
            DPoPProvider dpopProvider)
            throws Exception {

        Map<String, String> formData = Map.of("token", rawToken, "token_type_hint", "access_token");

        RawPostResponse response =
                OAuthPostSupport.postForm(
                        introspectionEndpoint, formData, authProvider, transport, dpopProvider);
        OAuthPostSupport.requireSuccessStatus(response, introspectionEndpoint);

        Map<String, Object> result = JSONObjectUtils.parse(response.body());
        Object activeObj = result.get("active");
        boolean active = Boolean.TRUE.equals(activeObj);

        return new IntrospectionResponse(active, result);
    }
}
