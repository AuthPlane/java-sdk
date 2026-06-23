package ai.authplane.sdk.core.oauth;

import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ai.authplane.sdk.core.AuthProvider;
import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.TokenExchangeOptions;
import ai.authplane.sdk.core.TokenResponse;
import ai.authplane.sdk.core.dpop.DPoPProvider;
import ai.authplane.sdk.core.errors.TokenExchangeException;
import ai.authplane.sdk.core.fetching.HttpTransport;
import ai.authplane.sdk.core.fetching.RawPostResponse;

/**
 * Stateless RFC 8693 token exchange implementation. Called internally by {@link AuthplaneClient}.
 */
public final class TokenExchange {

    private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";

    private TokenExchange() {}

    /**
     * Performs an RFC 8693 token exchange against the given token endpoint.
     *
     * @param tokenEndpoint the AS token endpoint URL
     * @param options exchange parameters
     * @param authProvider supplies client authentication headers, or null for none
     * @param transport HTTP transport to use
     * @return the exchanged token response
     * @throws TokenExchangeException on any error
     */
    public static TokenResponse exchange(
            String tokenEndpoint,
            TokenExchangeOptions options,
            AuthProvider authProvider,
            HttpTransport transport)
            throws Exception {
        return exchange(tokenEndpoint, options, authProvider, transport, null);
    }

    /** Performs an RFC 8693 token exchange, optionally using DPoP proof. */
    public static TokenResponse exchange(
            String tokenEndpoint,
            TokenExchangeOptions options,
            AuthProvider authProvider,
            HttpTransport transport,
            DPoPProvider dpopProvider)
            throws Exception {
        validateOptions(options);

        List<Map.Entry<String, String>> formData = new ArrayList<>();
        formData.add(new SimpleImmutableEntry<>("grant_type", GRANT_TYPE));
        formData.add(new SimpleImmutableEntry<>("subject_token", options.subjectToken()));
        formData.add(new SimpleImmutableEntry<>("subject_token_type", options.subjectTokenType()));

        if (options.scope() != null && !options.scope().isEmpty()) {
            formData.add(new SimpleImmutableEntry<>("scope", String.join(" ", options.scope())));
        }
        if (options.resources() != null) {
            for (String resource : options.resources()) {
                if (resource != null && !resource.isBlank()) {
                    formData.add(new SimpleImmutableEntry<>("resource", resource));
                }
            }
        }
        if (options.audiences() != null) {
            for (String audience : options.audiences()) {
                if (audience != null && !audience.isBlank()) {
                    formData.add(new SimpleImmutableEntry<>("audience", audience));
                }
            }
        }
        if (options.actorToken() != null) {
            formData.add(new SimpleImmutableEntry<>("actor_token", options.actorToken()));
        }
        String actorTokenType = resolveActorTokenType(options);
        if (actorTokenType != null) {
            formData.add(new SimpleImmutableEntry<>("actor_token_type", actorTokenType));
        }

        RawPostResponse response =
                OAuthPostSupport.postForm(
                        tokenEndpoint, formData, authProvider, transport, dpopProvider);
        return TokenResponseParser.parse("Token exchange", response, true, dpopProvider != null);
    }

    private static void validateOptions(TokenExchangeOptions options)
            throws TokenExchangeException {
        if (options.subjectToken() == null || options.subjectToken().isBlank()) {
            throw new TokenExchangeException(
                    "Token exchange requires a non-blank 'subject_token'", null);
        }
        if (options.subjectTokenType() == null || options.subjectTokenType().isBlank()) {
            throw new TokenExchangeException(
                    "Token exchange requires a non-blank 'subject_token_type'", null);
        }
    }

    private static String resolveActorTokenType(TokenExchangeOptions options) {
        if (options.actorToken() == null || options.actorToken().isBlank()) {
            return null;
        }
        if (options.actorTokenType() != null && !options.actorTokenType().isBlank()) {
            return options.actorTokenType();
        }
        // SDK default per RFC 8693 §2.1: when actor_token is present but
        // actor_token_type is omitted, default to access_token type.
        return "urn:ietf:params:oauth:token-type:access_token";
    }
}
