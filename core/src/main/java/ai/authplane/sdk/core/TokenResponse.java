package ai.authplane.sdk.core;

import java.util.List;

/**
 * Response from RFC 8693 token exchange.
 *
 * <p>RFC 9449 does not define a top-level {@code cnf} member on the OAuth token response — the DPoP
 * key binding lives in the {@code at+jwt} access token body (§6.1) and, for opaque tokens, in the
 * introspection response (§6.2, see {@link ai.authplane.sdk.core.oauth.IntrospectionResponse}).
 *
 * @param accessToken the exchanged access token
 * @param tokenType token type (typically {@code "Bearer"})
 * @param expiresIn lifetime in seconds, or {@code null} if not provided by the AS
 * @param scopes granted scopes, or {@code null} if the AS did not echo the scope
 * @param issuedTokenType the URN identifying the token type issued, or {@code null}
 */
public record TokenResponse(
        String accessToken,
        String tokenType,
        Integer expiresIn,
        List<String> scopes,
        String issuedTokenType) {

    public TokenResponse {
        scopes = scopes != null ? List.copyOf(scopes) : null;
    }
}
