package ai.authplane.sdk.spring.security;

import java.util.Objects;
import java.util.concurrent.CompletionException;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.VerificationResult;
import ai.authplane.sdk.core.errors.AuthplaneException;
import ai.authplane.sdk.core.errors.WwwAuthenticate;

/**
 * Spring Security {@link AuthenticationProvider} that validates an {@link AuthplanePreAuthToken}
 * (raw access token + request context) using {@link AuthplaneResource} and returns an {@link
 * AuthplaneAuthentication} on success.
 *
 * <p>The token and the {@link ai.authplane.sdk.core.dpop.VerificationRequestContext} (HTTP method,
 * URL, DPoP proof) are supplied per request by {@link AuthplaneAuthenticationConfigurer}'s
 * request-context {@code AuthenticationManagerResolver}, so inbound DPoP is validated end-to-end on
 * every request with no silent bearer-only fallback. AuthPlane core remains the single DPoP
 * authority.
 *
 * <h2>Error mapping</h2>
 *
 * <p>{@link AuthplaneException} subtypes are mapped to an {@link OAuth2AuthenticationException}
 * whose error code comes from {@link WwwAuthenticate#errorCodeFor(AuthplaneException)} (e.g. {@code
 * invalid_token}, {@code invalid_dpop_proof}, {@code insufficient_scope}). {@link
 * AuthplaneAuthenticationEntryPoint} renders the final HTTP response from the underlying error.
 */
public final class AuthplaneAuthenticationProvider implements AuthenticationProvider {

    private final AuthplaneResource resource;

    /**
     * @param resource the verifier this provider delegates to; must not be null
     */
    public AuthplaneAuthenticationProvider(AuthplaneResource resource) {
        this.resource = Objects.requireNonNull(resource, "resource must not be null");
    }

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {
        if (!(authentication instanceof AuthplanePreAuthToken request)) {
            // Not our token type — return null so a ProviderManager tries the next provider
            // (Spring's AuthenticationProvider contract), even though supports() already gates
            // this.
            return null;
        }
        try {
            VerificationResult result = resource.verify(request.token(), request.context()).join();
            return AuthplaneAuthentication.of(result.claims(), request.token());
        } catch (CompletionException e) {
            throw toOAuth2Exception(e.getCause() != null ? e.getCause() : e);
        } catch (AuthplaneException e) {
            throw toOAuth2Exception(e);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AuthplanePreAuthToken.class.isAssignableFrom(authentication);
    }

    /**
     * Maps a verification failure to an {@link OAuth2AuthenticationException} whose error code
     * comes from {@link WwwAuthenticate#errorCodeFor(AuthplaneException)}. Package-private so the
     * configurer's request-context resolver can route exceptions thrown <em>before</em> this
     * provider runs (e.g. {@link ai.authplane.sdk.core.dpop.MultipleDpopProofsException} from
     * {@code VerificationRequestContext} construction) through the same mapping — otherwise a raw
     * {@link AuthplaneException} would escape {@link
     * org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter}
     * (which only catches {@link AuthenticationException}) as an unhandled 500.
     */
    static OAuth2AuthenticationException toOAuth2Exception(Throwable cause) {
        // No exception's message is reflected back to the client, SDK-owned or not. The SDK's own
        // messages name the unknown kid, the claim that did not validate, or the aud the resource
        // expects; the description is the fixed sentence for the code instead, and server-side
        // logging holds the detail. The SDK's default wiring routes to
        // AuthplaneAuthenticationEntryPoint, which discards both halves of this exception, but an
        // application wiring this provider under Spring's own oauth2ResourceServer gets
        // BearerTokenAuthenticationEntryPoint, which renders the OAuth2Error description straight
        // into error_description — and with server.error.include-message=always the exception
        // message reaches the error body too.
        String errorCode;
        if (cause instanceof AuthplaneException ae) {
            errorCode = WwwAuthenticate.errorCodeFor(ae);
        } else {
            errorCode = "invalid_token";
        }
        String description = WwwAuthenticate.descriptionFor(errorCode);
        return new OAuth2AuthenticationException(
                new OAuth2Error(errorCode, description, null), description, cause);
    }
}
