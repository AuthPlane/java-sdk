package ai.authplane.sdk.spring.security;

import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import ai.authplane.sdk.core.dpop.VerificationRequestContext;

/**
 * Unauthenticated {@link org.springframework.security.core.Authentication} request produced by
 * {@link AuthplaneAuthenticationConfigurer}'s request-aware authentication manager and consumed by
 * {@link AuthplaneAuthenticationProvider}. It carries the raw access token together with the {@link
 * VerificationRequestContext} (HTTP method, URL, and DPoP proof headers) needed for inbound DPoP
 * validation — so the request context reaches the provider directly.
 */
final class AuthplanePreAuthToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1L;

    /**
     * Principal placeholder. The provider reads the token via {@link #token()}, so the principal is
     * only ever surfaced by the framework (e.g. {@code Authentication.toString()}, authentication
     * failure events). Returning a sentinel instead of the raw token keeps the access token out of
     * those sinks.
     */
    private static final String PRINCIPAL = "<authplane-pre-auth>";

    private final String token;
    private final transient VerificationRequestContext context;

    AuthplanePreAuthToken(String token, VerificationRequestContext context) {
        super(Collections.emptyList());
        this.token = token;
        this.context = context;
        setAuthenticated(false);
    }

    String token() {
        return token;
    }

    VerificationRequestContext context() {
        return context;
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getPrincipal() {
        return PRINCIPAL;
    }
}
