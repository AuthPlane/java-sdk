package ai.authplane.sdk.spring.security;

import java.io.IOException;
import java.util.Objects;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;

import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.errors.AuthplaneException;
import ai.authplane.sdk.core.errors.FailureResponse;
import ai.authplane.sdk.core.errors.TokenMissingException;
import ai.authplane.sdk.core.errors.WwwAuthenticate.ChallengeOptions;

/**
 * {@link AuthenticationEntryPoint} that renders RFC 6750 / RFC 9728 challenges via the shared
 * {@link FailureResponse}, so the status, {@code WWW-Authenticate} scheme/code, {@code
 * resource_metadata} URL, and JSON body are all correct.
 *
 * <p>When the failure carries an {@link AuthplaneException} cause (a token validation failure
 * routed through {@link BearerTokenAuthenticationFilter}), its specific status/scheme/code are used
 * (e.g. {@code invalid_dpop_proof}, {@code insufficient_scope}); otherwise (no/blank credentials
 * reaching authorization) a generic {@code 401 invalid_token} challenge is emitted.
 */
public final class AuthplaneAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final AuthplaneResource resource;

    /**
     * @param resource the resource being protected (supplies the {@code resource_metadata} URL)
     */
    public AuthplaneAuthenticationEntryPoint(AuthplaneResource resource) {
        this.resource = Objects.requireNonNull(resource, "resource must not be null");
    }

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException)
            throws IOException {

        AuthplaneException error =
                (authException != null && authException.getCause() instanceof AuthplaneException ae)
                        ? ae
                        : new TokenMissingException("Bearer token is missing or invalid");

        FailureResponse.Challenge challenge =
                FailureResponse.of(
                        error, ChallengeOptions.empty().withResourceMetadataUrl(resource.prmUrl()));

        response.setStatus(challenge.status());
        response.setHeader("WWW-Authenticate", challenge.wwwAuthenticate());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(challenge.jsonBody());
    }
}
