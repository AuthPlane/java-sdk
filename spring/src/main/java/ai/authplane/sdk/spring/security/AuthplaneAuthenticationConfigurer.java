package ai.authplane.sdk.spring.security;

import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.dpop.VerificationRequestContext;
import ai.authplane.sdk.core.errors.AuthplaneException;

/**
 * Spring Security configurer that adds Authplane access-token authentication to an {@link
 * HttpSecurity} — the AuthPlane analogue of Spring's own resource-server/DPoP configurers.
 *
 * <p>Apply it to the chain that protects your MCP resource:
 *
 * <pre>{@code
 * http.securityMatcher("/mcp")
 *     .with(new AuthplaneAuthenticationConfigurer(authResource), Customizer.withDefaults());
 * }</pre>
 *
 * <p>It reuses Spring's {@link BearerTokenAuthenticationFilter}, wiring in:
 *
 * <ul>
 *   <li>an {@link AuthplaneBearerTokenResolver} that accepts both the {@code Bearer} and RFC 9449
 *       {@code DPoP} schemes;
 *   <li>a request-aware {@link AuthenticationManagerResolver} that builds the {@link
 *       VerificationRequestContext} (method, URL, DPoP proof) from the request and delegates to
 *       {@link AuthplaneAuthenticationProvider} ({@link AuthplaneResource#verify(String,
 *       VerificationRequestContext)}) — so AuthPlane core remains the single DPoP authority and no
 *       {@code AuthenticationManagerResolver} threading workaround is needed;
 *   <li>an {@link AuthplaneAuthenticationEntryPoint} that renders RFC 6750 / RFC 9728 challenges
 *       via the shared {@code FailureResponse}.
 * </ul>
 *
 * <p>It deliberately does not use {@code http.oauth2ResourceServer(...)}, which in Spring Security
 * 7 unconditionally installs the native DPoP filter (validating proofs itself) with no opt-out.
 */
public final class AuthplaneAuthenticationConfigurer
        extends AbstractHttpConfigurer<AuthplaneAuthenticationConfigurer, HttpSecurity> {

    private final AuthplaneResource resource;
    private final AuthplaneAuthenticationProvider provider;
    private final AuthplaneAuthenticationEntryPoint entryPoint;

    /**
     * @param resource the protected resource whose tokens this configurer authenticates
     */
    public AuthplaneAuthenticationConfigurer(AuthplaneResource resource) {
        this.resource = Objects.requireNonNull(resource, "resource must not be null");
        this.provider = new AuthplaneAuthenticationProvider(resource);
        this.entryPoint = new AuthplaneAuthenticationEntryPoint(resource);
    }

    @Override
    public void init(HttpSecurity http) {
        // exceptionHandling adds a configurer, which must be registered during the init phase.
        http.exceptionHandling(ex -> ex.authenticationEntryPoint(entryPoint));
    }

    @Override
    public void configure(HttpSecurity http) {
        BearerTokenAuthenticationConverter converter = new BearerTokenAuthenticationConverter();
        converter.setBearerTokenResolver(new AuthplaneBearerTokenResolver());

        BearerTokenAuthenticationFilter filter =
                new BearerTokenAuthenticationFilter(
                        new RequestContextAuthenticationManagerResolver(provider, resource),
                        converter);
        filter.setAuthenticationEntryPoint(entryPoint);

        http.addFilterBefore(filter, AuthorizationFilter.class);
    }

    /**
     * Resolves a request-scoped {@link AuthenticationManager} that rebuilds the {@link
     * VerificationRequestContext} (HTTP method, DPoP proof headers) from each request and delegates
     * verification to {@link AuthplaneAuthenticationProvider}. Threading the request this way keeps
     * AuthPlane core as the single DPoP authority without an external resolver workaround.
     *
     * <p>The DPoP {@code htu} is built via {@link AuthplaneResource#normalizeRequestUrl(String)}:
     * the request's path with the resource's canonical scheme+host substituted in, so {@code htu}
     * verification is independent of the deployment's internal host and reverse-proxy {@code
     * X-Forwarded-*} headers (which we deliberately do not trust), while still binding to the
     * actual request target.
     */
    static final class RequestContextAuthenticationManagerResolver
            implements AuthenticationManagerResolver<HttpServletRequest> {

        private final AuthplaneAuthenticationProvider provider;
        private final AuthplaneResource resource;

        RequestContextAuthenticationManagerResolver(
                AuthplaneAuthenticationProvider provider, AuthplaneResource resource) {
            this.provider = provider;
            this.resource = resource;
        }

        @Override
        public AuthenticationManager resolve(HttpServletRequest request) {
            return authentication -> {
                String token = ((BearerTokenAuthenticationToken) authentication).getToken();
                VerificationRequestContext context;
                try {
                    context =
                            new VerificationRequestContext(
                                    request.getMethod(),
                                    resource.normalizeRequestUrl(
                                            request.getRequestURL().toString()),
                                    dpopHeaders(request));
                } catch (AuthplaneException e) {
                    // RFC 9449 §4.3 #1 (more than one DPoP header) is enforced at context
                    // construction, which throws before the provider runs — outside the provider's
                    // own AuthplaneException→OAuth2AuthenticationException mapping. Map it here so
                    // BearerTokenAuthenticationFilter (which catches only AuthenticationException)
                    // routes it to the entry point as a 401 DPoP challenge instead of a 500.
                    throw AuthplaneAuthenticationProvider.toOAuth2Exception(e);
                }
                return provider.authenticate(new AuthplanePreAuthToken(token, context));
            };
        }
    }

    private static List<String> dpopHeaders(HttpServletRequest request) {
        Enumeration<String> values = request.getHeaders("DPoP");
        return values == null ? List.of() : Collections.list(values);
    }
}
