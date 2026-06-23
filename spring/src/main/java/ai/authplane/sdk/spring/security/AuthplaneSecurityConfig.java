package ai.authplane.sdk.spring.security;

import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;

import ai.authplane.sdk.core.AuthProvider;
import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.AuthplaneClientBuilder;
import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.ResourceOptions;
import ai.authplane.sdk.core.RevocationChecker;
import ai.authplane.sdk.core.TokenCacheConfig;
import ai.authplane.sdk.core.dpop.InboundDPoPOptions;
import ai.authplane.sdk.core.dpop.OutboundDPoPOptions;
import ai.authplane.sdk.core.fetching.FetchSettings;

/**
 * Ready-made Spring Security configuration for an MCP server over Spring MVC (synchronous,
 * streamable-HTTP transport).
 *
 * <p>Import this class in your {@code @SpringBootApplication} or any {@code @Configuration} class:
 *
 * <pre>{@code
 * @Import(AuthplaneSecurityConfig.class)
 * @SpringBootApplication
 * public class MyMcpServer { ... }
 * }</pre>
 *
 * <p>Required properties:
 *
 * <pre>
 * authplane.issuer   = https://auth.example.com        # Authorization Server issuer URI
 * authplane.resource = https://mcp.example.com/mcp     # This server's URI / JWT audience
 * authplane.scopes   = tools/add,tools/multiply        # Comma-separated supported scopes
 * </pre>
 *
 * <p>Optional properties (shown with their defaults):
 *
 * <pre>
 * authplane.dev-mode                = false             # Allow http:// and localhost (dev only)
 * authplane.allowed-algorithms      = RS256,ES256       # Accepted JWT signing algorithms
 * authplane.clock-skew-seconds      = 30                # Clock drift tolerance
 * authplane.jwks-refresh-seconds    = 300               # Background JWKS refresh interval
 * authplane.metadata-refresh-seconds = 3600             # RFC 8414 metadata refresh interval
 * authplane.introspection.enabled            = false    # Enable built-in RFC 7662 token introspection
 * authplane.timeout-seconds                  = 0       # HTTP timeout (0 = use SDK default of 10s)
 * authplane.circuit-breaker-threshold        = 0       # Failures before circuit opens (0 = SDK default of 5)
 * authplane.circuit-breaker-cooldown-seconds = 0       # Cooldown before half-open (0 = SDK default of 30s)
 * authplane.token-cache-ttl-buffer-seconds   = 0       # Buffer before token expiry (0 = SDK default of 30s)
 * authplane.token-cache-default-ttl-seconds  = 0       # Fallback TTL when expires_in absent (0 = SDK default of 3600s)
 * authplane.token-cache-max-entries          = 0       # Max cached tokens before LRU eviction (0 = SDK default of 10000)
 * </pre>
 *
 * <p>Optional beans (for advanced configuration):
 *
 * <ul>
 *   <li>{@link AuthProvider} — Authorization Server authentication for introspection / token
 *       exchange. Expose {@code new ASCredentials(clientId, clientSecret)} for static client
 *       credentials, or a custom provider for a rotating secret / non-Basic scheme
 *   <li>{@link OutboundDPoPOptions} — enables outbound DPoP proof generation
 *   <li>{@link InboundDPoPOptions} — enables inbound DPoP proof validation
 *   <li>{@code @Qualifier("authplaneExecutor")} {@link Executor} — custom executor for async
 *       operations (default: {@code ForkJoinPool.commonPool()})
 * </ul>
 *
 * <p>Alternatively, expose a {@link RevocationChecker} bean for custom revocation logic (e.g. a
 * Redis blocklist). If both a {@code RevocationChecker} bean and {@code
 * authplane.introspection.enabled=true} are set, the bean takes precedence.
 *
 * <h2>What this wires up</h2>
 *
 * <ol>
 *   <li>{@link AuthplaneClient} bean — performs RFC 8414 discovery and initial JWKS fetch at
 *       startup. Auto-closed by Spring via {@link AutoCloseable}.
 *   <li>{@link AuthplaneResource} bean — lightweight JWT verifier scoped to the configured resource
 *       and scopes.
 *   <li>{@link AuthplaneAuthenticationConfigurer} — contributes Spring's {@code
 *       BearerTokenAuthenticationFilter} (accepting Bearer and DPoP schemes, with DPoP proof
 *       validated by the core verifier) to the resource-scoped chain below.
 *   <li>RFC 9728 PRM endpoint — serves the Protected Resource Metadata document at {@code
 *       /.well-known/oauth-protected-resource/<path>} via a Spring MVC {@code RouterFunction}.
 *   <li>{@link WebSecurityCustomizer} — bypasses Spring Security's own minimal PRM filter so the
 *       router function above can serve the correct document (including the {@code
 *       authorization_servers} field).
 *   <li>{@link SecurityFilterChain} — scoped to the resource path (not global); requires a valid
 *       token there and returns a structured 401/403 whose {@code WWW-Authenticate} header points
 *       to the PRM document, allowing MCP clients to discover the authorization server
 *       automatically.
 * </ol>
 *
 * <h2>Other Spring AI transport configurations</h2>
 *
 * <ul>
 *   <li>WebFlux / reactive transport → use {@code AuthplaneReactiveSecurityConfig} (not yet
 *       available)
 * </ul>
 */
@Configuration
@EnableWebSecurity
public class AuthplaneSecurityConfig {

    /**
     * {@link Order} of {@link #authplaneSecurityFilterChain}. Low value (high precedence) so the
     * resource path is matched by this chain ahead of a typical host catch-all chain. A host that
     * wants to claim the resource path itself must declare a chain with a strictly lower order
     * (e.g. {@link org.springframework.core.Ordered#HIGHEST_PRECEDENCE}).
     */
    public static final int AUTHPLANE_CHAIN_ORDER = 1;

    /**
     * Builds a {@link TokenCacheConfig} from the property values, substituting SDK defaults for any
     * left at 0, or {@code null} when none are set.
     *
     * <p>Note: {@code 0} means "use the SDK default" for every field, so the TTL buffer cannot be
     * set to 0 (no buffer) via properties — supply a custom {@link TokenCacheConfig} for that.
     */
    private static TokenCacheConfig resolveTokenCacheConfig(
            int ttlBufferSeconds, int defaultTtlSeconds, int maxEntries) {
        if (ttlBufferSeconds <= 0 && defaultTtlSeconds <= 0 && maxEntries <= 0) {
            return null;
        }
        return new TokenCacheConfig(
                ttlBufferSeconds > 0
                        ? ttlBufferSeconds
                        : TokenCacheConfig.DEFAULT_TTL_BUFFER_SECONDS,
                defaultTtlSeconds > 0 ? defaultTtlSeconds : TokenCacheConfig.DEFAULT_TTL_SECONDS,
                maxEntries > 0 ? maxEntries : TokenCacheConfig.DEFAULT_MAX_ENTRIES);
    }

    /**
     * Builds an {@link AuthplaneClient} that owns the AS connection state (metadata cache, JWKS
     * cache, HTTP transport). Auto-closed by Spring via {@link AutoCloseable}.
     *
     * <p>Performs RFC 8414 authorization server metadata discovery and an initial JWKS fetch before
     * the application starts serving requests.
     */
    @Bean
    public AuthplaneClient authplaneClient(
            @Value("${authplane.issuer}") String issuer,
            @Value("${authplane.dev-mode:false}") boolean devMode,
            @Value("${authplane.jwks-refresh-seconds:300}") int jwksRefreshSeconds,
            @Value("${authplane.metadata-refresh-seconds:3600}") int metadataRefreshSeconds,
            @Value("${authplane.timeout-seconds:0}") int timeoutSeconds,
            @Value("${authplane.circuit-breaker-threshold:0}") int circuitBreakerThreshold,
            @Value("${authplane.circuit-breaker-cooldown-seconds:0}")
                    int circuitBreakerCooldownSeconds,
            @Value("${authplane.token-cache-ttl-buffer-seconds:0}") int tokenCacheTtlBufferSeconds,
            @Value("${authplane.token-cache-default-ttl-seconds:0}")
                    int tokenCacheDefaultTtlSeconds,
            @Value("${authplane.token-cache-max-entries:0}") int tokenCacheMaxEntries,
            ObjectProvider<OutboundDPoPOptions> outboundDPoPProvider,
            @Qualifier("authplaneExecutor") ObjectProvider<Executor> executorProvider,
            ObjectProvider<AuthProvider> authProviderProvider)
            throws Exception {

        AuthplaneClientBuilder builder =
                AuthplaneClient.builder(issuer)
                        .devMode(devMode)
                        .jwksRefreshSeconds(jwksRefreshSeconds)
                        .metadataRefreshSeconds(metadataRefreshSeconds);

        // Credentials — supply an AuthProvider bean (e.g. new ASCredentials(id, secret)).
        AuthProvider customAuthProvider = authProviderProvider.getIfAvailable();
        if (customAuthProvider != null) {
            builder.authProvider(customAuthProvider);
        }

        // Custom timeout
        if (timeoutSeconds > 0) {
            FetchSettings base = FetchSettings.fromDevMode(devMode);
            builder.fetchSettings(
                    new FetchSettings(
                            base.ssrfProtection(),
                            base.allowHttp(),
                            base.allowLocalhost(),
                            base.allowPrivateNetworks(),
                            timeoutSeconds));
        }

        // Circuit breaker
        if (circuitBreakerThreshold > 0) {
            builder.circuitBreakerThreshold(circuitBreakerThreshold);
        }
        if (circuitBreakerCooldownSeconds > 0) {
            builder.circuitBreakerCooldownSeconds(circuitBreakerCooldownSeconds);
        }

        // Token cache
        TokenCacheConfig tokenCacheConfig =
                resolveTokenCacheConfig(
                        tokenCacheTtlBufferSeconds,
                        tokenCacheDefaultTtlSeconds,
                        tokenCacheMaxEntries);
        if (tokenCacheConfig != null) {
            builder.tokenCacheConfig(tokenCacheConfig);
        }

        // Outbound DPoP (optional bean)
        OutboundDPoPOptions outboundDPoP = outboundDPoPProvider.getIfAvailable();
        if (outboundDPoP != null) {
            builder.outboundDPoP(outboundDPoP);
        }

        // Custom executor (optional bean)
        Executor executor = executorProvider.getIfAvailable();
        if (executor != null) {
            builder.executor(executor);
        }

        return builder.build().get();
    }

    /**
     * Builds a lightweight {@link AuthplaneResource} scoped to the configured resource and scopes.
     * Backed by the shared {@link AuthplaneClient}.
     */
    @Bean
    public AuthplaneResource authplaneResource(
            AuthplaneClient client,
            @Value("${authplane.resource}") String resource,
            @Value("${authplane.scopes}") List<String> scopes,
            @Value("${authplane.allowed-algorithms:RS256,ES256}") List<String> allowedAlgorithms,
            @Value("${authplane.clock-skew-seconds:30}") int clockSkewSeconds,
            @Value("${authplane.introspection.enabled:false}") boolean introspectionEnabled,
            ObjectProvider<RevocationChecker> revocationCheckerProvider,
            ObjectProvider<InboundDPoPOptions> inboundDPoPProvider) {

        ResourceOptions.Builder optBuilder =
                ResourceOptions.builder()
                        .allowedAlgorithms(allowedAlgorithms)
                        .clockSkewSeconds(clockSkewSeconds);

        // Custom RevocationChecker bean takes precedence over property-based introspection
        RevocationChecker customChecker = revocationCheckerProvider.getIfAvailable();
        if (customChecker != null) {
            optBuilder.revocationChecker(customChecker);
        } else if (introspectionEnabled) {
            optBuilder.useBuiltinRevocationChecker();
        }

        // Inbound DPoP (optional bean)
        InboundDPoPOptions inboundDPoP = inboundDPoPProvider.getIfAvailable();
        if (inboundDPoP != null) {
            optBuilder.inboundDPoP(inboundDPoP);
        }

        return client.resource(resource, scopes, optBuilder.build());
    }

    /**
     * Serves the RFC 9728 Protected Resource Metadata document at the path derived from the
     * resource URI.
     *
     * <p>For {@code authplane.resource=https://mcp.example.com/mcp} the path is {@code
     * /.well-known/oauth-protected-resource/mcp} (RFC 9728 §4).
     */
    @Bean
    public RouterFunction<ServerResponse> authplanePrmEndpoint(AuthplaneResource authResource) {
        Map<String, Object> prmResponse = authResource.prmResponse();
        return RouterFunctions.route()
                .GET(authResource.prmPath(), req -> ServerResponse.ok().body(prmResponse))
                .build();
    }

    /**
     * Bypasses Spring Security's filter chain for the PRM endpoint so that the Spring MVC {@code
     * RouterFunction} above can serve the correct RFC 9728 document.
     *
     * <p>Without this, Spring Security's built-in {@code ProtectedResourceMetadataEndpointFilter}
     * intercepts the path and returns a minimal document that is missing the {@code
     * authorization_servers} field.
     */
    @Bean
    public WebSecurityCustomizer authplaneWebSecurityCustomizer(AuthplaneResource authResource) {
        String prmPath = authResource.prmPath();
        return web -> web.ignoring().requestMatchers(prmPath);
    }

    /**
     * Turnkey Spring Security chain scoped to the resource path and everything under it (via {@link
     * HttpSecurity#securityMatcher} on {@code <path>} and {@code <path>/**}), so it governs the
     * resource endpoint and its sub-paths (e.g. {@code /mcp} and {@code /mcp/tool}) — not the
     * host's global authorization. Token authentication (incl. DPoP) is contributed by {@link
     * AuthplaneAuthenticationConfigurer}; the chain is stateless with CSRF disabled (token API).
     *
     * <p>Ordered ahead of a typical host catch-all chain (see {@link #AUTHPLANE_CHAIN_ORDER}) so
     * the resource path is matched here first. To take over the resource path entirely, a host can
     * define its own higher-priority {@link SecurityFilterChain} matching it, or apply {@link
     * AuthplaneAuthenticationConfigurer} to its own chain instead of importing this configuration.
     *
     * @throws IllegalStateException if the resource has no path (e.g. {@code
     *     https://api.example.com}); a root resource yields an empty {@code securityMatcher}, whose
     *     semantics are undefined — configure {@code authplane.resource} with an explicit path
     */
    @Bean
    @Order(AUTHPLANE_CHAIN_ORDER)
    public SecurityFilterChain authplaneSecurityFilterChain(
            HttpSecurity http, AuthplaneResource authResource) throws Exception {
        String resourcePath = authResource.path();
        if (resourcePath.isEmpty()) {
            throw new IllegalStateException(
                    "authplane.resource must include a path (e.g. https://api.example.com/mcp): a"
                            + " root resource has no path to scope the security chain to via"
                            + " securityMatcher.");
        }
        return http.securityMatcher(resourcePath, resourcePath + "/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .with(
                        new AuthplaneAuthenticationConfigurer(authResource),
                        Customizer.withDefaults())
                .build();
    }
}
