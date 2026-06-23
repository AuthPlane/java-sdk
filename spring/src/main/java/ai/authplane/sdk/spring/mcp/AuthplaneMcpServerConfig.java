package ai.authplane.sdk.spring.mcp;

import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;

import org.springframework.ai.mcp.server.webmvc.transport.WebMvcStreamableServerTransportProvider;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
import io.modelcontextprotocol.common.McpTransportContext;

/**
 * Transport-level MCP authentication configuration for Spring MVC servers.
 *
 * <p>Integrates Authplane JWT validation directly into Spring AI's {@link
 * WebMvcStreamableServerTransportProvider} via the MCP SDK's {@code securityValidator} and {@code
 * contextExtractor} hooks, without involving Spring Security at all.
 *
 * <p>Import this class in your {@code @SpringBootApplication}:
 *
 * <pre>{@code
 * @Import(AuthplaneMcpServerConfig.class)
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
 * authplane.dev-mode                         = false       # Allow http:// and localhost (dev only)
 * authplane.allowed-algorithms               = RS256,ES256 # Accepted JWT signing algorithms
 * authplane.clock-skew-seconds               = 30          # Clock drift tolerance
 * authplane.jwks-refresh-seconds             = 300         # Background JWKS refresh interval
 * authplane.metadata-refresh-seconds         = 3600        # RFC 8414 metadata refresh interval
 * authplane.introspection.enabled            = false       # Enable built-in RFC 7662 token introspection
 * authplane.timeout-seconds                  = 0           # HTTP timeout (0 = use SDK default of 10s)
 * authplane.circuit-breaker-threshold        = 0           # Failures before circuit opens (0 = SDK default of 5)
 * authplane.circuit-breaker-cooldown-seconds = 0           # Cooldown before half-open (0 = SDK default of 30s)
 * authplane.token-cache-ttl-buffer-seconds   = 0           # Buffer before token expiry (0 = SDK default of 30s)
 * authplane.token-cache-default-ttl-seconds  = 0           # Fallback TTL when expires_in absent (0 = SDK default of 3600s)
 * authplane.token-cache-max-entries          = 0           # Max cached tokens before LRU eviction (0 = SDK default of 10000)
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
 *   <li>{@link AuthplaneMcpServerAdapter} bean — implements {@code
 *       ServerTransportSecurityValidator} and {@code McpTransportContextExtractor<ServerRequest>}.
 *   <li>{@link WebMvcStreamableServerTransportProvider} bean — wires the adapter into the transport
 *       layer. Spring AI's autoconfiguration uses {@code @ConditionalOnMissingBean} and defers to
 *       this bean.
 *   <li>RFC 9728 PRM endpoint — serves the Protected Resource Metadata document at {@code
 *       /.well-known/oauth-protected-resource/<path>}.
 * </ol>
 *
 * @see AuthplaneMcpServerAdapter
 */
@Configuration
public class AuthplaneMcpServerConfig {

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
     * Creates the transport-level adapter that validates tokens and extracts claims into the {@link
     * McpTransportContext}.
     */
    @Bean
    public AuthplaneMcpServerAdapter authplaneMcpServerAdapter(AuthplaneResource resource) {
        return new AuthplaneMcpServerAdapter(resource);
    }

    /**
     * Provides a {@link WebMvcStreamableServerTransportProvider} wired with Authplane's security
     * validator and context extractor hooks.
     *
     * <p>Spring AI's {@code McpServerStreamableHttpWebMvcAutoConfiguration} uses
     * {@code @ConditionalOnMissingBean} and will not create its own transport provider when this
     * bean is present.
     */
    @Bean
    public WebMvcStreamableServerTransportProvider webMvcStreamableServerTransportProvider(
            AuthplaneMcpServerAdapter adapter) {
        return WebMvcStreamableServerTransportProvider.builder()
                .securityValidator(adapter)
                .contextExtractor(adapter)
                .build();
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
}
