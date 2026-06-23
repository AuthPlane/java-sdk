package ai.authplane.sdk.mcp;

import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;

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
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;

/**
 * Single entry point for wiring Authplane JWT auth into an MCP servlet server.
 *
 * <p>The builder creates the {@link AuthplaneClient}, {@link AuthplaneResource}, {@link
 * AuthplaneMcpAdapter}, and PRM servlet. The host owns the MCP transport provider and wires in the
 * adapter as its security validator and context extractor.
 *
 * <p>Usage:
 *
 * <pre>{@code
 * AuthplaneMcpSetup setup = AuthplaneMcpSetup.builder()
 *     .issuer("https://auth.example.com")
 *     .resource("https://mcp.example.com/mcp")
 *     .scopes(List.of("tools/read", "tools/write"))
 *     .build()
 *     .get();
 *
 * // Build the transport, wiring in Authplane auth via the adapter:
 * HttpServletStreamableServerTransportProvider transport =
 *     HttpServletStreamableServerTransportProvider.builder()
 *         .mcpEndpoint(setup.mcpPath())
 *         .securityValidator(setup.adapter())
 *         .contextExtractor(setup.adapter())
 *         .build();
 *
 * // Wire into MCP server (user-defined tools):
 * McpServer.sync(transport)
 *     .serverInfo(new Implementation("my-server", "1.0.0"))
 *     .tools(...)
 *     .build();
 *
 * // Register with any Jakarta Servlet container:
 * setup.registerServlets(servletContext, transport);
 *
 * }</pre>
 */
public final class AuthplaneMcpSetup {

    private final AuthplaneClient client;
    private final AuthplaneResource resource;
    private final AuthplaneMcpAdapter adapter;
    private final String mcpPath;
    private final String prmPath;

    // Lazily created on first prmServlet() call — the document is cheap and only the host that
    // serves PRM needs it. Guarded by synchronization for safe publication.
    private PrmServlet prmServlet;

    private AuthplaneMcpSetup(
            AuthplaneClient client,
            AuthplaneResource resource,
            AuthplaneMcpAdapter adapter,
            String mcpPath,
            String prmPath) {
        this.client = client;
        this.resource = resource;
        this.adapter = adapter;
        this.mcpPath = mcpPath;
        this.prmPath = prmPath;
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /** The {@link AuthplaneClient} for token operations (exchange, introspection, etc.). */
    public AuthplaneClient client() {
        return client;
    }

    /** The {@link AuthplaneResource} for direct token verification and PRM. */
    public AuthplaneResource resource() {
        return resource;
    }

    /** The {@link AuthplaneMcpAdapter} wired as security validator and context extractor. */
    public AuthplaneMcpAdapter adapter() {
        return adapter;
    }

    /**
     * The RFC 9728 PRM servlet, created on demand from the resource's {@link
     * AuthplaneResource#prmResponse()} and memoized for subsequent calls.
     */
    public synchronized PrmServlet prmServlet() {
        if (prmServlet == null) {
            prmServlet = new PrmServlet(resource.prmResponse());
        }
        return prmServlet;
    }

    /** Path where the MCP transport should be registered (e.g. {@code /mcp}). */
    public String mcpPath() {
        return mcpPath;
    }

    /**
     * Path where the PRM document should be served (e.g. {@code
     * /.well-known/oauth-protected-resource/mcp}).
     */
    public String prmPath() {
        return prmPath;
    }

    // -----------------------------------------------------------------------
    // Standard servlet registration
    // -----------------------------------------------------------------------

    /**
     * Registers the host's MCP transport servlet and the PRM endpoint using the standard {@link
     * ServletContext} API.
     *
     * <p>This works with any Jakarta Servlet container (Tomcat, Jetty, Undertow, WildFly, etc.)
     * without additional dependencies. The host owns the transport provider (built with {@link
     * #adapter()} as the security validator and context extractor); this is a convenience that maps
     * it at {@link #mcpPath()} and serves the PRM document at {@link #prmPath()}.
     *
     * <p>Call this after building the {@code McpServer} (so the session factory is set on the
     * transport provider) but before the container starts serving requests.
     *
     * @param ctx the servlet context supplied by the container
     * @param transportProvider the host-owned MCP transport servlet to register at {@link
     *     #mcpPath()}
     */
    public void registerServlets(
            ServletContext ctx, HttpServletStreamableServerTransportProvider transportProvider) {
        ServletRegistration.Dynamic mcp = ctx.addServlet("authplane-mcp", transportProvider);
        mcp.addMapping(mcpPath);
        mcp.setAsyncSupported(true);

        ctx.addServlet("authplane-prm", prmServlet()).addMapping(prmPath);
    }

    // -----------------------------------------------------------------------
    // Builder
    // -----------------------------------------------------------------------

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Fluent builder for {@link AuthplaneMcpSetup}.
     *
     * <p>Only {@code issuer}, {@code resource}, and {@code scopes} are required.
     */
    public static final class Builder {

        private String issuer;
        private String resource;
        private List<String> scopes;

        // Client-level config
        private boolean devMode = false;
        private FetchSettings fetchSettings;
        private Integer jwksRefreshSeconds;
        private Integer metadataRefreshSeconds;
        private AuthProvider authProvider;
        private OutboundDPoPOptions outboundDPoP;
        private Executor executor;
        private Integer circuitBreakerThreshold;
        private Integer circuitBreakerCooldownSeconds;
        private TokenCacheConfig tokenCacheConfig;

        // Verifier-level config
        private List<String> allowedAlgorithms;
        private Integer clockSkewSeconds;
        private boolean useBuiltinRevocationChecker = false;
        private RevocationChecker revocationChecker;
        private InboundDPoPOptions inboundDPoP;

        private Builder() {}

        /** The Authorization Server issuer URI. Required. */
        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        /** The resource server URI — also the expected JWT {@code aud} claim. Required. */
        public Builder resource(String resource) {
            this.resource = resource;
            return this;
        }

        /** Scopes supported by this resource server. Required. */
        public Builder scopes(List<String> scopes) {
            this.scopes = scopes;
            return this;
        }

        public Builder devMode(boolean devMode) {
            this.devMode = devMode;
            return this;
        }

        public Builder allowedAlgorithms(List<String> algorithms) {
            this.allowedAlgorithms = algorithms;
            return this;
        }

        public Builder clockSkewSeconds(int seconds) {
            this.clockSkewSeconds = seconds;
            return this;
        }

        public Builder jwksRefreshSeconds(int seconds) {
            this.jwksRefreshSeconds = seconds;
            return this;
        }

        public Builder metadataRefreshSeconds(int seconds) {
            this.metadataRefreshSeconds = seconds;
            return this;
        }

        /**
         * Sets the {@link AuthProvider} for Authorization Server calls. Pass static client
         * credentials as {@code new ASCredentials(clientId, clientSecret)} (an {@code AuthProvider}
         * emitting HTTP Basic), or a custom provider for runtime credential rotation or non-Basic
         * authentication schemes. Invoked once per request.
         */
        public Builder authProvider(AuthProvider provider) {
            this.authProvider = Objects.requireNonNull(provider, "provider must not be null");
            return this;
        }

        public Builder useBuiltinRevocationChecker() {
            this.useBuiltinRevocationChecker = true;
            return this;
        }

        public Builder fetchSettings(FetchSettings settings) {
            this.fetchSettings = settings;
            return this;
        }

        public Builder revocationChecker(RevocationChecker checker) {
            this.revocationChecker = checker;
            return this;
        }

        /** Enables outbound DPoP proof generation for AS POST operations. */
        public Builder outboundDPoP(OutboundDPoPOptions options) {
            this.outboundDPoP = Objects.requireNonNull(options, "options must not be null");
            return this;
        }

        /** Sets the executor used for all async operations. */
        public Builder executor(Executor executor) {
            this.executor = Objects.requireNonNull(executor, "executor must not be null");
            return this;
        }

        /** Sets the number of failures before the circuit breaker opens. */
        public Builder circuitBreakerThreshold(int threshold) {
            this.circuitBreakerThreshold = threshold;
            return this;
        }

        /**
         * Sets the cooldown period in seconds before the circuit breaker transitions to half-open.
         */
        public Builder circuitBreakerCooldownSeconds(int seconds) {
            this.circuitBreakerCooldownSeconds = seconds;
            return this;
        }

        /** Configures the in-process token cache (TTL buffer, fallback TTL, max entries). */
        public Builder tokenCacheConfig(TokenCacheConfig config) {
            this.tokenCacheConfig = Objects.requireNonNull(config, "config must not be null");
            return this;
        }

        /** Enables inbound DPoP proof validation. */
        public Builder inboundDPoP(InboundDPoPOptions options) {
            this.inboundDPoP = Objects.requireNonNull(options, "options must not be null");
            return this;
        }

        /**
         * Validates configuration, creates the client, verifier, adapter, and PRM servlet.
         *
         * @return CompletableFuture completing with the ready-to-use setup
         */
        public CompletableFuture<AuthplaneMcpSetup> build() {
            Objects.requireNonNull(issuer, "issuer is required");
            Objects.requireNonNull(resource, "resource is required");
            Objects.requireNonNull(scopes, "scopes is required");

            URI resourceUri = URI.create(resource);
            String mcpPath = resourceUri.getPath();

            // Build client
            AuthplaneClientBuilder clientBuilder = AuthplaneClient.builder(issuer).devMode(devMode);
            if (fetchSettings != null) clientBuilder.fetchSettings(fetchSettings);
            if (jwksRefreshSeconds != null) clientBuilder.jwksRefreshSeconds(jwksRefreshSeconds);
            if (metadataRefreshSeconds != null)
                clientBuilder.metadataRefreshSeconds(metadataRefreshSeconds);
            if (authProvider != null) clientBuilder.authProvider(authProvider);
            if (outboundDPoP != null) clientBuilder.outboundDPoP(outboundDPoP);
            if (executor != null) clientBuilder.executor(executor);
            if (circuitBreakerThreshold != null)
                clientBuilder.circuitBreakerThreshold(circuitBreakerThreshold);
            if (circuitBreakerCooldownSeconds != null)
                clientBuilder.circuitBreakerCooldownSeconds(circuitBreakerCooldownSeconds);
            if (tokenCacheConfig != null) clientBuilder.tokenCacheConfig(tokenCacheConfig);

            return clientBuilder
                    .build()
                    .thenApply(
                            client -> {
                                // Build verifier
                                ResourceOptions.Builder optBuilder = ResourceOptions.builder();
                                if (allowedAlgorithms != null)
                                    optBuilder.allowedAlgorithms(allowedAlgorithms);
                                if (clockSkewSeconds != null)
                                    optBuilder.clockSkewSeconds(clockSkewSeconds);
                                if (revocationChecker != null)
                                    optBuilder.revocationChecker(revocationChecker);
                                if (useBuiltinRevocationChecker)
                                    optBuilder.useBuiltinRevocationChecker();
                                if (inboundDPoP != null) optBuilder.inboundDPoP(inboundDPoP);

                                AuthplaneResource authplaneResource =
                                        client.resource(this.resource, scopes, optBuilder.build());

                                // Build adapter (the host wires this into its own transport
                                // provider as securityValidator + contextExtractor).
                                AuthplaneMcpAdapter adapter =
                                        new AuthplaneMcpAdapter(client, authplaneResource);

                                // PrmServlet is created lazily by prmServlet(), serving PRM from
                                // the resource — the single source of truth (incl. DPoP fields).
                                return new AuthplaneMcpSetup(
                                        client,
                                        authplaneResource,
                                        adapter,
                                        mcpPath,
                                        authplaneResource.prmPath());
                            });
        }
    }
}
