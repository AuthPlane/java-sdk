package ai.authplane.sdk.spring.mcp;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;

import org.springframework.ai.mcp.server.webmvc.transport.WebMvcStreamableServerTransportProvider;
import org.springframework.web.servlet.function.ServerRequest;

import ai.authplane.sdk.core.AuthProvider;
import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.AuthplaneClientBuilder;
import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.ResourceOptions;
import ai.authplane.sdk.core.RevocationChecker;
import ai.authplane.sdk.core.TokenCacheConfig;
import ai.authplane.sdk.core.VerificationResult;
import ai.authplane.sdk.core.VerifiedClaims;
import ai.authplane.sdk.core.dpop.DPoPProofMissingException;
import ai.authplane.sdk.core.dpop.InboundDPoPOptions;
import ai.authplane.sdk.core.dpop.MultipleDpopProofsException;
import ai.authplane.sdk.core.dpop.OutboundDPoPOptions;
import ai.authplane.sdk.core.dpop.VerificationRequestContext;
import ai.authplane.sdk.core.errors.AuthplaneException;
import ai.authplane.sdk.core.errors.InsufficientScopeException;
import ai.authplane.sdk.core.fetching.FetchSettings;
import ai.authplane.sdk.core.http.HttpHeaders;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpTransportContextExtractor;
import io.modelcontextprotocol.server.transport.ServerTransportSecurityException;
import io.modelcontextprotocol.server.transport.ServerTransportSecurityValidator;

/**
 * Spring MVC (WebMVC) adapter for Authplane JWT token validation, designed for use with {@link
 * WebMvcStreamableServerTransportProvider}.
 *
 * <p>Implements both {@link ServerTransportSecurityValidator} (rejects requests with missing or
 * invalid Bearer tokens) and {@link McpTransportContextExtractor} (passes {@link VerifiedClaims} to
 * tool handlers), performing independent JWT signature verifications with no shared state between
 * the two hooks.
 *
 * <p>In {@code @Tool} methods, retrieve claims via:
 *
 * <pre>{@code
 * AuthplaneMcpServerAdapter.getClaims(exchange.transportContext())
 *         .requireScope("tools/add");
 * }</pre>
 *
 * <p><b>API Note — SSE GET DPoP behavior:</b> on the SSE GET notification-listener path, DPoP-bound
 * tokens ({@code cnf.jkt} present) have only their JWT signature, {@code exp}, {@code iss}, and
 * {@code aud} verified — the DPoP proof binding and the token's revocation state are <b>not</b>
 * checked. The upstream MCP SDK invokes only {@code validateHeaders} on SSE GET (never {@code
 * extract}), so the deferral mechanism this adapter uses for DPoP-bound POST traffic cannot reach
 * the proof or revocation checks. POST/PUT/DELETE traffic still receives full validation. This is
 * identical to {@code AuthplaneMcpAdapter}'s contract; the {@code AuthplaneAuthenticationProvider}
 * Spring Security filter is the only path in this SDK that runs verification once with full
 * context. See user-guide §13.
 *
 * <p><b>API Note — Double introspection on authenticated paths:</b> {@code validateHeaders} and
 * {@code extract} each invoke {@code resource.verify(...)}, so when RFC 7662 introspection-based
 * revocation checking is enabled a bearer-only request triggers two introspection calls to the
 * authorization server. A per-request memo (analogous to the TypeScript SDK's {@code
 * AsyncLocalStorage} cache) would collapse it to one without changing the public contract — left as
 * a noted follow-up.
 *
 * @see AuthplaneMcpServerConfig
 */
public final class AuthplaneMcpServerAdapter
        implements ServerTransportSecurityValidator, McpTransportContextExtractor<ServerRequest> {

    /** Context map key for the {@link VerifiedClaims} stored in {@link McpTransportContext}. */
    public static final String CLAIMS_KEY = "authplane.claims";

    private static final String BEARER_PREFIX = "Bearer ";

    private final AuthplaneResource resource;

    /** Package-private — used by tests and {@link Builder}. */
    AuthplaneMcpServerAdapter(AuthplaneResource resource) {
        this.resource = Objects.requireNonNull(resource, "resource must not be null");
    }

    // -----------------------------------------------------------------------
    // Factory
    // -----------------------------------------------------------------------

    /**
     * Creates an adapter using RFC 8414 metadata discovery.
     *
     * @param issuer the Authorization Server issuer URI
     * @param resource the resource server URI (expected JWT audience)
     * @param scopes scopes supported by this resource server
     * @return CompletableFuture completing with a ready-to-use adapter
     */
    public static CompletableFuture<AuthplaneMcpServerAdapter> create(
            String issuer, String resource, List<String> scopes) {
        return new Builder(issuer, resource, scopes).build();
    }

    // -----------------------------------------------------------------------
    // ServerTransportSecurityValidator
    // -----------------------------------------------------------------------

    /**
     * Validates the {@code Authorization: Bearer <token>} header.
     *
     * <p>Verifies the token in bearer-only mode (no {@link VerificationRequestContext}) and
     * discards the result — this is an early-rejection gate only. Claims are produced by the
     * subsequent {@link #extract} call, which has access to the {@link ServerRequest} and therefore
     * to the method, URL, and {@code DPoP} proof header needed for DPoP-bound tokens.
     *
     * <p><b>DPoP-bound tokens</b> ({@code cnf.jkt} present): bearer-only verify throws {@link
     * DPoPProofMissingException} by design (see {@code AuthplaneResource.validateDpop}). This
     * method <em>swallows</em> that specific exception so the request flows through to {@link
     * #extract}, where {@code resource.verify(token, context)} performs the full DPoP proof binding
     * check. Every other Authplane failure (expired, bad signature, revoked, DPoP unsupported,
     * scope insufficient) is still mapped to {@link ServerTransportSecurityException}.
     *
     * <p>For SSE GET listener streams the upstream MCP SDK calls only {@code validateHeaders} (no
     * {@code extract}). In that path a DPoP-bound token has its JWT signature, {@code exp}, {@code
     * iss}, and {@code aud} verified, but the DPoP proof binding is not validated (no request
     * object) <b>and</b> revocation is not checked either ({@code checkRevocation} runs after
     * {@code validateDpop} in {@code AuthplaneResource.verify}; the swallowed exception fires
     * first). See {@code mcp/docs/user-guide.md} §13 for the full rationale — this adapter shares
     * the upstream MCP SDK's two-hook contract and therefore the same SSE GET caveat as {@code
     * AuthplaneMcpAdapter}.
     *
     * <p>Note: the {@code AuthplaneAuthenticationProvider} Spring Security path is unaffected by
     * this asymmetry — its filter receives the full {@code HttpServletRequest} and runs a single
     * verify with context per request.
     *
     * @param headers request headers (multi-valued, case-insensitive lookup)
     * @throws ServerTransportSecurityException HTTP 401 if the Authorization header is missing,
     *     malformed, or carries an invalid token; HTTP 403 if the token is valid but has
     *     insufficient scope
     */
    @Override
    public void validateHeaders(Map<String, List<String>> headers)
            throws ServerTransportSecurityException {

        String authHeader = HttpHeaders.firstValue(headers, "Authorization");

        if (authHeader == null) {
            throw new ServerTransportSecurityException(401, "Authorization header is required");
        }

        if (!authHeader.startsWith(BEARER_PREFIX)) {
            throw new ServerTransportSecurityException(
                    401, "Authorization header must use Bearer scheme");
        }

        String token = authHeader.substring(BEARER_PREFIX.length()).strip();

        // RFC 9449 §4.3 #1: reject requests with more than one DPoP header before running the
        // verifier. The same check runs in VerificationRequestContext for the extract path; this
        // gate guards callers that use the validator without the matching extractor.
        try {
            VerificationRequestContext.assertSingleDpopHeader(HttpHeaders.values(headers, "dpop"));
        } catch (MultipleDpopProofsException e) {
            throw new ServerTransportSecurityException(401, e.getMessage());
        }

        try {
            resource.verify(token).join();
        } catch (CompletionException e) {
            Throwable cause = unwrapCompletion(e);
            if (cause instanceof DPoPProofMissingException) {
                // Token is DPoP-bound; bearer-only verify cannot bind the proof here (no
                // request object → no VerificationRequestContext). Defer to extract().
                return;
            }
            throw mapToSecurityException(cause);
        } catch (DPoPProofMissingException e) {
            // Defensive: today `resource.verify(token)` always returns a CompletableFuture
            // produced by supplyAsync, so failures surface via CompletionException above.
            // This branch guards against a future synchronous-throw refactor of
            // AuthplaneResource.verify.
            return;
        } catch (AuthplaneException e) {
            // Defensive (see DPoPProofMissingException branch above).
            throw mapToSecurityException(e);
        }
    }

    // -----------------------------------------------------------------------
    // McpTransportContextExtractor
    // -----------------------------------------------------------------------

    /**
     * Verifies the Bearer token with full request context (method, URL, DPoP proof) and wraps the
     * resulting claims in a {@link McpTransportContext}.
     *
     * @param request the Spring MVC server request
     * @return context containing {@link VerifiedClaims} at {@link #CLAIMS_KEY}
     * @throws AuthplaneException if the token is missing, malformed, or invalid
     */
    @Override
    public McpTransportContext extract(ServerRequest request) {
        String authHeader = request.headers().firstHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            throw new AuthplaneException("Authorization header is required");
        }

        String token = authHeader.substring(BEARER_PREFIX.length()).strip();
        List<String> dpopHeaders = request.headers().header("DPoP");
        String method = request.method().name();
        // DPoP htu: re-anchor the request URL to the resource's canonical scheme+host (not the
        // proxy-facing host), keeping the request path — proxy-independent and correct for resource
        // sub-paths.
        String url = resource.normalizeRequestUrl(request.uri().toString());

        try {
            VerificationRequestContext context =
                    new VerificationRequestContext(method, url, dpopHeaders);
            VerificationResult result = resource.verify(token, context).join();
            return McpTransportContext.create(Map.of(CLAIMS_KEY, result.claims()));
        } catch (CompletionException e) {
            Throwable cause = unwrapCompletion(e);
            if (cause instanceof RuntimeException re) throw re;
            throw new RuntimeException("Unexpected exception", cause);
        }
    }

    // -----------------------------------------------------------------------
    // Convenience helpers
    // -----------------------------------------------------------------------

    /**
     * Returns the {@link VerifiedClaims} stored in the given transport context, or {@code null} if
     * absent.
     *
     * @param context the transport context from {@code exchange.getTransportContext()}
     * @return verified claims, or {@code null} if not present
     */
    public static VerifiedClaims getClaims(McpTransportContext context) {
        if (context == null) {
            return null;
        }
        Object value = context.get(CLAIMS_KEY);
        return (value instanceof VerifiedClaims vc) ? vc : null;
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /**
     * Peels nested {@link CompletionException} layers to expose the root cause. A single {@code
     * getCause()} can leave a stale inner {@code CompletionException} when an async stage re-wraps
     * a failure (see {@code AuthplaneResource} composition). The depth cap is a defensive bound
     * against pathological {@code Throwable.initCause(this)} chains; real causes never get close.
     */
    private static Throwable unwrapCompletion(Throwable t) {
        Throwable cause = t;
        for (int i = 0;
                i < 8 && cause instanceof CompletionException && cause.getCause() != null;
                i++) {
            cause = cause.getCause();
        }
        return cause;
    }

    /**
     * Maps an Authplane (or unknown) exception to a {@link ServerTransportSecurityException} with
     * the correct HTTP status.
     */
    private static ServerTransportSecurityException mapToSecurityException(Throwable t) {
        if (t instanceof InsufficientScopeException) {
            return new ServerTransportSecurityException(403, t.getMessage());
        }
        if (t instanceof AuthplaneException) {
            return new ServerTransportSecurityException(401, t.getMessage());
        }
        return new ServerTransportSecurityException(401, "Token verification failed");
    }

    // -----------------------------------------------------------------------
    // Builder
    // -----------------------------------------------------------------------

    /**
     * Fluent builder for {@link AuthplaneMcpServerAdapter}.
     *
     * <p>Wraps {@link AuthplaneClientBuilder} for infrastructure and creates a verifier scoped to
     * the given resource and scopes.
     */
    public static final class Builder {

        private final String issuer;
        private final String resource;
        private final List<String> scopes;

        // Client-level config
        private boolean devMode = false;
        private FetchSettings fetchSettings = null;
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
        private RevocationChecker customRevocationChecker = null;
        private InboundDPoPOptions inboundDPoP;

        /**
         * @param issuer the Authorization Server issuer URI
         * @param resource the resource server URI (expected JWT audience)
         * @param scopes scopes supported by this resource server
         */
        public Builder(String issuer, String resource, List<String> scopes) {
            this.issuer = issuer;
            this.resource = resource;
            this.scopes = scopes;
        }

        public Builder allowedAlgorithms(List<String> algorithms) {
            this.allowedAlgorithms = algorithms;
            return this;
        }

        public Builder clockSkewSeconds(int seconds) {
            this.clockSkewSeconds = seconds;
            return this;
        }

        public Builder devMode(boolean devMode) {
            this.devMode = devMode;
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
         * Sets the {@link AuthProvider} for authenticated AS calls (introspection, revocation).
         * Pass static client credentials as {@code new ASCredentials(clientId, clientSecret)} (an
         * {@code AuthProvider} emitting HTTP Basic), or a custom provider for runtime credential
         * rotation or non-Basic authentication schemes. Invoked once per request.
         */
        public Builder authProvider(AuthProvider provider) {
            this.authProvider = Objects.requireNonNull(provider, "provider must not be null");
            return this;
        }

        /** Enables the built-in RFC 7662 introspection-based revocation check. */
        public Builder useBuiltinRevocationChecker() {
            if (customRevocationChecker != null) {
                throw new IllegalStateException(
                        "A custom RevocationChecker is already set; cannot also enable built-in introspection");
            }
            this.useBuiltinRevocationChecker = true;
            return this;
        }

        public Builder fetchSettings(FetchSettings settings) {
            this.fetchSettings = Objects.requireNonNull(settings, "fetchSettings must not be null");
            return this;
        }

        /**
         * Installs a custom {@link RevocationChecker}; mutually exclusive with the built-in one.
         */
        public Builder revocationChecker(RevocationChecker checker) {
            if (useBuiltinRevocationChecker) {
                throw new IllegalStateException(
                        "Built-in introspection is already enabled; cannot also set a custom RevocationChecker");
            }
            this.customRevocationChecker = checker;
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
         * Validates configuration, performs RFC 8414 metadata discovery and initial JWKS fetch,
         * then returns a ready-to-use adapter.
         *
         * @return CompletableFuture completing with the adapter
         */
        public CompletableFuture<AuthplaneMcpServerAdapter> build() {
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
                                ResourceOptions.Builder optBuilder = ResourceOptions.builder();
                                if (allowedAlgorithms != null)
                                    optBuilder.allowedAlgorithms(allowedAlgorithms);
                                if (clockSkewSeconds != null)
                                    optBuilder.clockSkewSeconds(clockSkewSeconds);
                                if (customRevocationChecker != null)
                                    optBuilder.revocationChecker(customRevocationChecker);
                                if (useBuiltinRevocationChecker)
                                    optBuilder.useBuiltinRevocationChecker();
                                if (inboundDPoP != null) optBuilder.inboundDPoP(inboundDPoP);

                                AuthplaneResource verifier =
                                        client.resource(resource, scopes, optBuilder.build());
                                return new AuthplaneMcpServerAdapter(verifier);
                            });
        }
    }
}
