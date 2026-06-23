package ai.authplane.sdk.core;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.logging.Logger;

import ai.authplane.sdk.core.dpop.DPoPProvider;
import ai.authplane.sdk.core.dpop.OutboundDPoPOptions;
import ai.authplane.sdk.core.errors.TokenExchangeException;
import ai.authplane.sdk.core.fetching.DocumentFetcher;
import ai.authplane.sdk.core.fetching.HttpTransport;
import ai.authplane.sdk.core.fetching.JwksCache;
import ai.authplane.sdk.core.fetching.MetadataCache;
import ai.authplane.sdk.core.oauth.ClientCredentialsGrant;
import ai.authplane.sdk.core.oauth.Introspection;
import ai.authplane.sdk.core.oauth.IntrospectionResponse;
import ai.authplane.sdk.core.oauth.Revocation;
import ai.authplane.sdk.core.oauth.TokenExchange;

/**
 * Central owner of Authorization Server connection state and token operations.
 *
 * <p>A single client can serve multiple resources via {@link #resource(String, List)}. The client
 * owns the metadata cache, JWKS cache, HTTP transport, circuit breaker, and token cache — all
 * shared across resources.
 *
 * <pre>{@code
 * AuthplaneClient client = AuthplaneClient.builder("https://auth.example.com")
 *     .authProvider(new ASCredentials("my-rs", "s3cret"))
 *     .build()
 *     .get();
 *
 * // ... use client ...
 *
 * client.close(); // on shutdown
 * }</pre>
 *
 * <p>See the project README for full usage examples.
 *
 * @see AuthplaneClientBuilder
 * @see AuthplaneResource
 * @see TokenExchangeOptions
 */
// Not final: downstream adapter tests mock this class with Mockito (subclass mock-maker).
@SuppressWarnings("checkstyle:FinalClass")
public class AuthplaneClient implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(AuthplaneClient.class.getName());

    /** Algorithms that must never be allowed. */
    private static final Set<String> DANGEROUS_ALGORITHMS =
            Set.of("none", "HS256", "HS384", "HS512");

    // Configuration
    private final String issuer;
    private final boolean devMode;

    // Infrastructure
    volatile JwksCache jwksCache;
    final MetadataCache metadataCache; // null if metadata not available
    final HttpTransport transport;
    final AuthProvider authProvider; // nullable
    final DocumentFetcher fetcher;
    final int jwksRefreshSeconds;

    // Async execution
    final Executor executor;

    // Resilience
    final CircuitBreaker circuitBreaker;
    final TokenCache tokenCache;
    final OutboundDPoPOptions outboundDPoP;
    private final ConcurrentHashMap<String, CompletableFuture<TokenResponse>> inflight =
            new ConcurrentHashMap<>();

    @SuppressWarnings("checkstyle:ParameterNumber") // Package-private; only called by the builder.
    AuthplaneClient(
            String issuer,
            boolean devMode,
            JwksCache jwksCache,
            MetadataCache metadataCache,
            HttpTransport transport,
            AuthProvider authProvider,
            DocumentFetcher fetcher,
            int jwksRefreshSeconds,
            CircuitBreaker circuitBreaker,
            TokenCache tokenCache,
            OutboundDPoPOptions outboundDPoP,
            Executor executor) {
        this.issuer = issuer;
        this.devMode = devMode;
        this.jwksCache = jwksCache;
        this.metadataCache = metadataCache;
        this.transport = transport;
        this.authProvider = authProvider;
        this.fetcher = fetcher;
        this.jwksRefreshSeconds = jwksRefreshSeconds;
        this.circuitBreaker = circuitBreaker;
        this.tokenCache = tokenCache;
        this.outboundDPoP = outboundDPoP;
        this.executor = executor;
    }

    // -----------------------------------------------------------------------
    // Factory
    // -----------------------------------------------------------------------

    /**
     * Creates a builder for this client, using RFC 8414 metadata discovery for the given issuer.
     */
    public static AuthplaneClientBuilder builder(String issuer) {
        return new AuthplaneClientBuilder(issuer);
    }

    // -----------------------------------------------------------------------
    // Resource factory
    // -----------------------------------------------------------------------

    /**
     * Creates a lightweight protected resource scoped to the given resource URI and scopes. Uses
     * default resource options (RS256+ES256, 30s clock skew, no revocation).
     */
    public AuthplaneResource resource(String resourceUri, List<String> scopes) {
        return resource(resourceUri, scopes, ResourceOptions.defaults());
    }

    /**
     * Creates a lightweight protected resource scoped to the given resource URI, scopes, and custom
     * options.
     */
    public AuthplaneResource resource(
            String resourceUri, List<String> scopes, ResourceOptions options) {
        Objects.requireNonNull(resourceUri, "resourceUri must not be null");
        Objects.requireNonNull(scopes, "scopes must not be null");
        Objects.requireNonNull(options, "options must not be null");
        if (resourceUri.isBlank())
            throw new IllegalArgumentException("resourceUri must not be blank");

        // Validate algorithms
        Set<String> dangerous = new HashSet<>(options.allowedAlgorithms());
        dangerous.retainAll(DANGEROUS_ALGORITHMS);
        if (!dangerous.isEmpty()) {
            throw new IllegalArgumentException(
                    "Dangerous algorithms are not permitted: "
                            + dangerous
                            + ". Only asymmetric algorithms (RS256, ES256, etc.) are allowed.");
        }

        return new AuthplaneResource(this, resourceUri, scopes, options);
    }

    // -----------------------------------------------------------------------
    // Token operations
    // -----------------------------------------------------------------------

    /**
     * Performs an RFC 6749 §4.4 client credentials grant with a list of scopes and multiple
     * resource indicators per RFC 8707.
     *
     * <p>Scopes are joined with a space separator for the {@code scope} form parameter. Each entry
     * in {@code resources} is emitted as a separate {@code resource} form parameter. Empty or null
     * lists cause the respective parameter to be omitted.
     *
     * @param scopes scopes to request (null or empty → omit scope parameter)
     * @param resources resource indicators (null or empty → omit resource parameters)
     * @return CompletableFuture completing with the token response
     */
    public CompletableFuture<TokenResponse> clientCredentials(
            List<String> scopes, List<String> resources) {
        if (authProvider == null) {
            return CompletableFuture.failedFuture(
                    new IllegalStateException(
                            "Client credentials grant requires an authProvider (e.g. ASCredentials) to be set on the client builder."));
        }

        String cacheKey = CacheKeys.clientCredentials(scopes, resources);
        TokenResponse cached = tokenCache.get(cacheKey);
        if (cached != null) {
            return CompletableFuture.completedFuture(cached);
        }

        return inflight.computeIfAbsent(
                cacheKey,
                k ->
                        CompletableFuture.supplyAsync(
                                        () -> {
                                            // Re-check cache: another inflight may have populated
                                            // it
                                            TokenResponse rechecked = tokenCache.get(k);
                                            if (rechecked != null) {
                                                return rechecked;
                                            }
                                            try {
                                                String tokenEndpoint = resolveTokenEndpoint();
                                                TokenResponse resp =
                                                        circuitBreaker.execute(
                                                                () ->
                                                                        ClientCredentialsGrant
                                                                                .execute(
                                                                                        tokenEndpoint,
                                                                                        CacheKeys
                                                                                                .normalizeValues(
                                                                                                        scopes),
                                                                                        CacheKeys
                                                                                                .normalizeValues(
                                                                                                        resources),
                                                                                        authProvider,
                                                                                        transport,
                                                                                        dpopProvider()),
                                                                CircuitPolicy::shouldTrip);
                                                tokenCache.put(k, resp);
                                                return resp;
                                            } catch (CircuitOpenException e) {
                                                throw new CompletionException(
                                                        new TokenExchangeException(
                                                                e.getMessage(), null));
                                            } catch (TokenExchangeException e) {
                                                throw new CompletionException(e);
                                            } catch (Exception e) {
                                                throw new CompletionException(
                                                        new TokenExchangeException(
                                                                "Client credentials grant failed: "
                                                                        + e.getMessage(),
                                                                null,
                                                                e));
                                            }
                                        },
                                        executor)
                                .whenComplete((resp, err) -> inflight.remove(k)));
    }

    /**
     * Performs an RFC 8693 token exchange.
     *
     * @param options exchange parameters
     * @return CompletableFuture completing with the exchanged token response
     */
    public CompletableFuture<TokenResponse> exchange(TokenExchangeOptions options) {
        String cacheKey = CacheKeys.tokenExchange(options);
        TokenResponse cached = tokenCache.get(cacheKey);
        if (cached != null) {
            return CompletableFuture.completedFuture(cached);
        }

        return inflight.computeIfAbsent(
                cacheKey,
                k ->
                        CompletableFuture.supplyAsync(
                                        () -> {
                                            TokenResponse rechecked = tokenCache.get(k);
                                            if (rechecked != null) {
                                                return rechecked;
                                            }
                                            try {
                                                String tokenEndpoint = resolveTokenEndpoint();
                                                TokenResponse resp =
                                                        circuitBreaker.execute(
                                                                () ->
                                                                        TokenExchange.exchange(
                                                                                tokenEndpoint,
                                                                                options,
                                                                                authProvider,
                                                                                transport,
                                                                                dpopProvider()),
                                                                CircuitPolicy::shouldTrip);
                                                tokenCache.put(k, resp);
                                                return resp;
                                            } catch (CircuitOpenException e) {
                                                throw new CompletionException(
                                                        new TokenExchangeException(
                                                                e.getMessage(), null));
                                            } catch (TokenExchangeException e) {
                                                throw new CompletionException(e);
                                            } catch (Exception e) {
                                                throw new CompletionException(
                                                        new TokenExchangeException(
                                                                "Token exchange failed: "
                                                                        + e.getMessage(),
                                                                null,
                                                                e));
                                            }
                                        },
                                        executor)
                                .whenComplete((resp, err) -> inflight.remove(k)));
    }

    /**
     * Performs RFC 7662 token introspection.
     *
     * @param token the token to introspect
     * @return CompletableFuture completing with the introspection response
     */
    public CompletableFuture<IntrospectionResponse> introspect(String token) {
        return CompletableFuture.supplyAsync(
                () -> {
                    try {
                        String introspectionEndpoint = resolveIntrospectionEndpoint();
                        return circuitBreaker.execute(
                                () ->
                                        Introspection.introspect(
                                                introspectionEndpoint,
                                                token,
                                                authProvider,
                                                transport,
                                                dpopProvider()),
                                CircuitPolicy::shouldTrip);
                    } catch (CircuitOpenException e) {
                        throw new CompletionException(
                                new TokenExchangeException(e.getMessage(), null));
                    } catch (Exception e) {
                        throw new CompletionException(e);
                    }
                },
                executor);
    }

    /**
     * Performs RFC 7009 token revocation.
     *
     * @param token the token to revoke
     * @return CompletableFuture completing when revocation is done
     */
    public CompletableFuture<Void> revoke(String token) {
        return CompletableFuture.supplyAsync(
                () -> {
                    try {
                        String revocationEndpoint = resolveRevocationEndpoint();
                        return circuitBreaker.execute(
                                () -> {
                                    Revocation.revoke(
                                            revocationEndpoint,
                                            token,
                                            "access_token",
                                            authProvider,
                                            transport,
                                            dpopProvider());
                                    return null;
                                },
                                CircuitPolicy::shouldTrip);
                    } catch (CircuitOpenException e) {
                        throw new CompletionException(
                                new TokenExchangeException(e.getMessage(), null));
                    } catch (Exception e) {
                        throw new CompletionException(e);
                    }
                },
                executor);
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    public String issuer() {
        return issuer;
    }

    public boolean devMode() {
        return devMode;
    }

    /**
     * Builds DPoP headers for a caller-managed downstream HTTP request.
     *
     * <p>Requires outbound DPoP to be configured on this client via {@link
     * AuthplaneClientBuilder#outboundDPoP(OutboundDPoPOptions)}.
     *
     * @param method HTTP method for the downstream request
     * @param absoluteUrl absolute request URL used as the DPoP {@code htu}
     * @return a header map containing the {@code DPoP} proof header
     * @throws IllegalStateException if outbound DPoP is not configured on this client
     */
    public Map<String, String> dpopHeaders(String method, String absoluteUrl) {
        DPoPProvider provider = requireDpopProvider();
        return provider.buildHeaders(method, absoluteUrl);
    }

    /**
     * Builds DPoP headers for a caller-managed downstream HTTP request and binds the proof to the
     * supplied access token via {@code ath}.
     *
     * @param method HTTP method for the downstream request
     * @param absoluteUrl absolute request URL used as the DPoP {@code htu}
     * @param accessToken access token whose hash should be embedded as {@code ath}
     * @return a header map containing the {@code DPoP} proof header
     * @throws IllegalStateException if outbound DPoP is not configured on this client
     */
    public Map<String, String> dpopHeaders(String method, String absoluteUrl, String accessToken) {
        DPoPProvider provider = requireDpopProvider();
        return provider.buildHeaders(method, absoluteUrl, accessToken);
    }

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    @Override
    public void close() {
        tokenCache.clear();
        LOG.info("AuthplaneClient closed");
    }

    // -----------------------------------------------------------------------
    // Package-private — used by AuthplaneResource
    // -----------------------------------------------------------------------

    /**
     * Forces a synchronous metadata refresh, triggering the jwks_uri rotation callback if the
     * metadata document has changed. Package-private — for use in tests only.
     */
    void forceMetadataRefreshForTest() throws Exception {
        if (metadataCache != null) {
            metadataCache.forceRefresh();
        }
    }

    DPoPProvider dpopProvider() {
        return outboundDPoP != null ? outboundDPoP.provider() : null;
    }

    private DPoPProvider requireDpopProvider() {
        DPoPProvider provider = dpopProvider();
        if (provider == null) {
            throw new IllegalStateException("No outbound DPoP provider configured on this client");
        }
        return provider;
    }

    // -----------------------------------------------------------------------
    // Endpoint resolution
    // -----------------------------------------------------------------------

    private String resolveTokenEndpoint() throws Exception {
        if (metadataCache == null) {
            throw new IllegalStateException(
                    "Token operations require AS metadata discovery. "
                            + "Build AuthplaneClient without skipping metadata.");
        }
        Map<String, Object> metadata = metadataCache.get();
        Object ep = metadata.get("token_endpoint");
        if (!(ep instanceof String endpoint) || endpoint.isBlank()) {
            throw new TokenExchangeException("AS metadata has no 'token_endpoint'", null);
        }
        return endpoint;
    }

    private String resolveIntrospectionEndpoint() throws Exception {
        if (metadataCache == null) {
            throw new IllegalStateException("Introspection requires AS metadata discovery.");
        }
        Map<String, Object> metadata = metadataCache.get();
        Object ep = metadata.get("introspection_endpoint");
        if (!(ep instanceof String endpoint) || endpoint.isBlank()) {
            throw new IllegalStateException("AS metadata has no 'introspection_endpoint'");
        }
        return endpoint;
    }

    private String resolveRevocationEndpoint() throws Exception {
        if (metadataCache == null) {
            throw new IllegalStateException("Revocation requires AS metadata discovery.");
        }
        Map<String, Object> metadata = metadataCache.get();
        Object ep = metadata.get("revocation_endpoint");
        if (!(ep instanceof String endpoint) || endpoint.isBlank()) {
            throw new IllegalStateException("AS metadata has no 'revocation_endpoint'");
        }
        return endpoint;
    }
}
