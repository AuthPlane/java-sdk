package ai.authplane.sdk.core;

import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;
import java.util.logging.Level;
import java.util.logging.Logger;

import ai.authplane.sdk.core.dpop.OutboundDPoPOptions;
import ai.authplane.sdk.core.fetching.DocumentFetcher;
import ai.authplane.sdk.core.fetching.FetchSettings;
import ai.authplane.sdk.core.fetching.HttpTransport;
import ai.authplane.sdk.core.fetching.JwksCache;
import ai.authplane.sdk.core.fetching.MetadataCache;
import ai.authplane.sdk.core.fetching.MetadataUrlBuilder;

/**
 * Fluent builder for {@link AuthplaneClient}.
 *
 * <p>Validates configuration, performs RFC 8414 metadata discovery and an initial JWKS fetch, then
 * returns a ready-to-use client via {@link #build()}.
 *
 * <pre>{@code
 * AuthplaneClient client = AuthplaneClientBuilder.create("https://auth.example.com")
 *     .authProvider(new ASCredentials("my-rs", "s3cret"))
 *     .build()
 *     .get();
 * }</pre>
 */
public final class AuthplaneClientBuilder {

    private static final Logger LOG = Logger.getLogger(AuthplaneClientBuilder.class.getName());

    private final String issuer;
    private boolean devMode = false;
    private FetchSettings fetchSettings = null;
    private int jwksRefreshSeconds = 300;
    private int metadataRefreshSeconds = 3600;
    private AuthProvider authProvider = null;
    private int circuitBreakerThreshold = 5;
    private int circuitBreakerCooldownSeconds = 30;
    private TokenCacheConfig tokenCacheConfig = TokenCacheConfig.defaults();
    private OutboundDPoPOptions outboundDPoP = null;
    private Executor executor = null;

    AuthplaneClientBuilder(String issuer) {
        Objects.requireNonNull(issuer, "issuer must not be null");
        if (issuer.isBlank()) throw new IllegalArgumentException("issuer must not be blank");
        // Store the issuer verbatim (identity is preserved). Any trailing slash is stripped only
        // where a URL is *derived* (RFC 8414/9728 §3.1), never on the stored/compared identifier.
        this.issuer = issuer;
    }

    /** Sets development mode. When true, SSRF protection is relaxed. */
    public AuthplaneClientBuilder devMode(boolean devMode) {
        this.devMode = devMode;
        return this;
    }

    /** Overrides fetch settings (timeouts, response size limits, SSRF protection). */
    public AuthplaneClientBuilder fetchSettings(FetchSettings settings) {
        this.fetchSettings = Objects.requireNonNull(settings, "fetchSettings must not be null");
        return this;
    }

    /** Sets the JWKS background-refresh interval in seconds. */
    public AuthplaneClientBuilder jwksRefreshSeconds(int seconds) {
        this.jwksRefreshSeconds = seconds;
        return this;
    }

    /** Sets the metadata background-refresh interval in seconds. */
    public AuthplaneClientBuilder metadataRefreshSeconds(int seconds) {
        this.metadataRefreshSeconds = seconds;
        return this;
    }

    /**
     * Sets the {@link AuthProvider} for Authorization Server calls (token, introspection,
     * revocation). Pass static client credentials as {@code new ASCredentials(clientId,
     * clientSecret)} (which is an {@code AuthProvider} emitting HTTP Basic), or a custom provider
     * for runtime credential rotation or non-Basic authentication schemes. Invoked once per
     * request.
     */
    public AuthplaneClientBuilder authProvider(AuthProvider provider) {
        this.authProvider = Objects.requireNonNull(provider, "provider must not be null");
        return this;
    }

    /**
     * Enables outbound DPoP proof generation for AS POST operations executed by this client and for
     * downstream helper calls such as {@link AuthplaneClient#dpopHeaders(String, String)}.
     */
    public AuthplaneClientBuilder outboundDPoP(OutboundDPoPOptions options) {
        this.outboundDPoP = Objects.requireNonNull(options, "options must not be null");
        return this;
    }

    /**
     * Sets the executor used for all async operations (token requests, verification, introspection,
     * revocation).
     *
     * <p><strong>WARNING:</strong> By default the common {@link ForkJoinPool} is used. This pool
     * has limited parallelism (CPU cores - 1) and is shared across the entire JVM. Under load,
     * blocking HTTP calls on this pool can starve other framework code. <strong>Production
     * deployments should provide a dedicated executor</strong> (e.g. {@code
     * Executors.newCachedThreadPool()}) to avoid thread starvation.
     *
     * @param executor the executor to use for async operations
     */
    public AuthplaneClientBuilder executor(Executor executor) {
        this.executor = Objects.requireNonNull(executor, "executor must not be null");
        return this;
    }

    /** Sets the consecutive-failure threshold before the circuit breaker opens. */
    public AuthplaneClientBuilder circuitBreakerThreshold(int threshold) {
        this.circuitBreakerThreshold = threshold;
        return this;
    }

    /** Sets the cooldown period (in seconds) before the circuit breaker re-attempts. */
    public AuthplaneClientBuilder circuitBreakerCooldownSeconds(int seconds) {
        this.circuitBreakerCooldownSeconds = seconds;
        return this;
    }

    /**
     * Configures the in-process token cache (TTL buffer, fallback TTL, and maximum entries).
     *
     * @param config the token cache configuration; see {@link TokenCacheConfig}
     */
    public AuthplaneClientBuilder tokenCacheConfig(TokenCacheConfig config) {
        this.tokenCacheConfig = Objects.requireNonNull(config, "config must not be null");
        return this;
    }

    /**
     * Validates configuration, performs RFC 8414 metadata discovery and initial JWKS fetch, then
     * returns a ready-to-use client.
     */
    public CompletableFuture<AuthplaneClient> build() {
        if (jwksRefreshSeconds <= 0) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException(
                            "jwksRefreshSeconds must be positive, got " + jwksRefreshSeconds));
        }
        if (metadataRefreshSeconds <= 0) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException(
                            "metadataRefreshSeconds must be positive, got "
                                    + metadataRefreshSeconds));
        }
        boolean effectiveDevMode =
                devMode || "true".equalsIgnoreCase(System.getenv("AUTHPLANE_DEV_MODE"));

        FetchSettings effectiveFetchSettings =
                (fetchSettings != null)
                        ? fetchSettings
                        : FetchSettings.fromDevMode(effectiveDevMode);

        if (!effectiveFetchSettings.ssrfProtection()) {
            LOG.warning("AuthplaneClient running with SSRF protection disabled");
        }

        return CompletableFuture.supplyAsync(
                () -> {
                    try {
                        return buildSync(effectiveDevMode, effectiveFetchSettings);
                    } catch (Exception e) {
                        throw new CompletionException(e);
                    }
                });
    }

    private AuthplaneClient buildSync(
            boolean effectiveDevMode, FetchSettings effectiveFetchSettings) throws Exception {

        HttpTransport transport = HttpTransport.from(effectiveFetchSettings);
        DocumentFetcher fetcher = DocumentFetcher.from(transport);

        String metadataUrl = MetadataUrlBuilder.buildMetadataUrl(issuer);
        LOG.info(() -> "Fetching AS metadata from: " + metadataUrl);
        MetadataCache metadataCache =
                new MetadataCache(
                        fetcher,
                        metadataUrl,
                        metadataRefreshSeconds,
                        issuer,
                        effectiveFetchSettings.allowHttp(),
                        null);
        metadataCache.fetch();

        String resolvedJwksUri = metadataCache.getJwksUri();
        LOG.info(() -> "Discovered JWKS URI: " + resolvedJwksUri);

        JwksCache jwksCache = new JwksCache(fetcher, resolvedJwksUri, jwksRefreshSeconds, null);
        jwksCache.fetch();

        CircuitBreaker circuitBreaker =
                new CircuitBreaker(circuitBreakerThreshold, circuitBreakerCooldownSeconds);
        TokenCache tokenCache = new TokenCache(tokenCacheConfig);

        Executor effectiveExecutor = executor != null ? executor : ForkJoinPool.commonPool();

        AuthplaneClient client =
                new AuthplaneClient(
                        issuer,
                        effectiveDevMode,
                        jwksCache,
                        metadataCache,
                        transport,
                        authProvider,
                        fetcher,
                        jwksRefreshSeconds,
                        circuitBreaker,
                        tokenCache,
                        outboundDPoP,
                        effectiveExecutor);

        wireMetadataCallback(client, metadataCache, fetcher);
        return client;
    }

    private void wireMetadataCallback(
            AuthplaneClient client, MetadataCache metadataCache, DocumentFetcher fetcher) {
        // Safe from concurrent races: the MetadataCache invokes this callback
        // inside its fetchLock, so jwks_uri rotation is serialized even if
        // multiple background refreshes overlap.
        metadataCache.setOnChangeCallback(
                (oldDoc, newDoc) -> {
                    Object newEp = newDoc.get("introspection_endpoint");
                    Object oldEp = oldDoc.get("introspection_endpoint");
                    if (!Objects.equals(oldEp, newEp)) {
                        LOG.info(() -> "AS introspection_endpoint changed to: " + newEp);
                    }

                    Object newTe = newDoc.get("token_endpoint");
                    Object oldTe = oldDoc.get("token_endpoint");
                    if (!Objects.equals(oldTe, newTe)) {
                        LOG.info(() -> "AS token_endpoint changed to: " + newTe);
                    }

                    Object newUriObj = newDoc.get("jwks_uri");
                    if (!(newUriObj instanceof String newUri)) return;
                    if (newUri.equals(client.jwksCache.getUrl())) return;

                    LOG.warning(
                            "jwks_uri changed from '"
                                    + client.jwksCache.getUrl()
                                    + "' to '"
                                    + newUri
                                    + "', restarting JWKS cache");

                    JwksCache newCache = new JwksCache(fetcher, newUri, jwksRefreshSeconds, null);
                    try {
                        newCache.fetch();
                        client.jwksCache = newCache;
                        LOG.info(() -> "JWKS cache restarted with new URI: " + newUri);
                    } catch (Exception e) {
                        LOG.log(
                                Level.WARNING,
                                "Failed to initialise new JWKS cache for URI: "
                                        + newUri
                                        + ". Keeping existing cache.",
                                e);
                    }
                });
    }
}
