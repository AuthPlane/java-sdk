package ai.authplane.sdk.core;

import java.time.Clock;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import ai.authplane.sdk.core.dpop.DPoPProvider;
import ai.authplane.sdk.core.dpop.OutboundDPoPOptions;
import ai.authplane.sdk.core.errors.TokenExchangeException;
import ai.authplane.sdk.core.fetching.DocumentCache;
import ai.authplane.sdk.core.fetching.DocumentFetcher;
import ai.authplane.sdk.core.fetching.HttpTransport;
import ai.authplane.sdk.core.fetching.JwksCache;
import ai.authplane.sdk.core.fetching.MetadataCache;
import ai.authplane.sdk.core.oauth.ClientCredentialsGrant;
import ai.authplane.sdk.core.oauth.Introspection;
import ai.authplane.sdk.core.oauth.IntrospectionResponse;
import ai.authplane.sdk.core.oauth.Revocation;
import ai.authplane.sdk.core.oauth.TokenExchange;
import ai.authplane.sdk.core.prm.ProtectedResourceMetadata;

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

    /** Depth bound for the cause walk in {@link #isInterrupt}; see the comment there. */
    private static final int MAX_CAUSE_HOPS = 16;

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

    /** Installed by the builder right after construction; null when there is no metadata cache. */
    volatile JwksCacheFactory jwksCacheFactory;

    private final ReentrantLock jwksRebindLock = new ReentrantLock();

    /**
     * Suppresses rebind attempts after one fails, on the same policy the caches use.
     *
     * <p>The factory builds a fresh {@link JwksCache} per attempt, so the backoff a cache keeps for
     * itself starts from zero every time and cannot govern this. Without a backoff here, a rotated
     * {@code jwks_uri} that is down costs a full HTTP timeout on the verification path for as long
     * as the outage lasts — reconciling means the mismatch is re-detected on every key lookup, so
     * every lookup pays. Tokens whose keys are already cached do not need that fetch to succeed;
     * they only need it not to block them.
     *
     * <p>Volatile rather than lock-guarded: the fast path reads it before taking {@link
     * #jwksRebindLock}, and a read that races a write costs at most one extra attempt.
     */
    private volatile long jwksRebindRetryNotBeforeEpochSeconds;

    /**
     * Time source for the rebind backoff. Replaced by the builder so tests can advance it.
     *
     * <p>{@code volatile} for the same reason {@code jwksCacheFactory} is: it is written after the
     * constructor returns, so it carries none of the JMM final-field guarantees the other infra
     * fields on this class get. A client published through a data race could otherwise hand a
     * request thread {@code clock == null}, which NPEs in {@link #rebindJwksIfMoved}.
     */
    private volatile Clock clock = Clock.systemUTC();

    /**
     * Set by {@link AuthplaneClientBuilder} after construction, alongside {@code jwksCacheFactory},
     * rather than as a thirteenth constructor parameter.
     */
    void setClock(Clock clock) {
        this.clock = clock;
    }

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
        // RFC 8707 §2 / RFC 9728 §1.2: no fragment component. Redundant with the gate in the
        // AuthplaneResource constructor, kept so the stack trace points at the caller's line.
        ProtectedResourceMetadata.requireNoFragment(resourceUri);
        // RFC 3986 §3.4: the query is now part of the identifier and is spliced into the
        // WWW-Authenticate challenge, so an octet outside the query production must not get
        // past construction. Same reason, same boundary.
        ProtectedResourceMetadata.requireValidQuery(resourceUri);
        // RFC 8707 §2: an absolute URI always carries a scheme. Same reason, same boundary.
        ProtectedResourceMetadata.requireScheme(resourceUri);
        // RFC 9110 §4.2.4: no userinfo. The identifier is published to unauthenticated callers
        // verbatim, so a credential in the authority is disclosed. Same reason, same boundary.
        ProtectedResourceMetadata.requireNoUserinfo(resourceUri);

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
     * Reads through the AS metadata cache and reconciles {@link #jwksCache} against the {@code
     * jwks_uri} it advertises. This is what makes {@code metadataRefreshSeconds} effective on a
     * resource server that only verifies tokens.
     *
     * <p>Such a server never calls the token, introspection or revocation endpoints, so nothing on
     * its request path would otherwise touch the metadata document after start-up: the cache would
     * hold the copy fetched at build time forever, and a rotated {@code jwks_uri} would never be
     * followed. Verification calls this before every key lookup. The read is cheap while the
     * document is fresh; once the interval has elapsed the cache re-fetches, and a rotation takes
     * effect on the very lookup that discovered it.
     *
     * <p>The comparison is against the URI the cache is currently bound to, not against a change in
     * the document, and that difference is the whole point. {@code DocumentCache} publishes a
     * refreshed document before it notifies its change listener, so an edge-triggered rebind that
     * failed — one 503 at the new URI — would leave key retrieval pinned to the withdrawn one with
     * nothing left to re-trigger it: every later refresh returns that same document, so the edge
     * never fires again. Comparing desired state to actual state instead means a failed rebind is
     * simply retried on the next lookup.
     *
     * <p>Failures are swallowed deliberately. A metadata endpoint that is briefly unreachable must
     * not fail verification of tokens whose signing keys the JWKS cache already holds; the cache
     * falls back to the last good document, so this only logs when there is nothing to fall back
     * on.
     */
    void refreshMetadataIfDue() {
        if (metadataCache == null) {
            return;
        }
        String discoveredJwksUri;
        try {
            discoveredJwksUri = metadataCache.getJwksUri();
        } catch (InterruptedException e) {
            // Shutdown, not a metadata problem. The flag is restored by DocumentCache; re-raising
            // it here and returning keeps a stack trace out of the log on the way down.
            Thread.currentThread().interrupt();
            return;
        } catch (Exception e) {
            // The interrupt does not reach the branch above from this call site: MetadataCache
            // wraps everything that is not a MetadataFetchException, so it arrives here wrapped.
            // The flag is still restored upstream — only the logging would be wrong, and a stack
            // trace on the way down is exactly what that branch exists to avoid. The sibling catch
            // in rebindJwksIfMoved does see it unwrapped, since DocumentCache.fetch rethrows.
            if (isInterrupt(e)) {
                Thread.currentThread().interrupt();
                return;
            }
            LOG.log(
                    Level.WARNING,
                    "AS metadata refresh failed; continuing with the current JWKS binding",
                    e);
            return;
        }
        rebindJwksIfMoved(discoveredJwksUri);
    }

    /**
     * Whether a failure is an interrupt, however deeply it was wrapped on the way here.
     *
     * <p>Checking the thread's own flag would answer a different question: it stays set from an
     * interrupt this call had nothing to do with, and would then silence a real metadata failure.
     */
    // Package-private rather than private: the wrapped/unwrapped asymmetry the two call sites
    // rely on, and the cycle bound below, are both worth pinning directly.
    static boolean isInterrupt(Throwable error) {
        // Bounded rather than walked to the end. `initCause` refuses a self-reference, so the
        // `t.getCause() == t` guard alone looks sufficient — but it does not stop a cycle built
        // through the `Throwable(String, Throwable)` constructors, where A causes B causes A. That
        // walk never terminates. No real chain approaches this depth.
        int hops = 0;
        for (Throwable t = error; t != null && hops < MAX_CAUSE_HOPS; t = t.getCause(), hops++) {
            if (t instanceof InterruptedException) {
                return true;
            }
            if (t.getCause() == t) {
                break;
            }
        }
        return false;
    }

    /**
     * Rebinds {@link #jwksCache} when the metadata document points key retrieval somewhere else.
     * No-op when the two already agree, which is every call but the one that follows a rotation.
     */
    private void rebindJwksIfMoved(String discoveredJwksUri) {
        if (jwksCacheFactory == null || discoveredJwksUri.equals(jwksCache.getUrl())) {
            return;
        }
        long now = clock.instant().getEpochSecond();
        if (now < jwksRebindRetryNotBeforeEpochSeconds) {
            LOG.fine(
                    () ->
                            "jwks_uri rebind backing off after a failed attempt (retry in "
                                    + (jwksRebindRetryNotBeforeEpochSeconds - now)
                                    + "s); keeping the current binding");
            return;
        }
        // One rebind at a time. A caller that loses the race keeps the current binding for this
        // lookup rather than queueing behind a JWKS fetch; the winner publishes for everyone, and
        // a kid miss forces a refresh anyway.
        if (!jwksRebindLock.tryLock()) {
            return;
        }
        try {
            String boundUri = jwksCache.getUrl();
            if (discoveredJwksUri.equals(boundUri)) {
                return; // another thread got there first
            }
            LOG.warning(
                    "jwks_uri changed from '"
                            + boundUri
                            + "' to '"
                            + discoveredJwksUri
                            + "', restarting JWKS cache");
            jwksCache = jwksCacheFactory.create(discoveredJwksUri);
            jwksRebindRetryNotBeforeEpochSeconds = 0;
            LOG.info(() -> "JWKS cache restarted with new URI: " + discoveredJwksUri);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            long backoff = DocumentCache.failureBackoffSeconds(jwksRefreshSeconds);
            jwksRebindRetryNotBeforeEpochSeconds = clock.instant().getEpochSecond() + backoff;
            LOG.log(
                    Level.WARNING,
                    "Failed to initialise new JWKS cache for URI: "
                            + discoveredJwksUri
                            + ". Keeping the existing cache; retrying in "
                            + backoff
                            + "s.",
                    e);
        } finally {
            jwksRebindLock.unlock();
        }
    }

    /**
     * Builds a JWKS cache bound to a newly discovered {@code jwks_uri}, already populated. Supplied
     * by {@link AuthplaneClientBuilder}, which owns the fetcher, the refresh interval and the time
     * source a new cache needs.
     */
    @FunctionalInterface
    interface JwksCacheFactory {
        JwksCache create(String jwksUri) throws Exception;
    }

    /**
     * Forces a synchronous metadata refresh, bypassing the configured interval. The JWKS binding is
     * not touched here — it is reconciled by the next {@link #refreshMetadataIfDue()}, which is
     * what every key lookup calls. Package-private — for use in tests only.
     */
    void forceMetadataRefreshForTest() throws Exception {
        if (metadataCache != null) {
            // Bypasses the failure backoff: a test asking for a refresh wants the attempt made, not
            // the cached copy handed back. The request-path callers deliberately do not.
            metadataCache.forceRefreshIgnoringFailureBackoff();
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
