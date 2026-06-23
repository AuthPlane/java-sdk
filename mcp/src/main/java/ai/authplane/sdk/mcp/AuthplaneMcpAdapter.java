package ai.authplane.sdk.mcp;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletionException;

import jakarta.servlet.http.HttpServletRequest;

import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.VerificationResult;
import ai.authplane.sdk.core.VerifiedClaims;
import ai.authplane.sdk.core.dpop.DPoPProofMissingException;
import ai.authplane.sdk.core.dpop.MultipleDpopProofsException;
import ai.authplane.sdk.core.dpop.VerificationRequestContext;
import ai.authplane.sdk.core.errors.AuthplaneException;
import ai.authplane.sdk.core.errors.InsufficientScopeException;
import ai.authplane.sdk.core.http.HttpHeaders;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpTransportContextExtractor;
import io.modelcontextprotocol.server.transport.ServerTransportSecurityException;
import io.modelcontextprotocol.server.transport.ServerTransportSecurityValidator;

/**
 * MCP Java SDK adapter for Authplane JWT token validation.
 *
 * <p>Implements both {@link ServerTransportSecurityValidator} (rejects requests with missing or
 * invalid Bearer tokens) and {@link McpTransportContextExtractor} (passes {@link VerifiedClaims} to
 * tool handlers), performing independent JWT signature verifications with no shared state between
 * the two hooks.
 *
 * <p>In tool handlers, retrieve claims via:
 *
 * <pre>{@code
 * VerifiedClaims claims = AuthplaneMcpAdapter.getClaims(exchange.transportContext());
 * claims.requireScope("tools/query");
 * }</pre>
 *
 * <p><b>API Note — SSE GET DPoP behavior:</b> on the SSE GET notification-listener path, DPoP-bound
 * tokens ({@code cnf.jkt} present) have only their JWT signature, {@code exp}, {@code iss}, and
 * {@code aud} verified — the DPoP proof binding and the token's revocation state are <b>not</b>
 * checked. The upstream MCP SDK invokes only {@code validateHeaders} on SSE GET (never {@code
 * extract}), so the deferral mechanism this adapter uses for DPoP-bound POST traffic cannot reach
 * the proof or revocation checks. POST/PUT/DELETE traffic still receives full validation. Operators
 * needing sender-binding or revocation enforcement on the listener stream must pre-validate at a
 * reverse proxy or use the Spring Security {@code AuthplaneAuthenticationProvider} filter. See
 * user-guide §13 for the full contract.
 *
 * <p><b>API Note — Double introspection on authenticated paths:</b> {@code validateHeaders} and
 * {@code extract} each invoke {@code resource.verify(...)}, so when RFC 7662 introspection-based
 * revocation checking is enabled a bearer-only request triggers two introspection calls to the
 * authorization server. A per-request memo (analogous to the TypeScript SDK's {@code
 * AsyncLocalStorage} cache) would collapse it to one without changing the public contract — left as
 * a noted follow-up.
 *
 * @see AuthplaneMcpSetup
 */
public final class AuthplaneMcpAdapter
        implements ServerTransportSecurityValidator,
                McpTransportContextExtractor<HttpServletRequest> {

    /** Context map key for the {@link VerifiedClaims} stored in {@link McpTransportContext}. */
    public static final String CLAIMS_KEY = "authplane.claims";

    private static final String BEARER_PREFIX = "Bearer ";

    private final AuthplaneClient client;
    private final AuthplaneResource resource;

    /**
     * Creates an adapter backed by the given client and resource.
     *
     * @param client the client that owns infrastructure and token operations
     * @param resource the resource scoped to a specific resource URI and scopes
     */
    public AuthplaneMcpAdapter(AuthplaneClient client, AuthplaneResource resource) {
        this.client = Objects.requireNonNull(client, "client must not be null");
        this.resource = Objects.requireNonNull(resource, "resource must not be null");
    }

    /** Returns the underlying {@link AuthplaneClient}. */
    public AuthplaneClient client() {
        return client;
    }

    /** Returns the underlying {@link AuthplaneResource}. */
    public AuthplaneResource resource() {
        return resource;
    }

    // -----------------------------------------------------------------------
    // ServerTransportSecurityValidator
    // -----------------------------------------------------------------------

    /**
     * Validates the {@code Authorization: Bearer <token>} header.
     *
     * <p>Verifies the token in bearer-only mode (no {@link VerificationRequestContext}) and
     * discards the result — this is an early-rejection gate only. Claims are produced by the
     * subsequent {@link #extract} call, which has access to the {@link HttpServletRequest} and
     * therefore to the method, URL, and {@code DPoP} proof header needed for DPoP-bound tokens.
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
     * iss}, and {@code aud} verified (those run inside {@code validator.verify} before {@code
     * validateDpop}), but the DPoP proof binding is not validated (no request object) <b>and</b>
     * revocation is not checked either: {@code AuthplaneResource.verify} runs {@code
     * checkRevocation} after {@code validateDpop}, so the {@code DPoPProofMissingException} thrown
     * for the no-context case fires before revocation can run. The adapter swallows that exception
     * here to defer to {@code extract}, but on SSE GET {@code extract} is never invoked. Acceptable
     * because SSE GET is a read-only notification listener; actionable JSON-RPC commands flow
     * through POST and receive full DPoP + revocation validation via {@code extract}. See
     * user-guide §13 for the full rationale.
     *
     * <p>The TypeScript SDK applies the equivalent workaround in its FastMCP integration ({@code
     * authenticate} is called twice per request and the verify result is cached across calls via
     * {@code AsyncLocalStorage}). The Java MCP SDK exposes two hooks that cannot share state
     * because {@code validateHeaders} receives only headers (no request), so the equivalent
     * invariant ("DPoP proof validated exactly once per request") is reached by deferring proof
     * binding to {@code extract} rather than caching across calls.
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
     * @param request the servlet request (Authorization header is read here)
     * @return context containing {@link VerifiedClaims} at {@link #CLAIMS_KEY}
     * @throws AuthplaneException if the token is missing, malformed, or invalid
     */
    @Override
    public McpTransportContext extract(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            throw new AuthplaneException("Authorization header is required");
        }

        String token = authHeader.substring(BEARER_PREFIX.length()).strip();
        List<String> dpopHeaders = headerValues(request, "DPoP");
        String method = request.getMethod();
        // DPoP htu: re-anchor the request URL to the resource's canonical scheme+host (not the
        // proxy-facing servlet host), keeping the request path — proxy-independent and correct for
        // resource sub-paths.
        String url = resource.normalizeRequestUrl(request.getRequestURL().toString());

        try {
            VerificationRequestContext context =
                    new VerificationRequestContext(method, url, dpopHeaders);
            VerificationResult result = resource.verify(token, context).join();
            return McpTransportContext.create(Map.of(CLAIMS_KEY, result.claims()));
        } catch (CompletionException e) {
            Throwable cause = unwrapCompletion(e);
            if (cause instanceof RuntimeException re) throw re;
            throw new AuthplaneMcpException("Unexpected exception during token extraction", cause);
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

    /** Returns all values for the given header from a servlet request, preserving duplicates. */
    private static List<String> headerValues(HttpServletRequest request, String name) {
        Enumeration<String> values = request.getHeaders(name);
        if (values == null) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        while (values.hasMoreElements()) {
            result.add(values.nextElement());
        }
        return result;
    }

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
}
