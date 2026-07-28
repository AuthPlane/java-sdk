package ai.authplane.sdk.core;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.logging.Logger;

import ai.authplane.sdk.core.dpop.DPoPBindingMismatchException;
import ai.authplane.sdk.core.dpop.DPoPNotSupportedException;
import ai.authplane.sdk.core.dpop.DPoPProofMissingException;
import ai.authplane.sdk.core.dpop.DPoPProofVerifier;
import ai.authplane.sdk.core.dpop.InboundDPoPOptions;
import ai.authplane.sdk.core.dpop.VerificationRequestContext;
import ai.authplane.sdk.core.dpop.VerifiedDPoPProof;
import ai.authplane.sdk.core.errors.AuthplaneException;
import ai.authplane.sdk.core.errors.InvalidClaimsException;
import ai.authplane.sdk.core.errors.TokenRevokedException;
import ai.authplane.sdk.core.prm.ProtectedResourceMetadata;

/**
 * Lightweight, scoped protected resource. Always created from an {@link AuthplaneClient} via {@link
 * AuthplaneClient#resource(String, List)} or {@link AuthplaneClient#resource(String, List,
 * ResourceOptions)}.
 *
 * <p>The resource's only job is JWT verification and PRM generation. All infrastructure (metadata,
 * JWKS, transport) and token operations (exchange, introspection, revocation) belong to the parent
 * {@link AuthplaneClient}.
 *
 * @see AuthplaneClient#resource(String, List)
 * @see AuthplaneClient#resource(String, List, ResourceOptions)
 * @see ResourceOptions
 */
public class AuthplaneResource {

    private static final Logger LOG = Logger.getLogger(AuthplaneResource.class.getName());

    // Parent client — owns all infrastructure
    private final AuthplaneClient client;

    // Scoped configuration
    private final String resourceUri;
    private final List<String> scopes;
    private final Set<String> allowedAlgorithms;

    // Verification logic
    private final JwtValidator validator;

    // Revocation — null means disabled
    private final RevocationChecker revocationChecker;
    private final boolean failClosed;
    private final InboundDPoPOptions inboundDPoP;

    // -----------------------------------------------------------------------
    // Package-private constructor — created by AuthplaneClient.resource()
    // -----------------------------------------------------------------------

    AuthplaneResource(
            AuthplaneClient client,
            String resourceUri,
            List<String> scopes,
            ResourceOptions options) {
        this.client = client;
        // RFC 8707 §2 — the resource identifier is opaque; validated for structure, never
        // rewritten (it is compared verbatim against aud and advertised verbatim in PRM).
        this.resourceUri = Identifiers.requireValidIdentifier(resourceUri, "resourceUri");
        this.scopes = List.copyOf(scopes);
        this.allowedAlgorithms = Set.copyOf(options.allowedAlgorithms());

        // Resolve revocation checker: custom > builtin > disabled
        if (options.revocationChecker() != null) {
            this.revocationChecker = options.revocationChecker();
        } else if (options.useBuiltinRevocationChecker()) {
            this.revocationChecker = new IntrospectionChecker(client);
        } else {
            this.revocationChecker = null;
        }
        this.failClosed = options.failClosed();
        this.inboundDPoP = options.inboundDPoP();

        // KeyLookup reads through the client's JWKS cache
        this.validator =
                new JwtValidator(
                        client.issuer(),
                        resourceUri,
                        this.allowedAlgorithms,
                        options.clockSkewSeconds(),
                        (kid, force) -> client.jwksCache.getKeyByKid(kid, force));
    }

    // -----------------------------------------------------------------------
    // Core verification
    // -----------------------------------------------------------------------

    /**
     * Verifies a JWT access token and returns the unified bearer/DPoP result.
     *
     * <p>Performs the full RFC 9068 verification sequence followed by optional revocation checking.
     * This overload does not apply inbound DPoP validation.
     *
     * @param token the raw JWT string (without {@code Bearer } or {@code DPoP } prefix)
     * @return CompletableFuture completing with bearer claims and an empty DPoP proof on success
     * @throws TokenRevokedException if the token has been revoked
     * @throws InvalidClaimsException if headers or required claims fail validation
     * @throws ai.authplane.sdk.core.errors.InvalidSignatureException if signature verification
     *     fails
     * @throws ai.authplane.sdk.core.errors.TokenExpiredException if the token has expired
     * @throws ai.authplane.sdk.core.errors.JwksFetchException if JWKS is unavailable
     */
    public CompletableFuture<VerificationResult> verify(String token) {
        return verify(token, null);
    }

    /**
     * Verifies a JWT access token and optionally applies inbound DPoP validation.
     *
     * <p>Inbound DPoP is enforced according to the resource's configured mode (RFC 9449 §6/§7, RFC
     * 9728 §2). The mode is a function of whether {@link
     * ai.authplane.sdk.core.dpop.InboundDPoPOptions} is configured and its {@code required} flag:
     *
     * <table>
     *   <caption>DPoP enforcement modes</caption>
     *   <tr><th>Mode</th><th>Configuration</th><th>Bearer-only token</th>
     *       <th>DPoP-bound token</th><th>Bearer token + proof</th></tr>
     *   <tr><td>Required</td><td>{@code inboundDPoP} set, {@code required=true}</td>
     *       <td>reject ({@link ai.authplane.sdk.core.dpop.DPoPBindingMismatchException})</td>
     *       <td>validate end-to-end</td><td>reject</td></tr>
     *   <tr><td>Supported</td><td>{@code inboundDPoP} set, {@code required=false}</td>
     *       <td>accept</td><td>validate end-to-end</td>
     *       <td>reject ({@link ai.authplane.sdk.core.dpop.DPoPBindingMismatchException})</td></tr>
     *   <tr><td>Not configured</td><td>{@code inboundDPoP} is {@code null}</td>
     *       <td>accept</td>
     *       <td>reject ({@link ai.authplane.sdk.core.dpop.DPoPNotSupportedException})</td>
     *       <td>reject ({@link ai.authplane.sdk.core.dpop.DPoPNotSupportedException})</td></tr>
     * </table>
     *
     * @param token the raw JWT string
     * @param context HTTP request context used for DPoP proof validation; nullable
     * @return CompletableFuture completing with verified claims and, when present and accepted, the
     *     validated DPoP proof
     */
    public CompletableFuture<VerificationResult> verify(
            String token, VerificationRequestContext context) {
        return CompletableFuture.supplyAsync(
                () -> {
                    try {
                        VerifiedClaims claims = validator.verify(token);
                        VerifiedDPoPProof proof = validateDpop(token, claims, context);
                        checkRevocation(token, claims);
                        return proof != null
                                ? VerificationResult.dpop(claims, proof)
                                : VerificationResult.bearer(claims);
                    } catch (TokenRevokedException e) {
                        LOG.warning(() -> "Token revoked: " + e.getMessage());
                        throw new CompletionException(e);
                    } catch (AuthplaneException e) {
                        throw new CompletionException(e);
                    } catch (Exception e) {
                        throw new CompletionException(
                                new InvalidClaimsException(
                                        "Token verification failed: " + e.getMessage(), e));
                    }
                },
                client.executor);
    }

    /**
     * Enforces inbound DPoP according to the resource's configured mode (RFC 9449 §6/§7, RFC 9728
     * §2).
     *
     * <ul>
     *   <li><b>Not configured</b> ({@code inboundDPoP == null}): any DPoP signal — a bound token or
     *       a proof — is rejected with {@link DPoPNotSupportedException}; plain bearer tokens pass.
     *   <li><b>Required</b> ({@code required == true}): bearer-only tokens are rejected with {@link
     *       DPoPBindingMismatchException}; DPoP-bound tokens are validated end-to-end.
     *   <li><b>Supported</b> ({@code required == false}): bearer-only tokens pass; a proof
     *       presented with a bearer-only token is rejected as malformed; DPoP-bound tokens are
     *       validated.
     * </ul>
     */
    private VerifiedDPoPProof validateDpop(
            String token, VerifiedClaims claims, VerificationRequestContext context) {
        boolean tokenHasCnf = claims.hasCnf();
        String proof = context == null ? null : context.dpopProof();
        boolean proofPresent = proof != null && !proof.isBlank();

        // Mode 3 — resource has not opted into DPoP. Reject any DPoP signal up front rather than
        // silently drop sender-binding or apply defaults never advertised in PRM (RFC 9449 §6).
        if (inboundDPoP == null) {
            if (tokenHasCnf || proofPresent) {
                throw new DPoPNotSupportedException(
                        "Resource is not configured for DPoP; configure inbound DPoP options"
                                + " (ResourceOptions.inboundDPoP) to enable DPoP validation");
            }
            return null;
        }

        // Modes 1 & 2 — resource supports DPoP (and may require it).
        if (!tokenHasCnf) {
            if (inboundDPoP.required()) {
                throw new DPoPBindingMismatchException(
                        proofPresent
                                ? "Resource requires DPoP-bound access tokens but the presented"
                                        + " token has no 'cnf.jkt' (a DPoP proof was attached, but"
                                        + " the proof cannot bind to a bearer-only token)"
                                : "Resource requires DPoP-bound access tokens but the presented"
                                        + " token has no 'cnf.jkt'");
            }
            if (proofPresent) {
                // A proof attached to a bearer-only token is structurally malformed: its 'ath'
                // claim has no DPoP-bound token to bind to (RFC 9449 §7).
                throw new DPoPBindingMismatchException(
                        "DPoP proof presented but the access token is not DPoP-bound ('cnf.jkt'"
                                + " missing); the proof has nothing to bind to");
            }
            return null;
        }

        // Token carries 'cnf' — it must contain a 'jkt' thumbprint (RFC 9449 §6).
        if (!claims.isDpopBound()) {
            throw new InvalidClaimsException(
                    "Access token has 'cnf' claim but missing 'cnf.jkt' — "
                            + "cannot verify DPoP binding");
        }

        if (context == null) {
            throw new DPoPProofMissingException(
                    "Token is DPoP-bound (cnf.jkt present) but no verification context was"
                            + " provided");
        }
        if (!proofPresent) {
            throw new DPoPProofMissingException("DPoP proof is required for DPoP-bound tokens");
        }

        return DPoPProofVerifier.verify(
                proof,
                context.method(),
                context.url(),
                token,
                claims.dpopThumbprint(),
                inboundDPoP);
    }

    /**
     * Runs the configured revocation check after successful cryptographic validation.
     *
     * <p>When {@code failClosed} is {@code false} (default), exceptions from the checker are logged
     * and the token is accepted. When {@code true}, exceptions cause the token to be rejected.
     *
     * @param token raw JWT string (needed for RFC 7662 POST body)
     * @param claims verified claims (provides jti)
     * @throws TokenRevokedException if the token is determined to be revoked
     */
    private void checkRevocation(String token, VerifiedClaims claims) {
        if (revocationChecker == null) {
            return;
        }
        try {
            if (revocationChecker.isRevoked(token, claims.jti())) {
                throw new TokenRevokedException(
                        "Token with jti='" + claims.jti() + "' rejected by revocation checker");
            }
        } catch (TokenRevokedException e) {
            throw e;
        } catch (Exception e) {
            if (failClosed) {
                throw new TokenRevokedException(
                        "Token with jti='"
                                + claims.jti()
                                + "' rejected: revocation check failed: "
                                + e.getMessage());
            }
            LOG.warning(
                    "Revocation check failed (fail-open) for jti='"
                            + claims.jti()
                            + "': "
                            + e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // PRM (Protected Resource Metadata — RFC 9728)
    // -----------------------------------------------------------------------

    /**
     * Returns the RFC 9728 Protected Resource Metadata document as a Map. Serve this at {@code
     * /.well-known/oauth-protected-resource} (or the path-qualified variant for resources with
     * paths).
     *
     * <p>Response shape: { "resource": "https://api.example.com", "authorization_servers":
     * ["https://auth.example.com"], "bearer_methods_supported": ["header"], "scopes_supported":
     * ["read:data", "write:data"] }
     */
    public Map<String, Object> prmResponse() {
        Map<String, Object> prm = new LinkedHashMap<>();
        prm.put("resource", resourceUri);
        prm.put("authorization_servers", List.of(client.issuer()));
        prm.put("bearer_methods_supported", List.of("header"));
        prm.put("scopes_supported", scopes);
        if (inboundDPoP != null) {
            prm.put(
                    "dpop_signing_alg_values_supported",
                    List.copyOf(inboundDPoP.allowedProofAlgorithms()));
            prm.put("dpop_bound_access_tokens_required", inboundDPoP.required());
        }
        return Collections.unmodifiableMap(prm);
    }

    /**
     * Returns the URL path at which this resource's RFC 9728 Protected Resource Metadata document
     * should be served (e.g. {@code /.well-known/oauth-protected-resource}, or a path-qualified
     * variant when the resource URI has a path).
     */
    public String prmPath() {
        return ProtectedResourceMetadata.wellKnownPath(URI.create(resourceUri));
    }

    /**
     * Returns the absolute URL of this resource's RFC 9728 Protected Resource Metadata document,
     * suitable for the {@code resource_metadata} parameter of a {@code WWW-Authenticate} challenge.
     *
     * <p><strong>Not header-safe.</strong> The value is derived from the operator-configured
     * resource URI and is returned verbatim — it is NOT escaped for use in an HTTP header. When
     * interpolating it into a header value, pass it through {@link
     * ai.authplane.sdk.core.errors.WwwAuthenticate#escapeQuotedString(String)} (as {@code
     * FailureResponse}/{@code WwwAuthenticate} already do) so a stray CR/LF or quote in a
     * misconfigured {@code authplane.resource} cannot cause header injection.
     */
    public String prmUrl() {
        return ProtectedResourceMetadata.wellKnownUrl(resourceUri);
    }

    /**
     * Returns the path component of this resource's URI (e.g. {@code /mcp} for {@code
     * https://mcp.example.com/mcp}), i.e. the endpoint path this resource is served at. Empty
     * string when the resource URI has no path.
     */
    public String path() {
        String path = URI.create(resourceUri).getPath();
        return path == null ? "" : path;
    }

    /**
     * Re-anchors an incoming request URL to this resource's canonical origin, producing the
     * absolute URL used as the DPoP {@code htu} for the request. The scheme and authority (host +
     * port) are taken from the configured resource URI (the JWT {@code aud}); only the request's
     * path is kept.
     *
     * <p>This keeps {@code htu} verification independent of the deployment's internal
     * address/hostname and of reverse-proxy {@code X-Forwarded-*} headers (which we deliberately do
     * not trust for a security check), while still binding to the actual request target — so
     * requests to sub-paths of the resource (e.g. {@code /mcp/tool} under resource {@code
     * https://host/mcp}) bind to the correct URL. Callers pass the full request URL (not just the
     * path) so any future change to this mapping stays contained here.
     *
     * @param requestUrl the incoming request URL (e.g. servlet {@code getRequestURL()} / {@code
     *     ServerRequest.uri()}); query and fragment are ignored
     * @return {@code scheme://authority} (from the resource) + the request's path
     */
    public String normalizeRequestUrl(String requestUrl) {
        URI base = URI.create(resourceUri);
        String path = URI.create(requestUrl).getRawPath();
        return base.getScheme() + "://" + base.getAuthority() + (path == null ? "" : path);
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /** The resource URI this instance is scoped to. */
    public String resourceUri() {
        return resourceUri;
    }

    /** The scopes this resource is configured with. */
    public List<String> scopes() {
        return scopes;
    }

    /** The parent client that owns infrastructure and token operations. */
    public AuthplaneClient client() {
        return client;
    }
}
