package ai.authplane.sdk.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.VerificationResult;
import ai.authplane.sdk.core.VerifiedClaims;
import ai.authplane.sdk.core.dpop.DPoPNotSupportedException;
import ai.authplane.sdk.core.dpop.DPoPProofMissingException;
import ai.authplane.sdk.core.dpop.VerificationRequestContext;
import ai.authplane.sdk.core.errors.AuthplaneException;
import ai.authplane.sdk.core.errors.InsufficientScopeException;
import ai.authplane.sdk.core.errors.InvalidClaimsException;
import ai.authplane.sdk.core.errors.TokenExpiredException;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.transport.ServerTransportSecurityException;

@ExtendWith(MockitoExtension.class)
class AuthplaneMcpAdapterTest {

    @Mock AuthplaneClient client;

    @Mock AuthplaneResource verifier;

    @Mock HttpServletRequest request;

    AuthplaneMcpAdapter adapter;

    /** A minimal valid VerifiedClaims instance for use in tests. */
    VerifiedClaims validClaims;

    @BeforeEach
    void setUp() {
        adapter = new AuthplaneMcpAdapter(client, verifier);
        validClaims =
                new VerifiedClaims(
                        "user-123",
                        "client-abc",
                        List.of("tools/query"),
                        "https://auth.example.com",
                        List.of("https://mcp.example.com"),
                        System.currentTimeMillis() / 1000 + 3600,
                        System.currentTimeMillis() / 1000,
                        "jti-001",
                        "key-1",
                        Map.of(),
                        "",
                        List.of(),
                        0L);
    }

    // -----------------------------------------------------------------------
    // validateHeaders + extract — happy path
    // -----------------------------------------------------------------------

    @Test
    void validToken_claimsAvailableViaContext() throws Exception {
        when(verifier.verify("valid-token"))
                .thenReturn(
                        CompletableFuture.completedFuture(VerificationResult.bearer(validClaims)));
        when(verifier.verify(eq("valid-token"), any(VerificationRequestContext.class)))
                .thenReturn(
                        CompletableFuture.completedFuture(VerificationResult.bearer(validClaims)));
        stubRequestForExtract("Bearer valid-token");

        adapter.validateHeaders(Map.of("authorization", List.of("Bearer valid-token")));
        McpTransportContext ctx = adapter.extract(request);

        assertThat(AuthplaneMcpAdapter.getClaims(ctx)).isSameAs(validClaims);
    }

    @Test
    void validToken_caseInsensitiveAuthorizationHeader() throws Exception {
        when(verifier.verify("valid-token"))
                .thenReturn(
                        CompletableFuture.completedFuture(VerificationResult.bearer(validClaims)));
        when(verifier.verify(eq("valid-token"), any(VerificationRequestContext.class)))
                .thenReturn(
                        CompletableFuture.completedFuture(VerificationResult.bearer(validClaims)));
        stubRequestForExtract("Bearer valid-token");

        adapter.validateHeaders(Map.of("Authorization", List.of("Bearer valid-token")));
        McpTransportContext ctx = adapter.extract(request);

        assertThat(AuthplaneMcpAdapter.getClaims(ctx)).isSameAs(validClaims);
    }

    @Test
    void validToken_multipleHeadersFirstNonBlankUsed() throws Exception {
        when(verifier.verify("first-token"))
                .thenReturn(
                        CompletableFuture.completedFuture(VerificationResult.bearer(validClaims)));
        when(verifier.verify(eq("first-token"), any(VerificationRequestContext.class)))
                .thenReturn(
                        CompletableFuture.completedFuture(VerificationResult.bearer(validClaims)));
        stubRequestForExtract("Bearer first-token");

        adapter.validateHeaders(
                Map.of("authorization", List.of("Bearer first-token", "Bearer second-token")));
        McpTransportContext ctx = adapter.extract(request);

        assertThat(AuthplaneMcpAdapter.getClaims(ctx)).isSameAs(validClaims);
    }

    // -----------------------------------------------------------------------
    // validateHeaders — rejection cases
    // -----------------------------------------------------------------------

    @Test
    void missingAuthorizationHeader_throws401() {
        assertThatThrownBy(() -> adapter.validateHeaders(Map.of()))
                .isInstanceOf(ServerTransportSecurityException.class)
                .satisfies(
                        e ->
                                assertThat(((ServerTransportSecurityException) e).getStatusCode())
                                        .isEqualTo(401));
    }

    @Test
    void missingAuthorizationHeader_blankValue_throws401() {
        assertThatThrownBy(
                        () -> adapter.validateHeaders(Map.of("authorization", List.of("", "  "))))
                .isInstanceOf(ServerTransportSecurityException.class)
                .satisfies(
                        e ->
                                assertThat(((ServerTransportSecurityException) e).getStatusCode())
                                        .isEqualTo(401));
    }

    @Test
    void headerWithoutBearerPrefix_throws401() {
        assertThatThrownBy(
                        () ->
                                adapter.validateHeaders(
                                        Map.of("authorization", List.of("Basic dXNlcjpwYXNz"))))
                .isInstanceOf(ServerTransportSecurityException.class)
                .satisfies(
                        e ->
                                assertThat(((ServerTransportSecurityException) e).getStatusCode())
                                        .isEqualTo(401));
    }

    @Test
    void expiredToken_throws401() {
        when(verifier.verify("expired-token"))
                .thenReturn(
                        CompletableFuture.failedFuture(
                                new CompletionException(
                                        new TokenExpiredException("Token has expired"))));

        assertThatThrownBy(
                        () ->
                                adapter.validateHeaders(
                                        Map.of("authorization", List.of("Bearer expired-token"))))
                .isInstanceOf(ServerTransportSecurityException.class)
                .satisfies(
                        e ->
                                assertThat(((ServerTransportSecurityException) e).getStatusCode())
                                        .isEqualTo(401));
    }

    @Test
    void wrongIssuerToken_throws401() {
        when(verifier.verify("bad-issuer-token"))
                .thenReturn(
                        CompletableFuture.failedFuture(
                                new CompletionException(
                                        new InvalidClaimsException("Issuer mismatch"))));

        assertThatThrownBy(
                        () ->
                                adapter.validateHeaders(
                                        Map.of(
                                                "authorization",
                                                List.of("Bearer bad-issuer-token"))))
                .isInstanceOf(ServerTransportSecurityException.class)
                .satisfies(
                        e ->
                                assertThat(((ServerTransportSecurityException) e).getStatusCode())
                                        .isEqualTo(401));
    }

    @Test
    void directAuthplaneException_throws401() {
        when(verifier.verify("direct-fail")).thenThrow(new AuthplaneException("direct failure"));

        assertThatThrownBy(
                        () ->
                                adapter.validateHeaders(
                                        Map.of("authorization", List.of("Bearer direct-fail"))))
                .isInstanceOf(ServerTransportSecurityException.class)
                .satisfies(
                        e ->
                                assertThat(((ServerTransportSecurityException) e).getStatusCode())
                                        .isEqualTo(401));
    }

    @Test
    void unknownException_throws401() {
        when(verifier.verify("unknown-fail"))
                .thenReturn(
                        CompletableFuture.failedFuture(
                                new CompletionException(new RuntimeException("unexpected"))));

        assertThatThrownBy(
                        () ->
                                adapter.validateHeaders(
                                        Map.of("authorization", List.of("Bearer unknown-fail"))))
                .isInstanceOf(ServerTransportSecurityException.class)
                .satisfies(
                        e -> {
                            ServerTransportSecurityException se =
                                    (ServerTransportSecurityException) e;
                            assertThat(se.getStatusCode()).isEqualTo(401);
                            assertThat(se.getMessage()).isEqualTo("Token verification failed");
                        });
    }

    @Test
    void completionExceptionWithNullCause_throws401() {
        when(verifier.verify("null-cause"))
                .thenReturn(CompletableFuture.failedFuture(new CompletionException(null)));

        assertThatThrownBy(
                        () ->
                                adapter.validateHeaders(
                                        Map.of("authorization", List.of("Bearer null-cause"))))
                .isInstanceOf(ServerTransportSecurityException.class)
                .satisfies(
                        e ->
                                assertThat(((ServerTransportSecurityException) e).getStatusCode())
                                        .isEqualTo(401));
    }

    @Test
    void insufficientScope_throws403() {
        when(verifier.verify("limited-token"))
                .thenReturn(
                        CompletableFuture.failedFuture(
                                new CompletionException(
                                        new InsufficientScopeException(
                                                "tools/write", List.of("tools/read")))));

        assertThatThrownBy(
                        () ->
                                adapter.validateHeaders(
                                        Map.of("authorization", List.of("Bearer limited-token"))))
                .isInstanceOf(ServerTransportSecurityException.class)
                .satisfies(
                        e ->
                                assertThat(((ServerTransportSecurityException) e).getStatusCode())
                                        .isEqualTo(403));
    }

    // -----------------------------------------------------------------------
    // extract — independent re-verification
    // -----------------------------------------------------------------------

    @Test
    void extract_isIdempotent() throws Exception {
        when(verifier.verify("valid-token"))
                .thenReturn(
                        CompletableFuture.completedFuture(VerificationResult.bearer(validClaims)));
        when(verifier.verify(eq("valid-token"), any(VerificationRequestContext.class)))
                .thenReturn(
                        CompletableFuture.completedFuture(VerificationResult.bearer(validClaims)));
        stubRequestForExtract("Bearer valid-token");

        adapter.validateHeaders(Map.of("authorization", List.of("Bearer valid-token")));
        McpTransportContext firstCtx = adapter.extract(request);
        McpTransportContext secondCtx = adapter.extract(request);

        assertThat(AuthplaneMcpAdapter.getClaims(firstCtx)).isSameAs(validClaims);
        assertThat(AuthplaneMcpAdapter.getClaims(secondCtx)).isSameAs(validClaims);
    }

    @Test
    void invalidToken_extractThrowsAuthplaneException() {
        when(verifier.verify("bad-token"))
                .thenReturn(
                        CompletableFuture.failedFuture(
                                new CompletionException(new InvalidClaimsException("bad"))));
        when(verifier.verify(eq("bad-token"), any(VerificationRequestContext.class)))
                .thenReturn(
                        CompletableFuture.failedFuture(
                                new CompletionException(new InvalidClaimsException("bad"))));
        stubRequestForExtract("Bearer bad-token");

        assertThatThrownBy(
                        () ->
                                adapter.validateHeaders(
                                        Map.of("authorization", List.of("Bearer bad-token"))))
                .isInstanceOf(ServerTransportSecurityException.class);

        assertThatThrownBy(() -> adapter.extract(request))
                .isInstanceOf(InvalidClaimsException.class);
    }

    @Test
    void extractWithoutAuthHeader_throwsAuthplaneException() {
        assertThatThrownBy(() -> adapter.extract(request))
                .isInstanceOf(AuthplaneException.class)
                .hasMessageContaining("Authorization header is required");
    }

    @Test
    void extractWithNonBearerHeader_throwsAuthplaneException() {
        when(request.getHeader("Authorization")).thenReturn("Basic dXNlcjpwYXNz");

        assertThatThrownBy(() -> adapter.extract(request))
                .isInstanceOf(AuthplaneException.class)
                .hasMessageContaining("Authorization header is required");
    }

    @Test
    void extract_checkedExceptionWrappedInRuntimeException() {
        when(verifier.verify(eq("check-token"), any(VerificationRequestContext.class)))
                .thenReturn(
                        CompletableFuture.failedFuture(
                                new CompletionException(new Exception("checked"))));
        stubRequestForExtract("Bearer check-token");

        assertThatThrownBy(() -> adapter.extract(request))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Unexpected exception");
    }

    // -----------------------------------------------------------------------
    // getClaims — edge cases
    // -----------------------------------------------------------------------

    @Test
    void getClaims_nullContext_returnsNull() {
        assertThat(AuthplaneMcpAdapter.getClaims(null)).isNull();
    }

    @Test
    void getClaims_emptyContext_returnsNull() {
        assertThat(AuthplaneMcpAdapter.getClaims(McpTransportContext.EMPTY)).isNull();
    }

    @Test
    void getClaims_wrongTypeAtKey_returnsNull() {
        // Hits the `value instanceof VerifiedClaims ? vc : null` false branch.
        McpTransportContext ctx =
                McpTransportContext.create(Map.of(AuthplaneMcpAdapter.CLAIMS_KEY, "not-claims"));
        assertThat(AuthplaneMcpAdapter.getClaims(ctx)).isNull();
    }

    // -----------------------------------------------------------------------
    // validateHeaders / extract — RFC 9449 §4.3 multiple-DPoP rejection
    // -----------------------------------------------------------------------

    @Test
    void validateHeaders_multipleDpopHeaders_throws401() {
        // RFC 9449 §4.3 #1 is rejected at the validator gate before the verifier runs, so
        // callers that wire only the ServerTransportSecurityValidator (not the extractor) still
        // get the check.
        assertThatThrownBy(
                        () ->
                                adapter.validateHeaders(
                                        Map.of(
                                                "authorization",
                                                List.of("Bearer t"),
                                                "DPoP",
                                                List.of("proof-1", "proof-2"))))
                .isInstanceOf(ServerTransportSecurityException.class)
                .satisfies(
                        e -> {
                            ServerTransportSecurityException se =
                                    (ServerTransportSecurityException) e;
                            assertThat(se.getStatusCode()).isEqualTo(401);
                            assertThat(se.getMessage()).contains("Multiple DPoP");
                        });
    }

    @Test
    void extract_multipleDpopHeaders_throwsMultipleDpopProofsException() throws Exception {
        // The same check is enforced at VerificationRequestContext construction inside extract,
        // so the typed exception surfaces directly (no verifier call expected).
        stubRequestForExtract("Bearer token");
        when(request.getHeaders("DPoP"))
                .thenReturn(
                        java.util.Collections.enumeration(java.util.List.of("proof-1", "proof-2")));

        assertThatThrownBy(() -> adapter.extract(request))
                .isInstanceOf(ai.authplane.sdk.core.dpop.MultipleDpopProofsException.class)
                .hasMessageContaining("Multiple DPoP");
    }

    @Test
    void extract_dpopHeaderWithBlankSecondValue_singleProofPath() throws Exception {
        // Two values where the second is blank: VerificationRequestContext normalization filters
        // blanks, so this should NOT trip the multi-DPoP guard.
        when(verifier.verify(eq("ok-token"), any(VerificationRequestContext.class)))
                .thenReturn(
                        CompletableFuture.completedFuture(VerificationResult.bearer(validClaims)));
        stubRequestForExtract("Bearer ok-token");
        when(request.getHeaders("DPoP"))
                .thenReturn(java.util.Collections.enumeration(java.util.List.of("proof", "   ")));

        McpTransportContext ctx = adapter.extract(request);
        assertThat(AuthplaneMcpAdapter.getClaims(ctx)).isSameAs(validClaims);
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    @Test
    void client_returnsClient() {
        assertThat(adapter.client()).isSameAs(client);
    }

    @Test
    void verifier_returnsVerifier() {
        assertThat(adapter.resource()).isSameAs(verifier);
    }

    // -----------------------------------------------------------------------
    // validateHeaders — additional edge cases
    // -----------------------------------------------------------------------

    @Test
    void validateHeaders_nullValuesInList_throws401() {
        assertThatThrownBy(() -> adapter.validateHeaders(Map.of("authorization", List.of())))
                .isInstanceOf(ServerTransportSecurityException.class)
                .satisfies(
                        e ->
                                assertThat(((ServerTransportSecurityException) e).getStatusCode())
                                        .isEqualTo(401));
    }

    @Test
    void extract_completionExceptionWithNullCause_rethrowsCompletionException() {
        // CompletionException is itself a RuntimeException; unwrapCompletion bails on a null
        // cause and the surviving CompletionException is rethrown as-is by extract() (the
        // `cause instanceof RuntimeException re` branch). No 401 mapping happens here because
        // extract() cannot return structured HTTP errors — only validateHeaders can.
        when(verifier.verify(eq("null-cause"), any(VerificationRequestContext.class)))
                .thenReturn(CompletableFuture.failedFuture(new CompletionException(null)));
        stubRequestForExtract("Bearer null-cause");

        assertThatThrownBy(() -> adapter.extract(request)).isInstanceOf(CompletionException.class);
    }

    // -----------------------------------------------------------------------
    // validateHeaders / extract — DPoP-bound token handling
    //
    // validateHeaders has no HttpServletRequest, so it cannot construct a
    // VerificationRequestContext. For DPoP-bound tokens (cnf.jkt present), the bearer-only
    // verify path throws DPoPProofMissingException by design; the adapter must swallow that
    // specific exception so the request reaches extract(), which performs the full DPoP
    // verification with context. Every other failure must still surface as 401.
    // -----------------------------------------------------------------------

    @Test
    void validateHeaders_dpopBoundToken_swallowsDPoPProofMissing_allowsThroughToExtract()
            throws ServerTransportSecurityException {
        when(verifier.verify("dpop-bound-token"))
                .thenReturn(
                        CompletableFuture.failedFuture(
                                new CompletionException(
                                        new DPoPProofMissingException(
                                                "Token is DPoP-bound (cnf.jkt present) but no"
                                                        + " verification context was provided"))));

        // No exception: the swallow lets the request flow through to extract().
        adapter.validateHeaders(Map.of("authorization", List.of("Bearer dpop-bound-token")));
    }

    @Test
    void validateHeaders_dpopBoundToken_directDPoPProofMissingException_alsoSwallowed()
            throws ServerTransportSecurityException {
        // Same swallow when the exception is thrown synchronously rather than wrapped in a
        // CompletableFuture failure (defensive: both code paths exist depending on how
        // AuthplaneResource composes its async pipeline).
        when(verifier.verify("dpop-bound-direct"))
                .thenThrow(
                        new DPoPProofMissingException(
                                "Token is DPoP-bound (cnf.jkt present) but no verification context"
                                        + " was provided"));

        adapter.validateHeaders(Map.of("authorization", List.of("Bearer dpop-bound-direct")));
    }

    @Test
    void validateHeaders_dpopNotSupportedException_stillRejects() {
        // DPoPNotSupportedException means the resource is not configured for DPoP at all. That
        // is a 401 condition, distinct from the "DPoP-bound, no context" deferral path. Must NOT
        // be swallowed.
        when(verifier.verify("dpop-no-support"))
                .thenReturn(
                        CompletableFuture.failedFuture(
                                new CompletionException(
                                        new DPoPNotSupportedException(
                                                "Resource is not configured for DPoP"))));

        assertThatThrownBy(
                        () ->
                                adapter.validateHeaders(
                                        Map.of("authorization", List.of("Bearer dpop-no-support"))))
                .isInstanceOf(ServerTransportSecurityException.class)
                .satisfies(
                        e ->
                                assertThat(((ServerTransportSecurityException) e).getStatusCode())
                                        .isEqualTo(401));
    }

    @Test
    void validateHeaders_nestedCompletionException_unwrapsAllLayers()
            throws ServerTransportSecurityException {
        // Defensive: if any future composition in AuthplaneResource re-wraps a failure in a
        // second CompletionException, the unwrap loop must still surface the real cause so the
        // DPoPProofMissingException swallow keeps working.
        CompletionException inner =
                new CompletionException(
                        new DPoPProofMissingException(
                                "Token is DPoP-bound (cnf.jkt present) but no verification context"
                                        + " was provided"));
        CompletionException outer = new CompletionException(inner);

        when(verifier.verify("nested-dpop")).thenReturn(CompletableFuture.failedFuture(outer));

        // No exception: deep unwrap finds DPoPProofMissingException and swallows it.
        adapter.validateHeaders(Map.of("authorization", List.of("Bearer nested-dpop")));
    }

    @Test
    void extract_dpopBoundToken_validatesWithContext_returnsClaims() throws Exception {
        // End-to-end flow that today's mock-only tests don't exercise:
        // validateHeaders swallows DPoPProofMissing → extract runs verify with full context →
        // claims surface in the McpTransportContext.
        when(verifier.verify("dpop-bound"))
                .thenReturn(
                        CompletableFuture.failedFuture(
                                new CompletionException(
                                        new DPoPProofMissingException(
                                                "Token is DPoP-bound (cnf.jkt present) but no"
                                                        + " verification context was provided"))));
        when(verifier.verify(eq("dpop-bound"), any(VerificationRequestContext.class)))
                .thenReturn(
                        CompletableFuture.completedFuture(VerificationResult.bearer(validClaims)));
        stubRequestForExtract("Bearer dpop-bound");

        adapter.validateHeaders(Map.of("authorization", List.of("Bearer dpop-bound")));
        McpTransportContext ctx = adapter.extract(request);

        assertThat(AuthplaneMcpAdapter.getClaims(ctx)).isSameAs(validClaims);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /** Stubs the HttpServletRequest mock with the minimum fields needed by extract(). */
    private void stubRequestForExtract(String authorizationHeader) {
        when(request.getHeader("Authorization")).thenReturn(authorizationHeader);
        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURL()).thenReturn(new StringBuffer("https://mcp.example.com/mcp"));
        // htu is built by resource.normalizeRequestUrl(requestUrl) (re-anchors host to the
        // resource, keeps the path); the resource is mocked here, so stub the result.
        when(verifier.normalizeRequestUrl(anyString())).thenReturn("https://mcp.example.com/mcp");
    }
}
