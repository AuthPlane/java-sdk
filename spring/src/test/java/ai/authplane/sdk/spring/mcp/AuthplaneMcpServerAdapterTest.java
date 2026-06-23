package ai.authplane.sdk.spring.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.servlet.function.ServerRequest;

import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.RevocationChecker;
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
class AuthplaneMcpServerAdapterTest {

    @Mock AuthplaneResource verifier;

    @Mock ServerRequest request;

    @Mock ServerRequest.Headers headers;

    AuthplaneMcpServerAdapter adapter;

    /** A minimal valid VerifiedClaims instance for use in tests. */
    VerifiedClaims validClaims;

    @BeforeEach
    void setUp() {
        adapter = new AuthplaneMcpServerAdapter(verifier);
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

        assertThat(AuthplaneMcpServerAdapter.getClaims(ctx)).isSameAs(validClaims);
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

        assertThat(AuthplaneMcpServerAdapter.getClaims(ctx)).isSameAs(validClaims);
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

        assertThat(AuthplaneMcpServerAdapter.getClaims(ctx)).isSameAs(validClaims);
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

        // Both extractions return valid claims — no shared state to deplete
        assertThat(AuthplaneMcpServerAdapter.getClaims(firstCtx)).isSameAs(validClaims);
        assertThat(AuthplaneMcpServerAdapter.getClaims(secondCtx)).isSameAs(validClaims);
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

        // extract() independently re-verifies and also fails
        assertThatThrownBy(() -> adapter.extract(request))
                .isInstanceOf(InvalidClaimsException.class);
    }

    @Test
    void extractWithoutAuthHeader_throwsAuthplaneException() {
        when(request.headers()).thenReturn(headers);
        when(headers.firstHeader("Authorization")).thenReturn(null);

        assertThatThrownBy(() -> adapter.extract(request))
                .isInstanceOf(AuthplaneException.class)
                .hasMessageContaining("Authorization header is required");
    }

    // -----------------------------------------------------------------------
    // getClaims — edge cases
    // -----------------------------------------------------------------------

    @Test
    void getClaims_nullContext_returnsNull() {
        assertThat(AuthplaneMcpServerAdapter.getClaims(null)).isNull();
    }

    @Test
    void getClaims_emptyContext_returnsNull() {
        assertThat(AuthplaneMcpServerAdapter.getClaims(McpTransportContext.EMPTY)).isNull();
    }

    @Test
    void getClaims_wrongTypeAtKey_returnsNull() {
        // Exercises the `value instanceof VerifiedClaims ? vc : null` false branch.
        McpTransportContext ctx =
                McpTransportContext.create(
                        Map.of(AuthplaneMcpServerAdapter.CLAIMS_KEY, "not-claims"));
        assertThat(AuthplaneMcpServerAdapter.getClaims(ctx)).isNull();
    }

    // -----------------------------------------------------------------------
    // validateHeaders / extract — RFC 9449 §4.3 multiple-DPoP rejection
    // -----------------------------------------------------------------------

    @Test
    void validateHeaders_multipleDpopHeaders_throws401() {
        // RFC 9449 §4.3 #1 is rejected at the validator gate before the verifier runs, so
        // callers wiring only the ServerTransportSecurityValidator still get the check.
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
    void extract_multipleDpopHeaders_throwsMultipleDpopProofsException() {
        when(request.headers()).thenReturn(headers);
        when(headers.firstHeader("Authorization")).thenReturn("Bearer token");
        when(headers.header("DPoP")).thenReturn(List.of("proof-1", "proof-2"));
        when(request.method()).thenReturn(org.springframework.http.HttpMethod.GET);
        when(request.uri()).thenReturn(URI.create("https://mcp.example.com/mcp"));
        when(verifier.normalizeRequestUrl(anyString())).thenReturn("https://mcp.example.com/mcp");

        assertThatThrownBy(() -> adapter.extract(request))
                .isInstanceOf(ai.authplane.sdk.core.dpop.MultipleDpopProofsException.class)
                .hasMessageContaining("Multiple DPoP");
    }

    @Test
    void validateHeaders_blankAuthorizationHeader_throws401() {
        assertThatThrownBy(
                        () -> adapter.validateHeaders(Map.of("authorization", List.of("", "  "))))
                .isInstanceOf(ServerTransportSecurityException.class);
    }

    @Test
    void validateHeaders_completionExceptionNullCause_throws401() {
        when(verifier.verify("null-cause"))
                .thenReturn(CompletableFuture.failedFuture(new CompletionException(null)));

        assertThatThrownBy(
                        () ->
                                adapter.validateHeaders(
                                        Map.of("authorization", List.of("Bearer null-cause"))))
                .isInstanceOf(ServerTransportSecurityException.class);
    }

    @Test
    void validateHeaders_directAuthplaneException_throws401() {
        when(verifier.verify("direct-fail")).thenThrow(new AuthplaneException("direct"));

        assertThatThrownBy(
                        () ->
                                adapter.validateHeaders(
                                        Map.of("authorization", List.of("Bearer direct-fail"))))
                .isInstanceOf(ServerTransportSecurityException.class);
    }

    @Test
    void validateHeaders_unknownExceptionType_throws401() {
        when(verifier.verify("unknown"))
                .thenReturn(
                        CompletableFuture.failedFuture(
                                new CompletionException(new RuntimeException("???"))));

        assertThatThrownBy(
                        () ->
                                adapter.validateHeaders(
                                        Map.of("authorization", List.of("Bearer unknown"))))
                .isInstanceOf(ServerTransportSecurityException.class)
                .satisfies(
                        e ->
                                assertThat(((ServerTransportSecurityException) e).getMessage())
                                        .isEqualTo("Token verification failed"));
    }

    @Test
    void validateHeaders_insufficientScope_throws403() {
        when(verifier.verify("limited"))
                .thenReturn(
                        CompletableFuture.failedFuture(
                                new CompletionException(
                                        new InsufficientScopeException(
                                                "tools/write", List.of("tools/read")))));

        assertThatThrownBy(
                        () ->
                                adapter.validateHeaders(
                                        Map.of("authorization", List.of("Bearer limited"))))
                .isInstanceOf(ServerTransportSecurityException.class)
                .satisfies(
                        e ->
                                assertThat(((ServerTransportSecurityException) e).getStatusCode())
                                        .isEqualTo(403));
    }

    @Test
    void extract_checkedExceptionWrappedInRuntime() {
        when(verifier.verify(eq("check"), any(VerificationRequestContext.class)))
                .thenReturn(
                        CompletableFuture.failedFuture(
                                new CompletionException(new Exception("checked"))));
        stubRequestForExtract("Bearer check");

        assertThatThrownBy(() -> adapter.extract(request))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Unexpected exception");
    }

    @Test
    void extract_nonBearerHeader_throwsAuthplaneException() {
        when(request.headers()).thenReturn(headers);
        when(headers.firstHeader("Authorization")).thenReturn("Basic dXNlcjpwYXNz");

        assertThatThrownBy(() -> adapter.extract(request))
                .isInstanceOf(AuthplaneException.class)
                .hasMessageContaining("Authorization header is required");
    }

    // -----------------------------------------------------------------------
    // Builder — new delegation methods
    // -----------------------------------------------------------------------

    @Test
    void builder_authProvider_null_throwsNPE() {
        AuthplaneMcpServerAdapter.Builder builder =
                new AuthplaneMcpServerAdapter.Builder(
                        "https://issuer.example.com",
                        "https://resource.example.com",
                        List.of("read"));
        assertThatThrownBy(() -> builder.authProvider(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void builder_fetchSettings_null_throwsNPE() {
        AuthplaneMcpServerAdapter.Builder builder =
                new AuthplaneMcpServerAdapter.Builder(
                        "https://issuer.example.com",
                        "https://resource.example.com",
                        List.of("read"));
        assertThatThrownBy(() -> builder.fetchSettings(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void builder_useBuiltinRevocationChecker_thenCustomChecker_throwsISE() {
        AuthplaneMcpServerAdapter.Builder builder =
                new AuthplaneMcpServerAdapter.Builder(
                        "https://issuer.example.com",
                        "https://resource.example.com",
                        List.of("read"));
        builder.useBuiltinRevocationChecker();
        assertThatThrownBy(() -> builder.revocationChecker(RevocationChecker.noOp()))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void builder_customChecker_thenUseBuiltinRevocationChecker_throwsISE() {
        AuthplaneMcpServerAdapter.Builder builder =
                new AuthplaneMcpServerAdapter.Builder(
                        "https://issuer.example.com",
                        "https://resource.example.com",
                        List.of("read"));
        builder.revocationChecker(RevocationChecker.noOp());
        assertThatThrownBy(() -> builder.useBuiltinRevocationChecker())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void builder_delegationMethods_returnSelf() {
        AuthplaneMcpServerAdapter.Builder b =
                new AuthplaneMcpServerAdapter.Builder(
                        "https://issuer.example.com",
                        "https://resource.example.com",
                        List.of("read"));
        assertThat(b.allowedAlgorithms(List.of("RS256"))).isSameAs(b);
        assertThat(b.clockSkewSeconds(60)).isSameAs(b);
        assertThat(b.devMode(true)).isSameAs(b);
        assertThat(b.jwksRefreshSeconds(600)).isSameAs(b);
        assertThat(b.metadataRefreshSeconds(7200)).isSameAs(b);
        assertThat(b.revocationChecker(RevocationChecker.noOp())).isSameAs(b);
    }

    // -----------------------------------------------------------------------
    // validateHeaders / extract — DPoP-bound token handling (parity with AuthplaneMcpAdapter)
    //
    // The Spring MCP transport's two-hook contract is identical to the servlet MCP transport's:
    // validateHeaders has no request, extract has the full context. For DPoP-bound tokens the
    // bearer-only verify path throws DPoPProofMissingException by design; the adapter must
    // swallow that specific exception so the request reaches extract(), which performs the full
    // DPoP verification with context. Every other failure must still surface as 401.
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
        // Defensive branch: today AuthplaneResource.verify always wraps in CompletableFuture,
        // but if a future refactor surfaces DPoPProofMissingException synchronously it must
        // also be swallowed.
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
        // is a 401 condition, distinct from the "DPoP-bound, no context" deferral path. Must
        // NOT be swallowed.
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
        // second CompletionException, the unwrap loop must still surface the real cause so
        // the DPoPProofMissingException swallow keeps working.
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
        // End-to-end flow: validateHeaders swallows DPoPProofMissing → extract runs verify
        // with full context → claims surface in the McpTransportContext.
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

        assertThat(AuthplaneMcpServerAdapter.getClaims(ctx)).isSameAs(validClaims);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /** Stubs the ServerRequest mock with the minimum fields needed by extract(). */
    private void stubRequestForExtract(String authorizationHeader) {
        when(request.headers()).thenReturn(headers);
        when(headers.firstHeader("Authorization")).thenReturn(authorizationHeader);
        when(headers.header("DPoP")).thenReturn(List.of());
        when(request.method()).thenReturn(org.springframework.http.HttpMethod.GET);
        when(request.uri()).thenReturn(URI.create("https://mcp.example.com/mcp"));
        when(verifier.normalizeRequestUrl(anyString())).thenReturn("https://mcp.example.com/mcp");
    }
}
