package ai.authplane.sdk.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletionException;
import java.util.function.BiFunction;

import org.junit.jupiter.api.Test;

import ai.authplane.sdk.core.errors.ConsentRequiredException;
import ai.authplane.sdk.core.errors.TokenExchangeException;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.ElicitUrlRequest;

class UrlElicitationSupportTest {

    @Test
    void toUrlElicitationRequiredError_mapsConsentRequired() {
        ConsentRequiredException error =
                new ConsentRequiredException(
                        "User must grant access",
                        "consent_required",
                        "calendar",
                        "missing_user_consent",
                        "https://as.example.com/consent?service=calendar");

        McpError mapped = UrlElicitationSupport.toUrlElicitationRequiredError(error);

        assertThat(mapped.getJsonRpcError().code()).isEqualTo(-32042);
        // The admin-configured consent message is preserved at the top-level JSON-RPC
        // message (parity with the python/ts SDKs), and the human-readable per-elicitation
        // message carries the same text plus service context.
        assertThat(mapped.getJsonRpcError().message()).isEqualTo("User must grant access");

        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) mapped.getJsonRpcError().data();
        assertThat(data).containsKey("elicitations");
        @SuppressWarnings("unchecked")
        List<ElicitUrlRequest> elicitations = (List<ElicitUrlRequest>) data.get("elicitations");
        assertThat(elicitations).hasSize(1);
        assertThat(elicitations.getFirst().mode()).isEqualTo("url");
        assertThat(elicitations.getFirst().url())
                .isEqualTo("https://as.example.com/consent?service=calendar");
        assertThat(elicitations.getFirst().message()).contains("User must grant access");
    }

    @Test
    void toUrlElicitationRequiredError_returnsNullForNonConsentError() {
        TokenExchangeException error = new TokenExchangeException("invalid grant", "invalid_grant");

        assertThat(UrlElicitationSupport.toUrlElicitationRequiredError(error)).isNull();
    }

    @Test
    void toUrlElicitationRequiredError_returnsNullForConsentWithoutUrl() {
        ConsentRequiredException error =
                new ConsentRequiredException(
                        "User interaction required",
                        "interaction_required",
                        "profile",
                        "interaction_required",
                        null);

        assertThat(UrlElicitationSupport.toUrlElicitationRequiredError(error)).isNull();
    }

    @Test
    void wrapToolWithUrlElicitation_passthroughOnSuccess() {
        BiFunction<McpSyncServerExchange, CallToolRequest, CallToolResult> wrapped =
                UrlElicitationSupport.wrapToolWithUrlElicitation(
                        (exchange, request) ->
                                new CallToolResult(List.of(), false, null, Map.of("ok", true)));

        CallToolResult result = wrapped.apply(null, null);
        assertThat(result.isError()).isFalse();
    }

    @Test
    void wrapToolWithUrlElicitation_mapsNestedCompletionException() {
        BiFunction<McpSyncServerExchange, CallToolRequest, CallToolResult> wrapped =
                UrlElicitationSupport.wrapToolWithUrlElicitation(
                        (exchange, request) -> {
                            throw new CompletionException(
                                    new ConsentRequiredException(
                                            "Consent required",
                                            "consent_required",
                                            "calendar",
                                            "missing_user_consent",
                                            "https://as.example.com/consent?service=calendar"));
                        });

        assertThatThrownBy(() -> wrapped.apply(null, null))
                .isInstanceOf(McpError.class)
                .satisfies(
                        error ->
                                assertThat(((McpError) error).getJsonRpcError().code())
                                        .isEqualTo(-32042));
    }

    @Test
    void toUrlElicitationRequiredError_blankConsentUrl_returnsNull() {
        ConsentRequiredException error =
                new ConsentRequiredException(
                        "needs consent", "consent_required", "svc", "detail", "   ");

        assertThat(UrlElicitationSupport.toUrlElicitationRequiredError(error)).isNull();
    }

    @Test
    void toUrlElicitationRequiredError_nullMessage_usesDefault() {
        ConsentRequiredException error =
                new ConsentRequiredException(
                        null, "consent_required", "svc", "detail", "https://x.example/c");

        McpError mapped = UrlElicitationSupport.toUrlElicitationRequiredError(error);

        assertThat(mapped.getJsonRpcError().message()).isEqualTo("Consent is required to proceed");
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) mapped.getJsonRpcError().data();
        @SuppressWarnings("unchecked")
        List<ElicitUrlRequest> elicitations = (List<ElicitUrlRequest>) data.get("elicitations");
        assertThat(elicitations.getFirst().message()).contains("Consent is required to proceed");
    }

    @Test
    void toUrlElicitationRequiredError_blankMessage_usesDefault() {
        ConsentRequiredException error =
                new ConsentRequiredException(
                        "   ", "consent_required", "svc", "detail", "https://x.example/c");

        McpError mapped = UrlElicitationSupport.toUrlElicitationRequiredError(error);

        assertThat(mapped.getJsonRpcError().message()).isEqualTo("Consent is required to proceed");
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) mapped.getJsonRpcError().data();
        @SuppressWarnings("unchecked")
        List<ElicitUrlRequest> elicitations = (List<ElicitUrlRequest>) data.get("elicitations");
        assertThat(elicitations.getFirst().message()).contains("Consent is required to proceed");
    }

    @Test
    void toUrlElicitationRequiredError_interactionRequired_alsoMapped() {
        ConsentRequiredException error =
                new ConsentRequiredException(
                        "Interact!",
                        "interaction_required",
                        "calendar",
                        "needs_step_up",
                        "https://x.example/interaction");

        McpError mapped = UrlElicitationSupport.toUrlElicitationRequiredError(error);

        assertThat(mapped.getJsonRpcError().code()).isEqualTo(-32042);
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) mapped.getJsonRpcError().data();
        @SuppressWarnings("unchecked")
        List<ElicitUrlRequest> elicitations = (List<ElicitUrlRequest>) data.get("elicitations");
        assertThat(elicitations.getFirst().url()).isEqualTo("https://x.example/interaction");
    }

    @Test
    void toUrlElicitationRequiredError_blankServiceIdAndCauseDetail_useFallbacks() {
        // toUrlElicitationRequiredError sets serviceId="unknown_service" and
        // causeDetail=message when the typed getters return blank — this exercises both
        // fallback branches.
        ConsentRequiredException error =
                new ConsentRequiredException(
                        "original message",
                        "consent_required",
                        "   ",
                        "   ",
                        "https://x.example/c");

        McpError mapped = UrlElicitationSupport.toUrlElicitationRequiredError(error);

        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) mapped.getJsonRpcError().data();
        @SuppressWarnings("unchecked")
        List<ElicitUrlRequest> elicitations = (List<ElicitUrlRequest>) data.get("elicitations");
        String combinedMessage = elicitations.getFirst().message();
        assertThat(combinedMessage).contains("unknown_service").contains("original message");
    }

    @Test
    void toUrlElicitationRequiredError_nonOauthError_returnsNull() {
        // oauth_error not in {consent_required, interaction_required} → asConsentRequired
        // returns null → toUrlElicitationRequiredError returns null (not applicable).
        TokenExchangeException error = new TokenExchangeException("misc", "access_denied");

        assertThat(UrlElicitationSupport.toUrlElicitationRequiredError(error)).isNull();
    }

    @Test
    void wrapToolWithUrlElicitation_checkedException_wrappedInRuntime() {
        // A checked Throwable is not a consent-with-URL error, so
        // toUrlElicitationRequiredError returns null. The wrapper's rethrow path then
        // wraps the checked cause in a RuntimeException (AuthplaneMcpException).
        Exception checked = new Exception("plain checked exception");
        BiFunction<McpSyncServerExchange, CallToolRequest, CallToolResult> wrapped =
                UrlElicitationSupport.wrapToolWithUrlElicitation(
                        (exchange, request) -> {
                            sneakyThrow(checked);
                            return null; // unreachable
                        });

        assertThatThrownBy(() -> wrapped.apply(null, null))
                .isInstanceOf(RuntimeException.class)
                .hasCause(checked);
    }

    @Test
    void wrapToolWithUrlElicitation_nonConsentRuntimeException_rethrownAsIs() {
        // A non-consent RuntimeException is not a consent-with-URL error, so
        // toUrlElicitationRequiredError returns null. The wrapper's rethrow path then
        // returns the original RuntimeException unchanged (same reference) — it is NOT
        // wrapped in AuthplaneMcpException.
        RuntimeException original = new IllegalArgumentException("not a consent error");
        BiFunction<McpSyncServerExchange, CallToolRequest, CallToolResult> wrapped =
                UrlElicitationSupport.wrapToolWithUrlElicitation(
                        (exchange, request) -> {
                            throw original;
                        });

        assertThatThrownBy(() -> wrapped.apply(null, null)).isSameAs(original);
    }

    @Test
    void bareTokenExchangeException_returnsNull() {
        // A bare TokenExchangeException is not a ConsentRequiredException, so
        // asConsentRequired returns null even when it carries "consent_required" →
        // toUrlElicitationRequiredError returns null (not applicable).
        TokenExchangeException raw = new TokenExchangeException("bare", "consent_required");

        assertThat(UrlElicitationSupport.toUrlElicitationRequiredError(raw)).isNull();
    }

    @SuppressWarnings("unchecked")
    private static <T extends Throwable> void sneakyThrow(Throwable t) throws T {
        throw (T) t;
    }
}
