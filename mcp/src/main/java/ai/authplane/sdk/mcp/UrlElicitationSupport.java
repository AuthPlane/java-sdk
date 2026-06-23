package ai.authplane.sdk.mcp;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletionException;
import java.util.function.BiFunction;

import ai.authplane.sdk.core.errors.ConsentRequiredException;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.ElicitUrlRequest;

/**
 * Helpers that translate {@link ConsentRequiredException} into MCP {@code URL elicitation} errors.
 * Used by tool handlers that delegate to a downstream service requiring user consent.
 */
public final class UrlElicitationSupport {

    private static final String DEFAULT_CONSENT_MESSAGE = "Consent is required to proceed";

    private UrlElicitationSupport() {}

    /**
     * Converts a throwable carrying a {@link ConsentRequiredException} (with a consent URL) into an
     * {@link McpError} formatted as a URL-elicitation response.
     *
     * @param error throwable produced by token exchange or downstream call
     * @return an {@link McpError} with code {@code -32042} ({@code URL elicitation required}), or
     *     {@code null} when the error is not a consent-with-URL failure
     */
    public static McpError toUrlElicitationRequiredError(Throwable error) {
        ConsentRequiredException cre = asConsentRequired(error);
        if (cre == null || cre.consentUrl() == null || cre.consentUrl().isBlank()) {
            return null;
        }

        String message =
                cre.getMessage() == null || cre.getMessage().isBlank()
                        ? DEFAULT_CONSENT_MESSAGE
                        : cre.getMessage();
        String serviceId =
                cre.serviceId() == null || cre.serviceId().isBlank()
                        ? "unknown_service"
                        : cre.serviceId();
        String causeDetail =
                cre.causeDetail() == null || cre.causeDetail().isBlank()
                        ? message
                        : cre.causeDetail();

        ElicitUrlRequest elicitation =
                ElicitUrlRequest.builder(
                                message + " (" + serviceId + ": " + causeDetail + ")",
                                cre.consentUrl(),
                                UUID.randomUUID().toString())
                        .build();

        return McpError.builder(McpSchema.ErrorCodes.URL_ELICITATION_REQUIRED)
                .message(message)
                .data(Map.of("elicitations", List.of(elicitation)))
                .build();
    }

    /**
     * Wraps a tool handler so that any consent-required error thrown by the handler is reported to
     * the client as a URL-elicitation response instead of propagating the raw exception.
     *
     * @param handler the inner tool handler
     * @return a wrapped handler with URL-elicitation translation applied
     */
    public static BiFunction<McpSyncServerExchange, CallToolRequest, CallToolResult>
            wrapToolWithUrlElicitation(
                    BiFunction<McpSyncServerExchange, CallToolRequest, CallToolResult> handler) {
        return (exchange, request) -> {
            try {
                return handler.apply(exchange, request);
            } catch (Throwable error) {
                McpError mapped = toUrlElicitationRequiredError(error);
                if (mapped != null) {
                    throw mapped;
                }
                throw rethrow(error);
            }
        };
    }

    private static ConsentRequiredException asConsentRequired(Throwable error) {
        Throwable current = error;
        while (current instanceof CompletionException && current.getCause() != null) {
            current = current.getCause();
        }
        return (current instanceof ConsentRequiredException cre) ? cre : null;
    }

    private static RuntimeException rethrow(Throwable error) {
        if (error instanceof RuntimeException re) {
            return re;
        }
        return new AuthplaneMcpException(error.getMessage(), error);
    }
}
