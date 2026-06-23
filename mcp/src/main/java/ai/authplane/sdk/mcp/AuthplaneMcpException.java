package ai.authplane.sdk.mcp;

import java.io.Serial;

import ai.authplane.sdk.core.errors.AuthplaneException;

/**
 * Thrown by the Authplane MCP adapter for unexpected failures that are not one of the typed {@link
 * AuthplaneException} subtypes (e.g. an unexpected checked cause surfacing from token
 * verification).
 */
public class AuthplaneMcpException extends AuthplaneException {

    @Serial private static final long serialVersionUID = 1L;

    public AuthplaneMcpException(String message) {
        super(message);
    }

    public AuthplaneMcpException(String message, Throwable cause) {
        super(message, cause);
    }
}
