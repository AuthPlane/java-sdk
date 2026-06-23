package ai.authplane.sdk.core.errors;

import java.io.Serial;

/**
 * Thrown when RFC 8693 token exchange fails.
 *
 * <p>When the Authorization Server returns an OAuth error response, {@link #oauthError()} contains
 * the {@code error} field value (e.g. {@code "invalid_grant"}). For other failures (network errors,
 * missing endpoint, malformed response) it is {@code null}.
 */
public class TokenExchangeException extends AuthplaneException {

    @Serial private static final long serialVersionUID = 1L;

    private final String oauthError; // nullable

    public TokenExchangeException(String message, String oauthError) {
        super(message);
        this.oauthError = oauthError;
    }

    public TokenExchangeException(String message, String oauthError, Throwable cause) {
        super(message, cause);
        this.oauthError = oauthError;
    }

    /**
     * Returns the OAuth error code (e.g. {@code "invalid_grant"}), or {@code null} if this
     * exception was not caused by an OAuth error response.
     */
    public String oauthError() {
        return oauthError;
    }
}
