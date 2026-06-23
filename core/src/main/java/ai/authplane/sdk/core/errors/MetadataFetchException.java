package ai.authplane.sdk.core.errors;

import java.io.Serial;

/**
 * Thrown when the OAuth Authorization Server metadata endpoint (RFC 8414
 * /.well-known/oauth-authorization-server) cannot be fetched and no cached metadata is available.
 *
 * <p>Also thrown if the metadata document is missing the required {@code jwks_uri} field.
 *
 * <p>Maps to HTTP 401.
 */
public class MetadataFetchException extends AuthplaneException {

    @Serial private static final long serialVersionUID = 1L;

    public MetadataFetchException(String message) {
        super(message);
    }

    public MetadataFetchException(String message, Throwable cause) {
        super(message, cause);
    }
}
