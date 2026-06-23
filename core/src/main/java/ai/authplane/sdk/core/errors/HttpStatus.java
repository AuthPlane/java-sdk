package ai.authplane.sdk.core.errors;

import ai.authplane.sdk.core.dpop.DPoPException;

/**
 * Maps Authplane exceptions to HTTP status codes.
 *
 * <p>Framework adapters can use this to translate SDK exceptions into appropriate HTTP responses.
 *
 * <table>
 *   <caption>SDK exception to HTTP status mapping</caption>
 *   <tr><th>Exception</th><th>HTTP Status</th></tr>
 *   <tr><td>{@link InsufficientScopeException}</td><td>403 Forbidden</td></tr>
 *   <tr><td>{@link JwksFetchException}, {@link MetadataFetchException}</td><td>503 Service Unavailable</td></tr>
 *   <tr><td>{@link TokenExchangeException}</td><td>500 Internal Server Error</td></tr>
 *   <tr><td>{@link TokenMissingException}, {@link TokenExpiredException},
 *       {@link InvalidSignatureException}, {@link InvalidClaimsException},
 *       {@link TokenRevokedException}, {@link DPoPException}</td><td>401 Unauthorized</td></tr>
 *   <tr><td>Other {@link AuthplaneException}</td><td>500 Internal Server Error</td></tr>
 * </table>
 */
public final class HttpStatus {

    private HttpStatus() {}

    /**
     * Returns the HTTP status code for the given Authplane exception.
     *
     * @param error the exception thrown by the SDK
     * @return the appropriate HTTP status code
     */
    public static int of(AuthplaneException error) {
        if (error instanceof InsufficientScopeException) {
            return 403;
        }
        if (error instanceof JwksFetchException || error instanceof MetadataFetchException) {
            return 503;
        }
        if (error instanceof TokenExchangeException) {
            return 500;
        }
        if (error instanceof TokenMissingException
                || error instanceof TokenExpiredException
                || error instanceof InvalidSignatureException
                || error instanceof InvalidClaimsException
                || error instanceof TokenRevokedException
                || error instanceof DPoPException) {
            return 401;
        }
        return 500;
    }
}
