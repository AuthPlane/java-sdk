package ai.authplane.sdk.core.fetching.ssrf;

import java.io.Serial;

/**
 * Thrown when an SSRF validation check fails: blocked IP address, invalid scheme, DNS resolution
 * failure, or response size exceeded.
 *
 * <p>This is an internal exception caught by SsrfSafeFetcher and re-thrown as JwksFetchException or
 * MetadataFetchException by the caller.
 */
public class SsrfException extends RuntimeException {

    @Serial private static final long serialVersionUID = 1L;

    public SsrfException(String message) {
        super(message);
    }

    public SsrfException(String message, Throwable cause) {
        super(message, cause);
    }
}
