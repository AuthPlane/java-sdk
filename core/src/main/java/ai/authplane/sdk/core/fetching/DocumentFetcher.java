package ai.authplane.sdk.core.fetching;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import com.nimbusds.jose.util.JSONObjectUtils;

/**
 * Fetches a JSON document from a URL and returns a FetchResult containing the parsed document and
 * optional server-supplied expiry.
 *
 * <p>All transport decisions (SSRF-safe vs plain) are made by the {@link HttpTransport} instance
 * passed to {@link #from(HttpTransport)}. Use the convenience factories {@link
 * #ssrfSafe(FetchSettings)} and {@link #direct(int)} when an {@link HttpTransport} is not already
 * available.
 */
@FunctionalInterface
public interface DocumentFetcher {

    /**
     * Fetches the document asynchronously.
     *
     * @return CompletableFuture completing with the FetchResult, or completing exceptionally with
     *     IOException or SsrfException.
     */
    CompletableFuture<FetchResult> fetch(String url);

    // -----------------------------------------------------------------------
    // Factory methods
    // -----------------------------------------------------------------------

    /**
     * Returns a DocumentFetcher backed by the given transport. Prefer this factory when an {@link
     * HttpTransport} is already available.
     */
    static DocumentFetcher from(HttpTransport transport) {
        return url ->
                CompletableFuture.supplyAsync(
                        () -> {
                            try {
                                HttpResponseData raw = transport.get(url);
                                Map<String, Object> doc = parseJson(raw.body(), url);
                                Long expiresAt = CacheHeaderParser.parseExpiresAt(raw.headers());
                                return new FetchResult(doc, expiresAt);
                            } catch (IOException e) {
                                throw new CompletionException(e);
                            }
                        });
    }

    /**
     * Returns a DocumentFetcher that uses SSRF-safe DNS-pinned fetching. Use in all production
     * scenarios.
     */
    static DocumentFetcher ssrfSafe(FetchSettings settings) {
        return from(HttpTransport.from(settings));
    }

    /**
     * Returns a DocumentFetcher that uses a plain HttpClient without any SSRF protection. Use only
     * in dev mode.
     */
    static DocumentFetcher direct(int timeoutSeconds) {
        return from(HttpTransport.from(new FetchSettings(false, true, true, true, timeoutSeconds)));
    }

    // -----------------------------------------------------------------------

    private static Map<String, Object> parseJson(String body, String url) throws IOException {
        if (body == null || body.isBlank()) {
            throw new IOException("Empty response body from " + url);
        }
        try {
            return JSONObjectUtils.parse(body);
        } catch (Exception e) {
            throw new IOException("Invalid JSON response from " + url + ": " + e.getMessage(), e);
        }
    }
}
