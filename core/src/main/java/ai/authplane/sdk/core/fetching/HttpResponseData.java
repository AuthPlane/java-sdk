package ai.authplane.sdk.core.fetching;

import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import ai.authplane.sdk.core.fetching.ssrf.SsrfSafeFetcher;

/**
 * Internal: raw HTTP response body and headers from a fetch operation. Not part of the public SDK
 * API.
 */
public record HttpResponseData(
        /** Response body as a UTF-8 string. */
        String body,

        /** Response headers, header names lower-cased for case-insensitive lookup. */
        Map<String, String> headers) {
    public HttpResponseData {
        if (body == null) body = "";
        headers = headers == null ? Map.of() : Map.copyOf(headers);
    }

    /** Returns the value of the given header (case-insensitive), or null. */
    public String header(String name) {
        return headers.get(name.toLowerCase());
    }

    /**
     * Creates an HttpResponse from a raw Java HTTP response.
     *
     * <p>Collects headers (lower-cased), rejects non-2xx status codes, reads the body via {@link
     * SsrfSafeFetcher#readLimited} (capped at 64 KB), and returns a new HttpResponse.
     *
     * @param response the raw HTTP response with InputStream body
     * @param url the request URL (used in error messages)
     * @return a populated HttpResponse
     * @throws IOException if the status is non-2xx or the body cannot be read
     */
    public static HttpResponseData from(HttpResponse<InputStream> response, String url)
            throws IOException {

        Map<String, String> headers = new HashMap<>();
        response.headers()
                .map()
                .forEach(
                        (name, values) -> {
                            if (!values.isEmpty()) headers.put(name.toLowerCase(), values.get(0));
                        });

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            response.body().close();
            throw new IOException("HTTP " + response.statusCode() + " from " + url);
        }

        byte[] bodyBytes = SsrfSafeFetcher.readLimited(response.body(), url);
        return new HttpResponseData(new String(bodyBytes, StandardCharsets.UTF_8), headers);
    }
}
