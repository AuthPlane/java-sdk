package ai.authplane.sdk.core.fetching;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ai.authplane.sdk.core.fetching.ssrf.SsrfSafeFetcher;

/**
 * Unified HTTP transport for the Authplane SDK.
 *
 * <p>Single decision point for SSRF-safe vs plain (dev-mode) HTTP access. All network calls — JWKS,
 * OAuth metadata, and token introspection — go through this class. Callers never instantiate {@link
 * SsrfSafeFetcher} or {@link HttpClient} directly.
 *
 * <p>Instantiate once per verifier via {@link #from(FetchSettings)}. Thread-safe — the underlying
 * {@link HttpClient} is thread-safe.
 */
public final class HttpTransport {

    private final FetchSettings settings;

    /**
     * Shared plain HttpClient for dev-mode (non-SSRF) calls. {@code null} when SSRF protection is
     * enabled.
     */
    private final HttpClient directClient;

    private HttpTransport(FetchSettings settings) {
        this.settings = settings;
        this.directClient =
                settings.ssrfProtection()
                        ? null
                        : HttpClient.newBuilder()
                                .followRedirects(HttpClient.Redirect.NEVER)
                                .connectTimeout(Duration.ofSeconds(settings.timeoutSeconds()))
                                .build();
    }

    /** Creates an {@code HttpTransport} configured from the given settings. */
    public static HttpTransport from(FetchSettings settings) {
        return new HttpTransport(settings);
    }

    /**
     * Performs an HTTP GET and returns the raw response.
     *
     * <p>Routes through SSRF-safe DNS-pinned fetching (production) or a plain {@link HttpClient}
     * (dev mode) based on the configured {@link FetchSettings}.
     *
     * @throws IOException on network error or non-2xx response
     */
    public HttpResponseData get(String url) throws IOException {
        return settings.ssrfProtection() ? SsrfSafeFetcher.fetch(url, settings) : directGet(url);
    }

    /**
     * Performs an HTTP POST with URL-encoded form data and returns the raw response.
     *
     * <p>Routes through SSRF-safe DNS-pinned fetching (production) or a plain {@link HttpClient}
     * (dev mode) based on the configured {@link FetchSettings}.
     *
     * @param formData form fields to URL-encode as the request body; may be null
     * @param extraHeaders additional headers (e.g. Authorization); may be null
     * @throws IOException on network error or non-2xx response
     */
    public HttpResponseData post(
            String url, Map<String, String> formData, Map<String, String> extraHeaders)
            throws IOException {
        return settings.ssrfProtection()
                ? SsrfSafeFetcher.post(url, formData, extraHeaders, settings)
                : directPost(url, formData, extraHeaders);
    }

    /**
     * Like {@link #post} but reads the response body even for 4xx responses, returning both HTTP
     * status code and body. Use when the caller must inspect error bodies (e.g. OAuth token
     * endpoint error responses per RFC 8693).
     *
     * <p>Package-private — used by token exchange internals.
     *
     * @param formData form fields to URL-encode as the request body; may be null
     * @param extraHeaders additional headers (e.g. Authorization); may be null
     * @throws IOException on network error
     */
    public RawPostResponse postRaw(
            String url, Map<String, String> formData, Map<String, String> extraHeaders)
            throws IOException {
        return postRaw(url, toEntries(formData), extraHeaders);
    }

    /** Posts form data (as an ordered entry list) to the given URL and returns the raw response. */
    public RawPostResponse postRaw(
            String url, List<Map.Entry<String, String>> formData, Map<String, String> extraHeaders)
            throws IOException {
        return settings.ssrfProtection()
                ? SsrfSafeFetcher.postRaw(url, formData, extraHeaders, settings)
                : directPostRaw(url, formData, extraHeaders);
    }

    // -----------------------------------------------------------------------
    // Dev-mode (non-SSRF) implementations
    // -----------------------------------------------------------------------

    private HttpResponseData directGet(String url) throws IOException {
        try {
            HttpRequest request =
                    HttpRequest.newBuilder()
                            .uri(URI.create(url))
                            .header("Accept", "application/json")
                            .timeout(Duration.ofSeconds(settings.timeoutSeconds()))
                            .GET()
                            .build();
            HttpResponse<InputStream> response =
                    directClient.send(request, BodyHandlers.ofInputStream());
            return HttpResponseData.from(response, url);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("GET interrupted for " + url, e);
        }
    }

    private RawPostResponse directPostRaw(
            String url, List<Map.Entry<String, String>> formData, Map<String, String> extraHeaders)
            throws IOException {
        try {
            String body = encodeEntries(formData);

            HttpRequest.Builder reqBuilder =
                    HttpRequest.newBuilder()
                            .uri(URI.create(url))
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .header("Accept", "application/json")
                            .timeout(Duration.ofSeconds(settings.timeoutSeconds()))
                            .POST(HttpRequest.BodyPublishers.ofString(body));

            if (extraHeaders != null) {
                extraHeaders.forEach(reqBuilder::header);
            }

            HttpResponse<InputStream> response =
                    directClient.send(reqBuilder.build(), BodyHandlers.ofInputStream());
            byte[] bodyBytes = SsrfSafeFetcher.readLimited(response.body(), url);
            return new RawPostResponse(
                    response.statusCode(),
                    new String(bodyBytes, StandardCharsets.UTF_8),
                    collectHeaders(response));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("POST interrupted for " + url, e);
        }
    }

    private HttpResponseData directPost(
            String url, Map<String, String> formData, Map<String, String> extraHeaders)
            throws IOException {
        try {
            String body = encodeEntries(toEntries(formData));

            HttpRequest.Builder reqBuilder =
                    HttpRequest.newBuilder()
                            .uri(URI.create(url))
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .header("Accept", "application/json")
                            .timeout(Duration.ofSeconds(settings.timeoutSeconds()))
                            .POST(HttpRequest.BodyPublishers.ofString(body));

            if (extraHeaders != null) {
                extraHeaders.forEach(reqBuilder::header);
            }

            HttpResponse<InputStream> response =
                    directClient.send(reqBuilder.build(), BodyHandlers.ofInputStream());
            return HttpResponseData.from(response, url);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("POST interrupted for " + url, e);
        }
    }

    private static Map<String, String> collectHeaders(HttpResponse<?> response) {
        Map<String, String> headers = new HashMap<>();
        response.headers()
                .map()
                .forEach(
                        (name, values) -> {
                            if (!values.isEmpty()) {
                                headers.put(name.toLowerCase(), values.get(0));
                            }
                        });
        return headers;
    }

    private static List<Map.Entry<String, String>> toEntries(Map<String, String> formData) {
        if (formData == null || formData.isEmpty()) {
            return List.of();
        }
        return formData.entrySet().stream()
                .<Map.Entry<String, String>>map(
                        entry -> new SimpleImmutableEntry<>(entry.getKey(), entry.getValue()))
                .toList();
    }

    /** URL-encodes an ordered list of key-value entries into a form-urlencoded string. */
    public static String encodeEntries(List<Map.Entry<String, String>> entries) {
        StringBuilder body = new StringBuilder();
        if (entries == null) {
            return "";
        }
        for (Map.Entry<String, String> entry : entries) {
            if (!body.isEmpty()) {
                body.append('&');
            }
            body.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
                    .append('=')
                    .append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
        }
        return body.toString();
    }
}
