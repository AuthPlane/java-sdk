package ai.authplane.sdk.core.fetching.ssrf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;

import ai.authplane.sdk.core.fetching.FetchSettings;
import ai.authplane.sdk.core.fetching.HttpResponseData;
import ai.authplane.sdk.core.fetching.HttpTransport;
import ai.authplane.sdk.core.fetching.RawPostResponse;

/**
 * Fetches a remote JSON document with full SSRF protection.
 *
 * <p>Protection mechanisms: 1. URL and IP validation via UrlValidator / IpValidator 2. DNS pinning:
 * connects directly to resolved IP, not hostname 3. TLS SNI set to original hostname (so
 * certificate validation works) 4. Host header set to original hostname (for virtual hosting) 5.
 * Redirects disabled 6. Response body capped at MAX_RESPONSE_BYTES (65536) 7. Configurable timeout
 * (default 10s)
 *
 * <p>Thread-safe — all methods are stateless. A new HttpClient is created per-IP-attempt to allow
 * per-request SNI configuration.
 */
public final class SsrfSafeFetcher {

    private static final Logger LOG = Logger.getLogger(SsrfSafeFetcher.class.getName());

    /** Maximum permitted response body size in bytes (64 KB). */
    public static final int MAX_RESPONSE_BYTES = 65_536;

    private SsrfSafeFetcher() {}

    /**
     * Fetches the given URL with SSRF protection.
     *
     * <p>Attempts each resolved IP in order, returning on the first success. Continues to the next
     * IP on connection timeout or network error. Immediately re-throws SsrfException (blocked IP or
     * size exceeded).
     *
     * @param url the URL to fetch
     * @param settings SSRF configuration
     * @return HttpResponse with body and headers
     * @throws SsrfException if the URL is blocked by SSRF rules
     * @throws IOException if all IPs fail with network errors
     */
    public static HttpResponseData fetch(String url, FetchSettings settings) throws IOException {

        ValidatedUrl validated = UrlValidator.validate(url, settings);
        LOG.fine(
                () ->
                        "SSRF-safe fetch: "
                                + url
                                + " → "
                                + validated.resolvedIps().size()
                                + " IP(s)");

        return tryEachIp(validated, "GET", ip -> fetchFromIp(validated, ip, settings));
    }

    /**
     * POSTs URL-encoded form data to the given URL with SSRF protection.
     *
     * <p>Mirrors the same DNS-pinning and IP-validation guarantees as {@link #fetch}.
     *
     * @param url the URL to POST to
     * @param formData URL-encoded form fields (key → value); may be empty
     * @param extraHeaders additional request headers (e.g. Authorization); may be null
     * @param settings SSRF configuration
     * @return HttpResponseData with body and headers
     * @throws SsrfException if the URL is blocked by SSRF rules
     * @throws IOException if all IPs fail with network errors
     */
    public static HttpResponseData post(
            String url,
            Map<String, String> formData,
            Map<String, String> extraHeaders,
            FetchSettings settings)
            throws IOException {

        ValidatedUrl validated = UrlValidator.validate(url, settings);
        LOG.fine(
                () -> "SSRF-safe POST: " + url + " → " + validated.resolvedIps().size() + " IP(s)");

        return tryEachIp(
                validated,
                "POST",
                ip -> postFromIp(validated, ip, formData, extraHeaders, settings));
    }

    /**
     * POSTs URL-encoded form data, reading the response body even for 4xx responses.
     *
     * <p>Use this when the caller needs to inspect the response body before deciding whether the
     * request succeeded (e.g. token exchange OAuth error responses).
     *
     * <p>Applies the same SSRF protections as {@link #post}.
     *
     * @param url the URL to POST to
     * @param formData URL-encoded form fields; may be null
     * @param extraHeaders additional request headers; may be null
     * @param settings SSRF configuration
     * @return {@link RawPostResponse} containing HTTP status and body
     * @throws SsrfException if the URL is blocked by SSRF rules
     * @throws IOException if all IPs fail with network errors
     */
    public static RawPostResponse postRaw(
            String url,
            Map<String, String> formData,
            Map<String, String> extraHeaders,
            FetchSettings settings)
            throws IOException {
        return postRaw(
                url,
                formData == null
                        ? List.of()
                        : formData.entrySet().stream()
                                .map(entry -> Map.entry(entry.getKey(), entry.getValue()))
                                .toList(),
                extraHeaders,
                settings);
    }

    /**
     * Posts form data to the given URL with SSRF-safe DNS resolution and returns the raw response.
     */
    public static RawPostResponse postRaw(
            String url,
            List<Map.Entry<String, String>> formData,
            Map<String, String> extraHeaders,
            FetchSettings settings)
            throws IOException {

        ValidatedUrl validated = UrlValidator.validate(url, settings);
        LOG.fine(
                () ->
                        "SSRF-safe POST (raw): "
                                + url
                                + " → "
                                + validated.resolvedIps().size()
                                + " IP(s)");

        return tryEachIpRaw(
                validated, ip -> postRawFromIp(validated, ip, formData, extraHeaders, settings));
    }

    // -----------------------------------------------------------------------
    // Shared infrastructure
    // -----------------------------------------------------------------------

    /** Checked functional interface for per-IP request execution. */
    @FunctionalInterface
    private interface IpHandler {
        HttpResponseData handle(InetAddress ip) throws Exception;
    }

    /** Checked functional interface for per-IP raw request execution. */
    @FunctionalInterface
    private interface RawIpHandler {
        RawPostResponse handle(InetAddress ip) throws Exception;
    }

    /**
     * Iterates resolved IPs, delegating each attempt to {@code handler}. Retries on transient
     * network errors; re-throws {@link SsrfException} immediately.
     */
    private static HttpResponseData tryEachIp(
            ValidatedUrl validated, String method, IpHandler handler) throws IOException {
        Exception lastError = null;
        for (InetAddress ip : validated.resolvedIps()) {
            try {
                return handler.handle(ip);
            } catch (SsrfException e) {
                throw e; // SSRF violations are not retried
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException(method + " interrupted for " + validated.originalUrl(), e);
            } catch (Exception e) {
                LOG.log(
                        Level.WARNING,
                        "Failed to " + method + " to " + ip.getHostAddress() + ", trying next IP",
                        e);
                lastError = e;
            }
        }
        throw new IOException(
                "All resolved IPs failed for " + method + " " + validated.originalUrl(), lastError);
    }

    /** Like {@link #tryEachIp} but for raw (status-preserving) responses. */
    private static RawPostResponse tryEachIpRaw(ValidatedUrl validated, RawIpHandler handler)
            throws IOException {
        Exception lastError = null;
        for (InetAddress ip : validated.resolvedIps()) {
            try {
                return handler.handle(ip);
            } catch (SsrfException e) {
                throw e;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("POST interrupted for " + validated.originalUrl(), e);
            } catch (Exception e) {
                LOG.log(
                        Level.WARNING,
                        "Failed raw POST to " + ip.getHostAddress() + ", trying next IP",
                        e);
                lastError = e;
            }
        }
        throw new IOException(
                "All resolved IPs failed for raw POST " + validated.originalUrl(), lastError);
    }

    /** Builds an HttpClient with SNI, no redirects, and a connect timeout. */
    private static HttpClient buildClient(ValidatedUrl validated, FetchSettings settings) {
        SSLParameters sslParameters = new SSLParameters();
        if ("https".equals(validated.scheme())) {
            sslParameters.setServerNames(List.of(new SNIHostName(validated.hostname())));
        }
        return HttpClient.newBuilder()
                .sslParameters(sslParameters)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(settings.timeoutSeconds()))
                .build();
    }

    /**
     * Sends the request and enforces the response size cap before reading the body. Throws {@link
     * SsrfException} if Content-Length already exceeds the limit.
     */
    private static HttpResponseData sendAndCheck(
            HttpClient client, HttpRequest request, ValidatedUrl validated)
            throws IOException, InterruptedException {
        HttpResponse<InputStream> response = client.send(request, BodyHandlers.ofInputStream());
        long contentLength = response.headers().firstValueAsLong("content-length").orElse(-1);
        if (contentLength > MAX_RESPONSE_BYTES) {
            response.body().close();
            throw new SsrfException(
                    String.format(
                            "Response from %s Content-Length %d exceeds maximum allowed size (%d bytes)",
                            validated.originalUrl(), contentLength, MAX_RESPONSE_BYTES));
        }
        return HttpResponseData.from(response, validated.originalUrl());
    }

    // -----------------------------------------------------------------------
    // Per-IP request builders
    // -----------------------------------------------------------------------

    private static HttpResponseData fetchFromIp(
            ValidatedUrl validated, InetAddress ip, FetchSettings settings)
            throws IOException, InterruptedException {
        HttpClient client = buildClient(validated, settings);
        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(URI.create(buildPinnedUrl(validated, ip)))
                        .header("Host", validated.hostname())
                        .header("Accept", "application/json")
                        .timeout(Duration.ofSeconds(settings.timeoutSeconds()))
                        .GET()
                        .build();
        return sendAndCheck(client, request, validated);
    }

    private static HttpResponseData postFromIp(
            ValidatedUrl validated,
            InetAddress ip,
            Map<String, String> formData,
            Map<String, String> extraHeaders,
            FetchSettings settings)
            throws IOException, InterruptedException {
        HttpClient client = buildClient(validated, settings);

        StringBuilder body = new StringBuilder();
        if (formData != null) {
            for (Map.Entry<String, String> entry : formData.entrySet()) {
                if (!body.isEmpty()) body.append('&');
                body.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
                        .append('=')
                        .append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
            }
        }

        HttpRequest.Builder reqBuilder =
                HttpRequest.newBuilder()
                        .uri(URI.create(buildPinnedUrl(validated, ip)))
                        .header("Host", validated.hostname())
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .header("Accept", "application/json")
                        .timeout(Duration.ofSeconds(settings.timeoutSeconds()))
                        .POST(HttpRequest.BodyPublishers.ofString(body.toString()));

        if (extraHeaders != null) {
            extraHeaders.forEach(reqBuilder::header);
        }

        return sendAndCheck(client, reqBuilder.build(), validated);
    }

    private static RawPostResponse postRawFromIp(
            ValidatedUrl validated,
            InetAddress ip,
            List<Map.Entry<String, String>> formData,
            Map<String, String> extraHeaders,
            FetchSettings settings)
            throws IOException, InterruptedException {
        HttpClient client = buildClient(validated, settings);
        String body = HttpTransport.encodeEntries(formData);

        HttpRequest.Builder reqBuilder =
                HttpRequest.newBuilder()
                        .uri(URI.create(buildPinnedUrl(validated, ip)))
                        .header("Host", validated.hostname())
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .header("Accept", "application/json")
                        .timeout(Duration.ofSeconds(settings.timeoutSeconds()))
                        .POST(HttpRequest.BodyPublishers.ofString(body));

        if (extraHeaders != null) {
            extraHeaders.forEach(reqBuilder::header);
        }

        HttpResponse<InputStream> response =
                client.send(reqBuilder.build(), BodyHandlers.ofInputStream());

        long contentLength = response.headers().firstValueAsLong("content-length").orElse(-1);
        if (contentLength > MAX_RESPONSE_BYTES) {
            response.body().close();
            throw new SsrfException(
                    String.format(
                            "Response from %s Content-Length %d exceeds maximum allowed size (%d bytes)",
                            validated.originalUrl(), contentLength, MAX_RESPONSE_BYTES));
        }

        byte[] bodyBytes = readLimited(response.body(), validated.originalUrl());
        Map<String, String> headers = new HashMap<>();
        response.headers()
                .map()
                .forEach(
                        (name, values) -> {
                            if (!values.isEmpty()) {
                                headers.put(name.toLowerCase(), values.get(0));
                            }
                        });

        return new RawPostResponse(
                response.statusCode(), new String(bodyBytes, StandardCharsets.UTF_8), headers);
    }

    // -----------------------------------------------------------------------
    // Utilities
    // -----------------------------------------------------------------------

    /**
     * Reads {@code is} into a byte array, throwing {@link SsrfException} immediately if the
     * accumulated byte count exceeds {@link #MAX_RESPONSE_BYTES}. Closes the stream.
     */
    public static byte[] readLimited(InputStream is, String url) throws IOException {
        byte[] buf = new byte[8192];
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (is) {
            int read;
            while ((read = is.read(buf)) != -1) {
                if (baos.size() + read > MAX_RESPONSE_BYTES) {
                    throw new SsrfException(
                            String.format(
                                    "Response from %s exceeds maximum allowed size (%d bytes)",
                                    url, MAX_RESPONSE_BYTES));
                }
                baos.write(buf, 0, read);
            }
        }
        return baos.toByteArray();
    }

    private static String buildPinnedUrl(ValidatedUrl validated, InetAddress ip) {
        String ipStr = ip.getHostAddress();
        // IPv6 addresses must be wrapped in brackets in URLs
        if (ip instanceof Inet6Address) {
            // Remove any zone ID (e.g. %eth0)
            int zoneIdx = ipStr.indexOf('%');
            if (zoneIdx != -1) ipStr = ipStr.substring(0, zoneIdx);
            ipStr = "[" + ipStr + "]";
        }
        return validated.scheme() + "://" + ipStr + ":" + validated.port() + validated.path();
    }
}
