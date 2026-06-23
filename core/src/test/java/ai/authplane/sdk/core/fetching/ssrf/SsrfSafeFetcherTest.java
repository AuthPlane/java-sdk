package ai.authplane.sdk.core.fetching.ssrf;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import ai.authplane.sdk.core.fetching.FetchSettings;
import ai.authplane.sdk.core.fetching.HttpResponseData;
import ai.authplane.sdk.core.fetching.RawPostResponse;

/**
 * Tests for SsrfSafeFetcher.
 *
 * <p>readLimited() is tested with pure in-memory inputs.
 *
 * <p>fetch() integration tests use a local WireMock server. The system property
 * jdk.httpclient.allowRestrictedHeaders=host must be set at JVM startup (configured in pom.xml
 * Surefire) so that SsrfSafeFetcher can set the Host header for DNS-pinned connections.
 *
 * <p>SSRF-blocked scenarios are tested without any HTTP connection (URL validation fails before a
 * TCP connection is attempted).
 */
class SsrfSafeFetcherTest {

    private static WireMockServer wireMock;
    private static String baseUrl;

    @BeforeAll
    static void startWireMock() {
        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();
        baseUrl = "http://localhost:" + wireMock.port();
    }

    @AfterAll
    static void stopWireMock() {
        wireMock.stop();
    }

    @BeforeEach
    void resetStubs() {
        wireMock.resetAll();
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    @Test
    void maxResponseBytes_is65536() {
        assertThat(SsrfSafeFetcher.MAX_RESPONSE_BYTES).isEqualTo(65_536);
    }

    // -----------------------------------------------------------------------
    // readLimited() — pure unit tests
    // -----------------------------------------------------------------------

    @Test
    void readLimited_smallContent_returnsByteArray() throws IOException {
        byte[] content = "hello world".getBytes(StandardCharsets.UTF_8);
        byte[] result =
                SsrfSafeFetcher.readLimited(
                        new ByteArrayInputStream(content), "https://example.com");
        assertThat(result).isEqualTo(content);
    }

    @Test
    void readLimited_emptyInput_returnsEmptyArray() throws IOException {
        byte[] result =
                SsrfSafeFetcher.readLimited(
                        new ByteArrayInputStream(new byte[0]), "https://example.com");
        assertThat(result).isEmpty();
    }

    @Test
    void readLimited_exactlyAtLimit_succeeds() throws IOException {
        byte[] exact = new byte[SsrfSafeFetcher.MAX_RESPONSE_BYTES];
        Arrays.fill(exact, (byte) 'A');
        byte[] result =
                SsrfSafeFetcher.readLimited(new ByteArrayInputStream(exact), "https://example.com");
        assertThat(result).hasSize(SsrfSafeFetcher.MAX_RESPONSE_BYTES);
    }

    @Test
    void readLimited_oneBeyondLimit_throwsSsrfException() {
        byte[] tooBig = new byte[SsrfSafeFetcher.MAX_RESPONSE_BYTES + 1];
        assertThatThrownBy(
                        () ->
                                SsrfSafeFetcher.readLimited(
                                        new ByteArrayInputStream(tooBig), "https://example.com"))
                .isInstanceOf(SsrfException.class)
                .hasMessageContaining("exceeds maximum allowed size");
    }

    @Test
    void readLimited_largeContent_throwsSsrfException() {
        byte[] huge = new byte[SsrfSafeFetcher.MAX_RESPONSE_BYTES * 2];
        assertThatThrownBy(
                        () ->
                                SsrfSafeFetcher.readLimited(
                                        new ByteArrayInputStream(huge),
                                        "https://oversize.example.com"))
                .isInstanceOf(SsrfException.class)
                .hasMessageContaining("exceeds maximum allowed size")
                .hasMessageContaining("https://oversize.example.com");
    }

    @Test
    void readLimited_multipleChunks_readsAll() throws IOException {
        byte[] content = new byte[3_000];
        Arrays.fill(content, (byte) 'B');
        byte[] result =
                SsrfSafeFetcher.readLimited(
                        new ByteArrayInputStream(content), "https://example.com");
        assertThat(result).hasSize(3_000);
        assertThat(result[0]).isEqualTo((byte) 'B');
    }

    // -----------------------------------------------------------------------
    // fetch() — integration with WireMock (devMode settings, localhost)
    //
    // Requires jdk.httpclient.allowRestrictedHeaders=host (set in pom.xml).
    // -----------------------------------------------------------------------

    @Test
    void fetch_success_returnsResponseBody() throws IOException {
        String body = "{\"keys\":[]}";
        wireMock.stubFor(
                get(urlEqualTo("/jwks"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(body)));

        HttpResponseData response =
                SsrfSafeFetcher.fetch(baseUrl + "/jwks", FetchSettings.devMode());

        assertThat(response.body()).isEqualTo(body);
    }

    @Test
    void fetch_success_returnsLowerCasedHeaders() throws IOException {
        wireMock.stubFor(
                get(urlEqualTo("/meta"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withHeader("Cache-Control", "max-age=300")
                                        .withBody("{\"issuer\":\"x\"}")));

        HttpResponseData response =
                SsrfSafeFetcher.fetch(baseUrl + "/meta", FetchSettings.devMode());

        // Headers must be lower-cased
        assertThat(response.headers()).containsKey("content-type");
        assertThat(response.headers()).containsKey("cache-control");
        assertThat(response.header("Cache-Control")).isEqualTo("max-age=300");
    }

    @Test
    void fetch_non2xxStatus_throwsIoException() {
        wireMock.stubFor(
                get(urlEqualTo("/not-found"))
                        .willReturn(aResponse().withStatus(404).withBody("Not Found")));

        // Non-2xx causes IOException from HttpResponseData.from(), which the per-IP loop
        // treats as a network error and retries. With a single IP (localhost) the loop
        // exhausts and re-throws as "All resolved IPs failed", with the original HTTP
        // status error as the cause.
        assertThatThrownBy(
                        () ->
                                SsrfSafeFetcher.fetch(
                                        baseUrl + "/not-found", FetchSettings.devMode()))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("All resolved IPs failed")
                .cause()
                .isInstanceOf(IOException.class)
                .hasMessageContaining("404");
    }

    @Test
    void fetch_500Status_throwsIoException() {
        wireMock.stubFor(
                get(urlEqualTo("/error"))
                        .willReturn(aResponse().withStatus(500).withBody("Internal Server Error")));

        assertThatThrownBy(() -> SsrfSafeFetcher.fetch(baseUrl + "/error", FetchSettings.devMode()))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("All resolved IPs failed")
                .cause()
                .isInstanceOf(IOException.class)
                .hasMessageContaining("500");
    }

    // -----------------------------------------------------------------------
    // fetch() — SSRF blocking (URL validation fails before any TCP connection)
    // -----------------------------------------------------------------------

    @Test
    void fetch_httpInProduction_throwsSsrfException() {
        assertThatThrownBy(
                        () ->
                                SsrfSafeFetcher.fetch(
                                        "http://example.com/jwks", FetchSettings.production()))
                .isInstanceOf(SsrfException.class)
                .hasMessageContaining("HTTP is not allowed");
    }

    @Test
    void fetch_localhostInProduction_throwsSsrfException() {
        // localhost → 127.0.0.1, which is blocked in production
        assertThatThrownBy(
                        () ->
                                SsrfSafeFetcher.fetch(
                                        "https://localhost/jwks", FetchSettings.production()))
                .isInstanceOf(SsrfException.class)
                .hasMessageContaining("SSRF blocked");
    }

    @Test
    void fetch_unsupportedScheme_throwsSsrfException() {
        assertThatThrownBy(
                        () ->
                                SsrfSafeFetcher.fetch(
                                        "ftp://example.com/file", FetchSettings.production()))
                .isInstanceOf(SsrfException.class)
                .hasMessageContaining("Unsupported URL scheme");
    }

    @Test
    void fetch_unknownHostname_throwsSsrfException() {
        assertThatThrownBy(
                        () ->
                                SsrfSafeFetcher.fetch(
                                        "https://nonexistent.invalid/jwks",
                                        FetchSettings.production()))
                .isInstanceOf(SsrfException.class)
                .hasMessageContaining("DNS resolution failed");
    }

    @Test
    void fetch_cloudMetadataEndpoint_throwsSsrfException_inDevMode() {
        // 169.254.169.254 is always blocked, even in dev mode
        assertThatThrownBy(
                        () ->
                                SsrfSafeFetcher.fetch(
                                        "http://169.254.169.254/latest/meta-data/",
                                        FetchSettings.devMode()))
                .isInstanceOf(SsrfException.class);
    }

    // -----------------------------------------------------------------------
    // post() — integration with WireMock
    // -----------------------------------------------------------------------

    @Test
    void post_success_returnsResponseBody() throws IOException {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"access_token\":\"tok\"}")));

        HttpResponseData response =
                SsrfSafeFetcher.post(
                        baseUrl + "/token",
                        Map.of("grant_type", "client_credentials"),
                        null,
                        FetchSettings.devMode());

        assertThat(response.body()).contains("access_token");
    }

    @Test
    void post_withExtraHeaders_sendsHeaders() throws IOException {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .withHeader("Authorization", equalTo("Basic abc"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"ok\":true}")));

        HttpResponseData response =
                SsrfSafeFetcher.post(
                        baseUrl + "/token",
                        Map.of("grant_type", "client_credentials"),
                        Map.of("Authorization", "Basic abc"),
                        FetchSettings.devMode());

        assertThat(response.body()).contains("ok");
    }

    @Test
    void post_non2xx_throwsIoException() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(aResponse().withStatus(400).withBody("bad request")));

        assertThatThrownBy(
                        () ->
                                SsrfSafeFetcher.post(
                                        baseUrl + "/token", null, null, FetchSettings.devMode()))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("All resolved IPs failed");
    }

    @Test
    void post_httpInProduction_throwsSsrfException() {
        assertThatThrownBy(
                        () ->
                                SsrfSafeFetcher.post(
                                        "http://example.com/token",
                                        null,
                                        null,
                                        FetchSettings.production()))
                .isInstanceOf(SsrfException.class);
    }

    // -----------------------------------------------------------------------
    // postRaw() — integration with WireMock
    // -----------------------------------------------------------------------

    @Test
    void postRaw_success_returnsStatusAndBody() throws IOException {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"active\":true}")));

        RawPostResponse response =
                SsrfSafeFetcher.postRaw(
                        baseUrl + "/introspect",
                        Map.of("token", "test-token"),
                        Map.of("Authorization", "Basic xyz"),
                        FetchSettings.devMode());

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("active");
    }

    @Test
    void postRaw_4xxStatus_stillReturnsBody() throws IOException {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(400)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"error\":\"invalid_token\"}")));

        RawPostResponse response =
                SsrfSafeFetcher.postRaw(
                        baseUrl + "/introspect",
                        Map.of("token", "bad"),
                        null,
                        FetchSettings.devMode());

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("invalid_token");
    }

    @Test
    void postRaw_httpInProduction_throwsSsrfException() {
        assertThatThrownBy(
                        () ->
                                SsrfSafeFetcher.postRaw(
                                        "http://example.com/introspect",
                                        (Map<String, String>) null,
                                        null,
                                        FetchSettings.production()))
                .isInstanceOf(SsrfException.class);
    }

    @Test
    void postRaw_nullFormData_sendsEmptyBody() throws IOException {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(aResponse().withStatus(200).withBody("{\"active\":false}")));

        RawPostResponse response =
                SsrfSafeFetcher.postRaw(
                        baseUrl + "/introspect",
                        (Map<String, String>) null,
                        null,
                        FetchSettings.devMode());

        assertThat(response.statusCode()).isEqualTo(200);
    }
}
