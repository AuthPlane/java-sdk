package ai.authplane.sdk.core.fetching;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

/**
 * Tests for DocumentFetcher factory methods.
 *
 * <p>ssrfSafe() and direct() are both exercised via WireMock, covering the happy path and the
 * IOException / invalid-JSON failure paths.
 *
 * <p>ssrfSafe() uses FetchSettings.devMode() so that localhost is permitted by the SSRF validator;
 * the jdk.httpclient.allowRestrictedHeaders=host system property (set in pom.xml Surefire) lets
 * SsrfSafeFetcher pin the Host header.
 */
class DocumentFetcherTest {

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
    // ssrfSafe() — SSRF-safe fetching via SsrfSafeFetcher
    // -----------------------------------------------------------------------

    @Test
    void ssrfSafe_success_returnsDocument() throws Exception {
        wireMock.stubFor(
                get(urlEqualTo("/jwks"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"keys\":[]}")));

        DocumentFetcher fetcher = DocumentFetcher.ssrfSafe(FetchSettings.devMode());
        FetchResult result = fetcher.fetch(baseUrl + "/jwks").get();

        assertThat(result.document()).containsKey("keys");
        assertThat(result.expiresAt()).isNull();
        assertThat(result.hasServerExpiry()).isFalse();
    }

    @Test
    void ssrfSafe_withCacheControl_populatesExpiresAt() throws Exception {
        wireMock.stubFor(
                get(urlEqualTo("/jwks-cached"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withHeader("Cache-Control", "max-age=300")
                                        .withBody("{\"keys\":[]}")));

        DocumentFetcher fetcher = DocumentFetcher.ssrfSafe(FetchSettings.devMode());
        FetchResult result = fetcher.fetch(baseUrl + "/jwks-cached").get();

        assertThat(result.hasServerExpiry()).isTrue();
        assertThat(result.expiresAt()).isGreaterThan(0L);
    }

    @Test
    void ssrfSafe_non2xxResponse_failsFuture() {
        // CompletableFuture.supplyAsync() unwraps CompletionException, so .get()
        // throws ExecutionException whose cause is the original IOException directly.
        wireMock.stubFor(
                get(urlEqualTo("/not-found"))
                        .willReturn(aResponse().withStatus(404).withBody("Not Found")));

        var future =
                DocumentFetcher.ssrfSafe(FetchSettings.devMode()).fetch(baseUrl + "/not-found");

        assertThatThrownBy(future::get)
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(IOException.class);
    }

    @Test
    void ssrfSafe_emptyBody_failsFuture() {
        wireMock.stubFor(
                get(urlEqualTo("/empty"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("")));

        var future = DocumentFetcher.ssrfSafe(FetchSettings.devMode()).fetch(baseUrl + "/empty");

        assertThatThrownBy(future::get)
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Empty response body");
    }

    @Test
    void ssrfSafe_invalidJson_failsFuture() {
        wireMock.stubFor(
                get(urlEqualTo("/bad-json"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("not-json")));

        var future = DocumentFetcher.ssrfSafe(FetchSettings.devMode()).fetch(baseUrl + "/bad-json");

        assertThatThrownBy(future::get)
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Invalid JSON");
    }

    // -----------------------------------------------------------------------
    // direct() — plain HttpClient (dev mode only)
    // -----------------------------------------------------------------------

    @Test
    void direct_success_returnsDocument() throws Exception {
        wireMock.stubFor(
                get(urlEqualTo("/meta"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"issuer\":\"https://auth.example.com\"}")));

        DocumentFetcher fetcher = DocumentFetcher.direct(5);
        FetchResult result = fetcher.fetch(baseUrl + "/meta").get();

        assertThat(result.document()).containsKey("issuer");
        assertThat(result.document().get("issuer")).isEqualTo("https://auth.example.com");
    }

    @Test
    void direct_withCacheControl_populatesExpiresAt() throws Exception {
        wireMock.stubFor(
                get(urlEqualTo("/meta-cached"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withHeader("Cache-Control", "max-age=600")
                                        .withBody("{\"issuer\":\"https://auth.example.com\"}")));

        DocumentFetcher fetcher = DocumentFetcher.direct(5);
        FetchResult result = fetcher.fetch(baseUrl + "/meta-cached").get();

        assertThat(result.hasServerExpiry()).isTrue();
        assertThat(result.expiresAt()).isGreaterThan(0L);
    }

    @Test
    void direct_non2xxResponse_failsFuture() {
        wireMock.stubFor(
                get(urlEqualTo("/server-error"))
                        .willReturn(aResponse().withStatus(500).withBody("Internal Server Error")));

        var future = DocumentFetcher.direct(5).fetch(baseUrl + "/server-error");

        assertThatThrownBy(future::get)
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(IOException.class);
    }

    @Test
    void direct_emptyBody_failsFuture() {
        wireMock.stubFor(
                get(urlEqualTo("/direct-empty"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("")));

        var future = DocumentFetcher.direct(5).fetch(baseUrl + "/direct-empty");

        assertThatThrownBy(future::get)
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Empty response body");
    }

    @Test
    void direct_invalidJson_failsFuture() {
        wireMock.stubFor(
                get(urlEqualTo("/direct-bad-json"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{ bad json }")));

        var future = DocumentFetcher.direct(5).fetch(baseUrl + "/direct-bad-json");

        assertThatThrownBy(future::get)
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Invalid JSON");
    }
}
