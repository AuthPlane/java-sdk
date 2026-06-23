package ai.authplane.sdk.core.fetching;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

class HttpTransportTest {

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
    // Dev-mode (non-SSRF) — exercises directGet/directPost/directPostRaw
    // -----------------------------------------------------------------------

    @Test
    void get_devMode_returnsResponse() throws IOException {
        wireMock.stubFor(
                get(urlEqualTo("/jwks"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"keys\":[]}")));

        HttpTransport transport = HttpTransport.from(FetchSettings.devMode());
        HttpResponseData response = transport.get(baseUrl + "/jwks");

        assertThat(response.body()).isEqualTo("{\"keys\":[]}");
    }

    @Test
    void post_devMode_returnsResponse() throws IOException {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"access_token\":\"tok\"}")));

        HttpTransport transport = HttpTransport.from(FetchSettings.devMode());
        HttpResponseData response =
                transport.post(
                        baseUrl + "/token",
                        Map.of("grant_type", "client_credentials"),
                        Map.of("Authorization", "Basic abc"));

        assertThat(response.body()).contains("access_token");
    }

    @Test
    void post_devMode_nullFormDataAndHeaders() throws IOException {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(aResponse().withStatus(200).withBody("{\"ok\":true}")));

        HttpTransport transport = HttpTransport.from(FetchSettings.devMode());
        HttpResponseData response = transport.post(baseUrl + "/token", null, null);

        assertThat(response.body()).contains("ok");
    }

    @Test
    void postRaw_devMode_returns4xxBody() throws IOException {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse().withStatus(400).withBody("{\"error\":\"invalid\"}")));

        HttpTransport transport = HttpTransport.from(FetchSettings.devMode());
        RawPostResponse response =
                transport.postRaw(baseUrl + "/introspect", Map.of("token", "bad"), null);

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("invalid");
    }

    @Test
    void postRaw_devMode_success() throws IOException {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(aResponse().withStatus(200).withBody("{\"active\":true}")));

        HttpTransport transport = HttpTransport.from(FetchSettings.devMode());
        RawPostResponse response =
                transport.postRaw(
                        baseUrl + "/introspect",
                        Map.of("token", "good"),
                        Map.of("Authorization", "Basic xyz"));

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("active");
    }

    // -----------------------------------------------------------------------
    // SSRF-enabled (production) — blocked by SSRF rules for localhost
    // -----------------------------------------------------------------------

    @Test
    void get_production_localhostBlocked() {
        HttpTransport transport = HttpTransport.from(FetchSettings.production());
        assertThatThrownBy(() -> transport.get(baseUrl + "/jwks")).isInstanceOf(Exception.class);
    }

    @Test
    void post_production_localhostBlocked() {
        HttpTransport transport = HttpTransport.from(FetchSettings.production());
        assertThatThrownBy(() -> transport.post(baseUrl + "/token", null, null))
                .isInstanceOf(Exception.class);
    }

    @Test
    void postRaw_production_localhostBlocked() {
        HttpTransport transport = HttpTransport.from(FetchSettings.production());
        assertThatThrownBy(
                        () ->
                                transport.postRaw(
                                        baseUrl + "/introspect", (Map<String, String>) null, null))
                .isInstanceOf(Exception.class);
    }

    @Test
    void get_devMode_non2xx_throwsIoException() {
        wireMock.stubFor(
                get(urlEqualTo("/fail")).willReturn(aResponse().withStatus(500).withBody("error")));

        HttpTransport transport = HttpTransport.from(FetchSettings.devMode());
        assertThatThrownBy(() -> transport.get(baseUrl + "/fail")).isInstanceOf(IOException.class);
    }
}
