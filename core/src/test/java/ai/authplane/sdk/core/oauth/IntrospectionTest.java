package ai.authplane.sdk.core.oauth;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import ai.authplane.sdk.core.ASCredentials;
import ai.authplane.sdk.core.fetching.FetchSettings;
import ai.authplane.sdk.core.fetching.HttpTransport;

/** Unit tests for the static Introspection methods. */
class IntrospectionTest {

    private static WireMockServer wireMock;
    private static String introspectUrl;
    private static HttpTransport transport;

    @BeforeAll
    static void startWireMock() {
        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();
        introspectUrl = "http://localhost:" + wireMock.port() + "/introspect";
        transport = HttpTransport.from(FetchSettings.devMode());
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
    // introspect() returns active=true
    // -----------------------------------------------------------------------

    @Test
    void introspect_activeTrue_returnsActiveResponse() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"active\":true,\"sub\":\"user-123\",\"scope\":\"read write\"}")));

        IntrospectionResponse resp =
                Introspection.introspect(introspectUrl, "some-token", null, transport);

        assertThat(resp.active()).isTrue();
        assertThat(resp.raw()).containsEntry("sub", "user-123");
        assertThat(resp.raw()).containsEntry("scope", "read write");
    }

    // -----------------------------------------------------------------------
    // introspect() returns active=false
    // -----------------------------------------------------------------------

    @Test
    void introspect_activeFalse_returnsInactiveResponse() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"active\":false}")));

        IntrospectionResponse resp =
                Introspection.introspect(introspectUrl, "some-token", null, transport);

        assertThat(resp.active()).isFalse();
    }

    @Test
    void introspect_activeAbsent_returnsInactive() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"sub\":\"user-123\"}")));

        IntrospectionResponse resp =
                Introspection.introspect(introspectUrl, "some-token", null, transport);

        assertThat(resp.active()).isFalse();
    }

    // -----------------------------------------------------------------------
    // introspect() surfaces RFC 9449 §6.2 cnf.jkt for DPoP-bound tokens
    // -----------------------------------------------------------------------

    @Test
    void introspect_dpopBoundToken_exposesCnfThumbprint() throws Exception {
        // RFC 9449 §6.2 Figure 11: cnf.jkt is a top-level member of the introspection response.
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"active\":true,\"token_type\":\"DPoP\","
                                                        + "\"cnf\":{\"jkt\":\"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I\"}}")));

        IntrospectionResponse resp =
                Introspection.introspect(introspectUrl, "some-token", null, transport);

        assertThat(resp.active()).isTrue();
        assertThat(resp.dpopThumbprint()).isEqualTo("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
        assertThat(resp.cnf()).containsEntry("jkt", "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
    }

    @Test
    void introspect_bearerToken_hasNoThumbprint() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"active\":true,\"sub\":\"user-123\"}")));

        IntrospectionResponse resp =
                Introspection.introspect(introspectUrl, "some-token", null, transport);

        assertThat(resp.dpopThumbprint()).isNull();
        assertThat(resp.cnf()).isEmpty();
    }

    // -----------------------------------------------------------------------
    // introspect() with credentials
    // -----------------------------------------------------------------------

    @Test
    void introspect_withCredentials_succeeds() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"active\":true}")));

        ASCredentials creds = new ASCredentials("my-client", "s3cret");
        IntrospectionResponse resp =
                Introspection.introspect(introspectUrl, "some-token", creds, transport);

        assertThat(resp.active()).isTrue();
    }
}
