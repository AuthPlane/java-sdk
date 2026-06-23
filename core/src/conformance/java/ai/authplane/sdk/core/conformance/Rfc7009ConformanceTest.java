package ai.authplane.sdk.core.conformance;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import ai.authplane.sdk.core.ASCredentials;
import ai.authplane.sdk.core.fetching.FetchSettings;
import ai.authplane.sdk.core.fetching.HttpTransport;
import ai.authplane.sdk.core.oauth.Revocation;

@ConformanceSuite
class Rfc7009ConformanceTest extends AbstractPlaceholderConformanceTest {

    private static WireMockServer wireMock;
    private static String revocationUrl;
    private static HttpTransport transport;
    private static ASCredentials credentials;

    @BeforeAll
    static void startWireMock() {
        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();
        revocationUrl = "http://localhost:" + wireMock.port() + "/revoke";
        transport = HttpTransport.from(FetchSettings.devMode());
        credentials = new ASCredentials("client-id", "client-secret");
    }

    @AfterAll
    static void stopWireMock() {
        wireMock.stop();
    }

    @BeforeEach
    void resetStubs() {
        wireMock.resetAll();
    }

    @Test
    @ConformanceCase("rfc7009-revocation-200-is-success-even-for-already-invalid-token")
    void rfc7009_revocation_200_is_success_even_for_already_invalid_token() {
        wireMock.stubFor(post(urlEqualTo("/revoke")).willReturn(aResponse().withStatus(200)));

        assertThatCode(
                        () ->
                                Revocation.revoke(
                                        revocationUrl,
                                        "already-invalid",
                                        "access_token",
                                        credentials,
                                        transport))
                .doesNotThrowAnyException();
    }

    @Test
    @ConformanceCase("rfc7009-revocation-request-must-post-token-and-token-type-hint")
    void rfc7009_revocation_request_must_post_token_and_token_type_hint() {
        wireMock.stubFor(post(urlEqualTo("/revoke")).willReturn(aResponse().withStatus(200)));

        assertThatCode(
                        () ->
                                Revocation.revoke(
                                        revocationUrl,
                                        "raw-token",
                                        "access_token",
                                        credentials,
                                        transport))
                .doesNotThrowAnyException();

        wireMock.verify(
                postRequestedFor(urlEqualTo("/revoke"))
                        .withRequestBody(containing("token=raw-token"))
                        .withRequestBody(containing("token_type_hint=access_token")));
    }

    @Test
    @ConformanceCase("rfc7009-revocation-server-errors-must-surface")
    void rfc7009_revocation_server_errors_must_surface() {
        wireMock.stubFor(post(urlEqualTo("/revoke")).willReturn(aResponse().withStatus(500)));

        assertThatThrownBy(
                        () ->
                                Revocation.revoke(
                                        revocationUrl,
                                        "raw-token",
                                        "access_token",
                                        credentials,
                                        transport))
                .isInstanceOf(java.io.IOException.class)
                .hasMessageContaining("500");
    }
}
