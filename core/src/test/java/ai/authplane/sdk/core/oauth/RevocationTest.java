package ai.authplane.sdk.core.oauth;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import ai.authplane.sdk.core.ASCredentials;
import ai.authplane.sdk.core.fetching.FetchSettings;
import ai.authplane.sdk.core.fetching.HttpTransport;

/** Unit tests for the static Revocation.revoke() method. */
class RevocationTest {

    private static WireMockServer wireMock;
    private static String revokeUrl;
    private static HttpTransport transport;

    @BeforeAll
    static void startWireMock() {
        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();
        revokeUrl = "http://localhost:" + wireMock.port() + "/revoke";
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
    // Sends token to revocation endpoint
    // -----------------------------------------------------------------------

    @Test
    void revoke_sendsTokenInBody() throws Exception {
        wireMock.stubFor(post(urlEqualTo("/revoke")).willReturn(aResponse().withStatus(200)));

        Revocation.revoke(revokeUrl, "my-access-token", "access_token", null, transport);

        wireMock.verify(
                postRequestedFor(urlEqualTo("/revoke"))
                        .withRequestBody(containing("token=my-access-token")));
    }

    @Test
    void revoke_succeeds_noException() {
        wireMock.stubFor(post(urlEqualTo("/revoke")).willReturn(aResponse().withStatus(200)));

        assertThatCode(
                        () ->
                                Revocation.revoke(
                                        revokeUrl, "my-token", "access_token", null, transport))
                .doesNotThrowAnyException();
    }

    // -----------------------------------------------------------------------
    // With/without credentials
    // -----------------------------------------------------------------------

    @Test
    void revoke_withCredentials_sendsBasicAuth() throws Exception {
        wireMock.stubFor(post(urlEqualTo("/revoke")).willReturn(aResponse().withStatus(200)));

        ASCredentials creds = new ASCredentials("my-client", "s3cret");
        Revocation.revoke(revokeUrl, "my-token", "access_token", creds, transport);

        String encodedId = URLEncoder.encode("my-client", StandardCharsets.UTF_8);
        String encodedSecret = URLEncoder.encode("s3cret", StandardCharsets.UTF_8);
        String expected =
                "Basic "
                        + Base64.getEncoder()
                                .encodeToString(
                                        (encodedId + ":" + encodedSecret)
                                                .getBytes(StandardCharsets.UTF_8));
        wireMock.verify(
                postRequestedFor(urlEqualTo("/revoke"))
                        .withHeader("Authorization", equalTo(expected)));
    }

    @Test
    void revoke_withoutCredentials_noAuthHeader() throws Exception {
        wireMock.stubFor(post(urlEqualTo("/revoke")).willReturn(aResponse().withStatus(200)));

        Revocation.revoke(revokeUrl, "my-token", "access_token", null, transport);

        wireMock.verify(postRequestedFor(urlEqualTo("/revoke")).withoutHeader("Authorization"));
    }

    // -----------------------------------------------------------------------
    // With/without token_type_hint
    // -----------------------------------------------------------------------

    @Test
    void revoke_withTokenTypeHint_includesHintInBody() throws Exception {
        wireMock.stubFor(post(urlEqualTo("/revoke")).willReturn(aResponse().withStatus(200)));

        Revocation.revoke(revokeUrl, "my-token", "refresh_token", null, transport);

        wireMock.verify(
                postRequestedFor(urlEqualTo("/revoke"))
                        .withRequestBody(containing("token_type_hint=refresh_token")));
    }

    @Test
    void revoke_nullTokenTypeHint_omitsHintFromBody() throws Exception {
        wireMock.stubFor(post(urlEqualTo("/revoke")).willReturn(aResponse().withStatus(200)));

        Revocation.revoke(revokeUrl, "my-token", null, null, transport);

        wireMock.verify(
                postRequestedFor(urlEqualTo("/revoke"))
                        .withRequestBody(containing("token=my-token")));
        // Should not contain token_type_hint at all
    }

    @Test
    void revoke_blankTokenTypeHint_omitsHintFromBody() throws Exception {
        wireMock.stubFor(post(urlEqualTo("/revoke")).willReturn(aResponse().withStatus(200)));

        Revocation.revoke(revokeUrl, "my-token", "  ", null, transport);

        wireMock.verify(
                postRequestedFor(urlEqualTo("/revoke"))
                        .withRequestBody(containing("token=my-token")));
    }
}
