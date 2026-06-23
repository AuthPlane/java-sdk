package ai.authplane.sdk.core.conformance;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import ai.authplane.sdk.core.ASCredentials;
import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.TestFixtures;
import ai.authplane.sdk.core.dpop.DPoPAlgorithm;
import ai.authplane.sdk.core.dpop.DPoPKeyMaterial;
import ai.authplane.sdk.core.dpop.DPoPProvider;
import ai.authplane.sdk.core.dpop.OutboundDPoPOptions;

@ConformanceSuite
class Rfc9110ConformanceTest {

    @Test
    @ConformanceCase("rfc9110-rfc9449-dpop-nonce-header-must-be-treated-case-insensitively")
    void rfc9110_rfc9449_dpop_nonce_header_must_be_treated_case_insensitively() throws Exception {
        TestFixtures.RSAKeyPair rsaKeys = TestFixtures.generateRsaKeyPair();
        TestFixtures.ECKeyPair dpopKeys = TestFixtures.generateEcKeyPair();
        WireMockServer wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();

        try {
            String baseUrl = "http://localhost:" + wireMock.port();
            ConformanceTestSupport.stubMetadata(
                    wireMock,
                    Map.of(
                            "issuer", baseUrl,
                            "jwks_uri", baseUrl + "/jwks",
                            "token_endpoint", baseUrl + "/token"));
            ConformanceTestSupport.stubJwks(wireMock, "/jwks", rsaKeys);
            wireMock.stubFor(
                    post(urlEqualTo("/token"))
                            .willReturn(
                                    aResponse()
                                            .withStatus(200)
                                            .withHeader("Content-Type", "application/json")
                                            .withHeader("dpop-nonce", "lowercase-nonce")
                                            .withBody(
                                                    "{\"access_token\":\"ok\",\"token_type\":\"DPoP\"}")));

            DPoPProvider provider =
                    new DPoPProvider(DPoPKeyMaterial.fromJwk(dpopKeys.jwk(), DPoPAlgorithm.ES256));
            try (AuthplaneClient client =
                    AuthplaneClient.builder(baseUrl)
                            .devMode(true)
                            .authProvider(new ASCredentials("client-id", "client-secret"))
                            .outboundDPoP(new OutboundDPoPOptions(provider))
                            .build()
                            .get()) {
                client.clientCredentials(List.of("read:data"), List.of()).get();
                assertThat(provider.currentNonce(baseUrl + "/token")).isEqualTo("lowercase-nonce");
            }
        } finally {
            wireMock.stop();
        }
    }
}
