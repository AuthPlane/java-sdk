package ai.authplane.sdk.core.conformance;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import ai.authplane.sdk.core.ASCredentials;
import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.TestFixtures;
import ai.authplane.sdk.core.VerifiedClaims;
import ai.authplane.sdk.core.fetching.FetchSettings;
import ai.authplane.sdk.core.fetching.HttpTransport;
import ai.authplane.sdk.core.oauth.ClientCredentialsGrant;
import ai.authplane.sdk.core.prm.ProtectedResourceMetadata;

@ConformanceSuite
class Rfc8707ConformanceTest extends AbstractPlaceholderConformanceTest {

    private static WireMockServer wireMock;
    private static String baseUrl;
    private static String tokenUrl;
    private static HttpTransport transport;
    private static TestFixtures.RSAKeyPair rsaKeys;

    @BeforeAll
    static void startWireMock() {
        rsaKeys = TestFixtures.generateRsaKeyPair();
        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();
        baseUrl = "http://localhost:" + wireMock.port();
        tokenUrl = baseUrl + "/token";
        transport = HttpTransport.from(FetchSettings.devMode());
    }

    @AfterAll
    static void stopWireMock() {
        wireMock.stop();
    }

    @BeforeEach
    void resetStubs() {
        wireMock.resetAll();
        ConformanceTestSupport.stubJwks(wireMock, "/jwks", rsaKeys);
    }

    @Test
    @ConformanceCase("rfc8707-client-credentials-resource-parameter-should-be-supported")
    void rfc8707_client_credentials_resource_parameter_should_be_supported() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")));

        assertThatCode(
                        () ->
                                ClientCredentialsGrant.execute(
                                        tokenUrl,
                                        List.of("read"),
                                        List.of("https://api.example.com"),
                                        new ASCredentials("my-client", "secret"),
                                        transport))
                .doesNotThrowAnyException();

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(containing("resource=https%3A%2F%2Fapi.example.com")));
    }

    @Test
    @ConformanceCase("rfc8707-verifier-must-accept-resource-when-present-in-aud-array")
    void rfc8707_verifier_must_accept_resource_when_present_in_aud_array() {
        ConformanceTestSupport.stubMetadata(
                wireMock, Map.of("issuer", baseUrl, "jwks_uri", baseUrl + "/jwks"));

        AuthplaneClient client =
                assertDoesNotThrow(() -> ConformanceTestSupport.buildClient(baseUrl));
        AuthplaneResource verifier =
                ConformanceTestSupport.buildVerifier(
                        client, TestFixtures.RESOURCE, List.of("read:data"));

        String token =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .issuer(baseUrl)
                        .audienceList(List.of("https://other.example.com", TestFixtures.RESOURCE))
                        .build();

        VerifiedClaims claims = assertDoesNotThrow(() -> verifier.verify(token).get().claims());

        assertThat(claims.audience()).contains(TestFixtures.RESOURCE, "https://other.example.com");
    }

    @Test
    @ConformanceCase("rfc8707-client-credentials-multiple-resource-parameters-must-be-emitted")
    void rfc8707_client_credentials_multiple_resource_parameters_must_be_emitted() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")));

        assertThatCode(
                        () ->
                                ClientCredentialsGrant.execute(
                                        tokenUrl,
                                        List.of("read"),
                                        List.of(
                                                "https://api-one.example.com",
                                                "https://api-two.example.com"),
                                        new ASCredentials("my-client", "secret"),
                                        transport))
                .doesNotThrowAnyException();

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(containing("resource=https%3A%2F%2Fapi-one.example.com"))
                        .withRequestBody(containing("resource=https%3A%2F%2Fapi-two.example.com")));
    }

    @Test
    @ConformanceCase("rfc8707-resource-indicator-must-not-contain-a-fragment")
    void rfc8707_resource_indicator_must_not_contain_a_fragment() {
        ConformanceTestSupport.stubMetadata(
                wireMock, Map.of("issuer", baseUrl, "jwks_uri", baseUrl + "/jwks"));
        AuthplaneClient client =
                assertDoesNotThrow(() -> ConformanceTestSupport.buildClient(baseUrl));

        // The case is satisfied only by a rejection observable from the construction call itself
        // (RFC 8707 §2, RFC 9728 §1.2). Asserted on the operator-facing factory, which is the
        // `resource.create` stimulus, so a gate that moved to the derivation helpers would fail
        // here rather than pass on a fragment silently dropped at prmUrl() time.
        assertThatThrownBy(
                        () ->
                                ConformanceTestSupport.buildVerifier(
                                        client,
                                        "https://api.example.com/mcp#section",
                                        List.of("read:data")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not include a fragment component");

        // Same gate on the PRM builder: an identifier reaching the document through the builder
        // rather than through a resource must not get past construction either.
        assertThatThrownBy(
                        () ->
                                ProtectedResourceMetadata.builder()
                                        .resource("https://api.example.com/mcp#section")
                                        .authorizationServer("https://auth.example.com")
                                        .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not include a fragment component");

        // A fragment-free identifier is unaffected — the gate rejects the fragment, it does not
        // narrow what a resource identifier may otherwise be.
        assertThatCode(
                        () ->
                                ConformanceTestSupport.buildVerifier(
                                        client,
                                        "https://api.example.com/mcp",
                                        List.of("read:data")))
                .doesNotThrowAnyException();
    }
}
