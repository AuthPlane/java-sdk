package ai.authplane.sdk.core.conformance;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

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

@ConformanceSuite
class Rfc8414ConformanceTest extends AbstractPlaceholderConformanceTest {

    private static WireMockServer wireMock;
    private static String baseUrl;
    private static TestFixtures.RSAKeyPair rsaKeys;

    @BeforeAll
    static void startWireMock() {
        rsaKeys = TestFixtures.generateRsaKeyPair();
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

    @Test
    @ConformanceCase("rfc8414-metadata-issuer-must-match-configured-issuer")
    void rfc8414_metadata_issuer_must_match_configured_issuer() {
        ConformanceTestSupport.stubMetadata(
                wireMock,
                Map.of("issuer", "https://evil.example.com", "jwks_uri", baseUrl + "/jwks"));
        ConformanceTestSupport.stubJwks(wireMock, "/jwks", rsaKeys);

        assertThatThrownBy(() -> ConformanceTestSupport.buildClient(baseUrl))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("issuer");

        // Variant: a trailing-slash difference is equivalent per RFC 3986 §6.2.3 but not
        // identical — RFC 8414 §3.3 requires identity, so it must be rejected.
        wireMock.resetAll();
        ConformanceTestSupport.stubMetadata(
                wireMock, Map.of("issuer", baseUrl + "/", "jwks_uri", baseUrl + "/jwks"));
        ConformanceTestSupport.stubJwks(wireMock, "/jwks", rsaKeys);

        assertThatThrownBy(() -> ConformanceTestSupport.buildClient(baseUrl))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("issuer");
    }

    @Test
    @ConformanceCase("rfc8414-jwks-uri-required-for-jwt-validation")
    void rfc8414_jwks_uri_required_for_jwt_validation() {
        ConformanceTestSupport.stubMetadata(wireMock, Map.of("issuer", baseUrl));

        assertThatThrownBy(() -> ConformanceTestSupport.buildClient(baseUrl))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("jwks_uri");
    }

    @Test
    @ConformanceCase("rfc8414-metadata-must-contain-issuer")
    void rfc8414_metadata_must_contain_issuer() {
        ConformanceTestSupport.stubMetadata(wireMock, Map.of("jwks_uri", baseUrl + "/jwks"));
        ConformanceTestSupport.stubJwks(wireMock, "/jwks", rsaKeys);

        assertThatThrownBy(() -> ConformanceTestSupport.buildClient(baseUrl))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("issuer");
    }

    @Test
    @ConformanceCase("rfc8414-discovery-url-must-insert-well-known-before-issuer-path")
    void rfc8414_discovery_url_must_insert_well_known_before_issuer_path() throws Exception {
        String issuerWithPath = baseUrl + "/tenant-a";

        wireMock.stubFor(
                get(urlEqualTo("/.well-known/oauth-authorization-server/tenant-a"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                TestFixtures.serializeMap(
                                                        Map.of(
                                                                "issuer",
                                                                issuerWithPath,
                                                                "jwks_uri",
                                                                baseUrl + "/jwks")))));
        ConformanceTestSupport.stubJwks(wireMock, "/jwks", rsaKeys);

        AuthplaneClient client = ConformanceTestSupport.buildClient(issuerWithPath);
        assertThat(client.issuer()).isEqualTo(issuerWithPath);
        client.close();
    }

    @Test
    @ConformanceCase("rfc8414-jwks-uri-must-be-absolute-https-url")
    void rfc8414_jwks_uri_must_be_absolute_https_url() {
        ConformanceTestSupport.stubMetadata(
                wireMock, Map.of("issuer", baseUrl, "jwks_uri", "/relative-jwks"));

        assertThatThrownBy(() -> ConformanceTestSupport.buildClient(baseUrl))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("jwks_uri");
    }

    @Test
    @ConformanceCase("rfc8414-token-endpoint-required-when-token-operation-is-used")
    void rfc8414_token_endpoint_required_when_token_operation_is_used() {
        ConformanceTestSupport.stubMetadata(
                wireMock, Map.of("issuer", baseUrl, "jwks_uri", baseUrl + "/jwks"));
        ConformanceTestSupport.stubJwks(wireMock, "/jwks", rsaKeys);

        AuthplaneClient client =
                assertDoesNotThrow(
                        () ->
                                ConformanceTestSupport.buildClient(
                                        baseUrl, new ASCredentials("client", "secret")));

        assertThatThrownBy(() -> client.clientCredentials(List.of("read"), List.of()).get())
                .isInstanceOf(ExecutionException.class)
                .hasMessageContaining("token_endpoint");
    }

    @Test
    @ConformanceCase("rfc8414-token-endpoint-must-be-absolute-https-url")
    void rfc8414_token_endpoint_must_be_absolute_https_url() {
        ConformanceTestSupport.stubMetadata(
                wireMock,
                Map.of(
                        "issuer",
                        baseUrl,
                        "jwks_uri",
                        "https://auth.example.com/jwks",
                        "token_endpoint",
                        "http://auth.example.com/oauth/token"));

        assertThatThrownBy(
                        () ->
                                ConformanceTestSupport.buildClientStrictEndpoints(
                                        baseUrl, new ASCredentials("client", "secret")))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("token_endpoint");
    }

    @Test
    @ConformanceCase("rfc8414-introspection-endpoint-must-be-absolute-https-url")
    void rfc8414_introspection_endpoint_must_be_absolute_https_url() {
        ConformanceTestSupport.stubMetadata(
                wireMock,
                Map.of(
                        "issuer",
                        baseUrl,
                        "jwks_uri",
                        "https://auth.example.com/jwks",
                        "introspection_endpoint",
                        "http://auth.example.com/oauth/introspect"));

        assertThatThrownBy(() -> ConformanceTestSupport.buildClientStrictEndpoints(baseUrl))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("introspection_endpoint");
    }

    @Test
    @ConformanceCase("rfc8414-revocation-endpoint-must-be-absolute-https-url")
    void rfc8414_revocation_endpoint_must_be_absolute_https_url() {
        ConformanceTestSupport.stubMetadata(
                wireMock,
                Map.of(
                        "issuer",
                        baseUrl,
                        "jwks_uri",
                        "https://auth.example.com/jwks",
                        "revocation_endpoint",
                        "http://auth.example.com/oauth/revoke"));

        assertThatThrownBy(() -> ConformanceTestSupport.buildClientStrictEndpoints(baseUrl))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("revocation_endpoint");
    }

    @Test
    @ConformanceCase("rfc8414-introspection-endpoint-required-when-introspection-is-used")
    void rfc8414_introspection_endpoint_required_when_introspection_is_used() {
        ConformanceTestSupport.stubMetadata(
                wireMock, Map.of("issuer", baseUrl, "jwks_uri", baseUrl + "/jwks"));
        ConformanceTestSupport.stubJwks(wireMock, "/jwks", rsaKeys);

        AuthplaneClient client =
                assertDoesNotThrow(() -> ConformanceTestSupport.buildClient(baseUrl));

        assertThatThrownBy(() -> client.introspect("raw-token").get())
                .isInstanceOf(ExecutionException.class)
                .hasMessageContaining("introspection_endpoint");
    }

    @Test
    @ConformanceCase("rfc8414-revocation-endpoint-required-when-revocation-is-used")
    void rfc8414_revocation_endpoint_required_when_revocation_is_used() {
        ConformanceTestSupport.stubMetadata(
                wireMock, Map.of("issuer", baseUrl, "jwks_uri", baseUrl + "/jwks"));
        ConformanceTestSupport.stubJwks(wireMock, "/jwks", rsaKeys);

        AuthplaneClient client =
                assertDoesNotThrow(() -> ConformanceTestSupport.buildClient(baseUrl));

        assertThatThrownBy(() -> client.revoke("raw-token").get())
                .isInstanceOf(ExecutionException.class)
                .hasMessageContaining("revocation_endpoint");
    }

    @Test
    @ConformanceCase("rfc8414-jwks-uri-rotation-must-reconfigure-jwks-cache")
    void rfc8414_jwks_uri_rotation_must_reconfigure_jwks_cache() {
        TestFixtures.RSAKeyPair rotatedKeys = TestFixtures.generateRsaKeyPair();
        ConformanceTestSupport.stubMetadata(
                wireMock, Map.of("issuer", baseUrl, "jwks_uri", baseUrl + "/jwks-1"));
        ConformanceTestSupport.stubJwks(wireMock, "/jwks-1", rsaKeys);
        ConformanceTestSupport.stubJwks(wireMock, "/jwks-2", rotatedKeys);

        AuthplaneClient client =
                assertDoesNotThrow(() -> ConformanceTestSupport.buildClient(baseUrl));
        AuthplaneResource verifier =
                ConformanceTestSupport.buildVerifier(
                        client, TestFixtures.RESOURCE, List.of("read:data"));

        VerifiedClaims initialClaims =
                assertDoesNotThrow(
                        () ->
                                verifier.verify(ConformanceTestSupport.validToken(rsaKeys, baseUrl))
                                        .get()
                                        .claims());
        assertThat(initialClaims.kid()).isEqualTo(TestFixtures.KID);

        ConformanceTestSupport.stubMetadata(
                wireMock, Map.of("issuer", baseUrl, "jwks_uri", baseUrl + "/jwks-2"));

        assertDoesNotThrow(() -> ConformanceTestSupport.forceMetadataRefresh(client));

        VerifiedClaims rotatedClaims =
                assertDoesNotThrow(
                        () ->
                                verifier.verify(
                                                ConformanceTestSupport.validToken(
                                                        rotatedKeys, baseUrl))
                                        .get()
                                        .claims());
        assertThat(rotatedClaims.kid()).isEqualTo(TestFixtures.KID);
    }
}
