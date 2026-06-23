package ai.authplane.sdk.core.conformance;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.ResourceOptions;
import ai.authplane.sdk.core.TestFixtures;
import ai.authplane.sdk.core.VerifiedClaims;
import ai.authplane.sdk.core.errors.InvalidSignatureException;

@ConformanceSuite
class Rfc8725ConformanceTest extends AbstractPlaceholderConformanceTest {

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
    @ConformanceCase("rfc8725-allowed-jwt-algorithms-must-be-restricted")
    void rfc8725_allowed_jwt_algorithms_must_be_restricted() {
        ConformanceTestSupport.stubMetadata(
                wireMock, Map.of("issuer", baseUrl, "jwks_uri", baseUrl + "/jwks"));
        ConformanceTestSupport.stubJwks(wireMock, "/jwks", rsaKeys);

        AuthplaneClient client =
                assertDoesNotThrow(() -> ConformanceTestSupport.buildClient(baseUrl));

        assertThatThrownBy(
                        () ->
                                client.resource(
                                        TestFixtures.RESOURCE,
                                        List.of("read:data"),
                                        ResourceOptions.builder()
                                                .allowedAlgorithms(List.of("HS256"))
                                                .build()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("HS256");
    }

    @Test
    @ConformanceCase("rfc8725-kid-must-resolve-through-jwks-with-single-refresh-on-miss")
    void rfc8725_kid_must_resolve_through_jwks_with_single_refresh_on_miss() {
        Map<String, Object> initialKey = new LinkedHashMap<>(rsaKeys.publicJwkMap());
        initialKey.put("kid", "old-key");
        Map<String, Object> refreshedKey = new LinkedHashMap<>(rsaKeys.publicJwkMap());
        refreshedKey.put("kid", "rotated-key");
        ConformanceTestSupport.stubMetadata(
                wireMock, Map.of("issuer", baseUrl, "jwks_uri", baseUrl + "/jwks"));
        wireMock.stubFor(
                get(urlEqualTo("/jwks"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                TestFixtures.serializeMap(
                                                        Map.of("keys", List.of(initialKey))))));
        wireMock.resetRequests();

        AuthplaneClient client =
                assertDoesNotThrow(() -> ConformanceTestSupport.buildClient(baseUrl));
        AuthplaneResource verifier =
                ConformanceTestSupport.buildVerifier(
                        client, TestFixtures.RESOURCE, List.of("read:data"));

        wireMock.stubFor(
                get(urlEqualTo("/jwks"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                TestFixtures.serializeMap(
                                                        Map.of("keys", List.of(refreshedKey))))));

        VerifiedClaims claims =
                assertDoesNotThrow(
                        () ->
                                verifier.verify(
                                                TestFixtures.token()
                                                        .rsaKey(rsaKeys)
                                                        .issuer(baseUrl)
                                                        .kid("rotated-key")
                                                        .build())
                                        .get()
                                        .claims());

        assertThat(claims.kid()).isEqualTo("rotated-key");
        wireMock.verify(2, getRequestedFor(urlEqualTo("/jwks")));
    }

    @Test
    @ConformanceCase("rfc8725-kid-must-resolve-through-jwks-with-single-refresh-on-miss")
    void rfc8725_kid_must_resolve_through_jwks_key_still_missing() {
        ConformanceTestSupport.stubMetadata(
                wireMock, Map.of("issuer", baseUrl, "jwks_uri", baseUrl + "/jwks"));
        // Both initial and refreshed JWKS return empty keys — kid never resolves
        wireMock.stubFor(
                get(urlEqualTo("/jwks"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                TestFixtures.serializeMap(
                                                        Map.of("keys", List.of())))));

        AuthplaneClient client =
                assertDoesNotThrow(() -> ConformanceTestSupport.buildClient(baseUrl));
        AuthplaneResource verifier =
                ConformanceTestSupport.buildVerifier(
                        client, TestFixtures.RESOURCE, List.of("read:data"));

        String token =
                TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).kid("missing-key").build();

        assertThatThrownBy(() -> verifier.verify(token).get())
                .isInstanceOf(java.util.concurrent.ExecutionException.class);
    }

    @Test
    @ConformanceCase("rfc8725-jwk-selection-must-honor-use-key-ops-and-alg")
    void rfc8725_jwk_selection_must_honor_use_key_ops_and_alg() {
        ConformanceTestSupport.stubMetadata(
                wireMock, Map.of("issuer", baseUrl, "jwks_uri", baseUrl + "/jwks"));
        Map<String, Object> badKey = new LinkedHashMap<>(rsaKeys.publicJwkMap());
        badKey.put("use", "enc");
        badKey.put("key_ops", List.of("encrypt"));
        wireMock.stubFor(
                get(urlEqualTo("/jwks"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                TestFixtures.serializeMap(
                                                        Map.of("keys", List.of(badKey))))));

        AuthplaneClient client =
                assertDoesNotThrow(() -> ConformanceTestSupport.buildClient(baseUrl));
        AuthplaneResource verifier =
                ConformanceTestSupport.buildVerifier(
                        client, TestFixtures.RESOURCE, List.of("read:data"));

        assertThatThrownBy(
                        () ->
                                verifier.verify(ConformanceTestSupport.validToken(rsaKeys, baseUrl))
                                        .get())
                .hasRootCauseInstanceOf(InvalidSignatureException.class);
    }
}
