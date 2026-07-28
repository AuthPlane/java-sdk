package ai.authplane.sdk.core.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.net.URI;
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
import ai.authplane.sdk.core.dpop.InMemoryDPoPReplayStore;
import ai.authplane.sdk.core.dpop.InboundDPoPOptions;
import ai.authplane.sdk.core.prm.ProtectedResourceMetadata;

@ConformanceSuite
class Rfc9728ConformanceTest extends AbstractPlaceholderConformanceTest {

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
        ConformanceTestSupport.stubMetadata(
                wireMock, Map.of("issuer", baseUrl, "jwks_uri", baseUrl + "/jwks"));
        ConformanceTestSupport.stubJwks(wireMock, "/jwks", rsaKeys);
    }

    private AuthplaneResource verifier() throws Exception {
        AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl);
        return ConformanceTestSupport.buildVerifier(
                client,
                TestFixtures.RESOURCE,
                List.of("read:data", "write:data"),
                ResourceOptions.builder().allowedAlgorithms(List.of("RS256", "ES256")).build());
    }

    @Test
    @ConformanceCase("rfc9728-prm-must-contain-required-fields")
    void rfc9728_prm_must_contain_required_fields() {
        Map<String, Object> prm = assertDoesNotThrow(() -> verifier().prmResponse());

        assertThat(prm)
                .containsKeys(
                        "resource",
                        "authorization_servers",
                        "bearer_methods_supported",
                        "scopes_supported");
    }

    @Test
    @ConformanceCase("rfc9728-prm-authorization-servers-must-list-the-issuer")
    void rfc9728_prm_authorization_servers_must_list_the_issuer() {
        Map<String, Object> prm = assertDoesNotThrow(() -> verifier().prmResponse());

        assertThat((List<String>) prm.get("authorization_servers")).containsExactly(baseUrl);
    }

    @Test
    @ConformanceCase("rfc9728-prm-supported-bearer-methods-should-be-stable")
    void rfc9728_prm_supported_bearer_methods_should_be_stable() {
        Map<String, Object> prm = assertDoesNotThrow(() -> verifier().prmResponse());

        assertThat((List<String>) prm.get("bearer_methods_supported")).containsExactly("header");
    }

    @Test
    @ConformanceCase("rfc9728-prm-dpop-fields-should-be-advertised-when-dpop-is-supported")
    void rfc9728_prm_dpop_fields_should_be_advertised_when_dpop_is_supported() throws Exception {
        AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl);
        AuthplaneResource dpopVerifier =
                ConformanceTestSupport.buildVerifier(
                        client,
                        TestFixtures.RESOURCE,
                        List.of("read:data"),
                        ResourceOptions.builder()
                                .allowedAlgorithms(List.of("RS256", "ES256"))
                                .inboundDPoP(
                                        InboundDPoPOptions.defaults(new InMemoryDPoPReplayStore()))
                                .build());

        Map<String, Object> prm = dpopVerifier.prmResponse();

        assertThat(prm).containsKey("dpop_signing_alg_values_supported");
        @SuppressWarnings("unchecked")
        List<String> dpopAlgs = (List<String>) prm.get("dpop_signing_alg_values_supported");
        assertThat(dpopAlgs).containsExactlyInAnyOrder("RS256", "ES256");
    }

    @Test
    @ConformanceCase("rfc9728-prm-must-advertise-dpop-required-when-resource-requires-dpop")
    void rfc9728_prm_must_advertise_dpop_required_when_resource_requires_dpop() throws Exception {
        AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl);
        AuthplaneResource requiredVerifier =
                ConformanceTestSupport.buildVerifier(
                        client,
                        TestFixtures.RESOURCE,
                        List.of("read:data"),
                        ResourceOptions.builder()
                                .allowedAlgorithms(List.of("RS256", "ES256"))
                                .inboundDPoP(
                                        InboundDPoPOptions.defaults(new InMemoryDPoPReplayStore())
                                                .withRequired(true))
                                .build());

        Map<String, Object> prm = requiredVerifier.prmResponse();

        assertThat(prm).containsEntry("dpop_bound_access_tokens_required", true);
    }

    @Test
    @ConformanceCase("rfc9728-well-known-path-must-derive-from-resource-uri")
    void rfc9728_well_known_path_must_derive_from_resource_uri() {
        assertThat(ProtectedResourceMetadata.wellKnownPath(URI.create("https://api.example.com")))
                .isEqualTo("/.well-known/oauth-protected-resource");

        assertThat(
                        ProtectedResourceMetadata.wellKnownPath(
                                URI.create("https://api.example.com/mcp")))
                .isEqualTo("/.well-known/oauth-protected-resource/mcp");

        assertThat(
                        ProtectedResourceMetadata.wellKnownPath(
                                URI.create("https://api.example.com/v2/mcp")))
                .isEqualTo("/.well-known/oauth-protected-resource/v2/mcp");

        // RFC 9728 §3 insertion preserves the path exactly, including a trailing slash.
        assertThat(
                        ProtectedResourceMetadata.wellKnownPath(
                                URI.create("https://api.example.com/mcp/")))
                .isEqualTo("/.well-known/oauth-protected-resource/mcp/");
    }
}
