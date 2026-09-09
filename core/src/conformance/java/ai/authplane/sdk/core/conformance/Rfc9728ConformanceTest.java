package ai.authplane.sdk.core.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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

        // Catalog variant: a resource identifier published with a terminating slash serves its
        // metadata at the slash-less well-known path, so identifiers differing only by that slash
        // resolve to the same document (RFC 9728 §3.1).
        assertThat(
                        ProtectedResourceMetadata.wellKnownPath(
                                URI.create("https://api.example.com/mcp/")))
                .isEqualTo("/.well-known/oauth-protected-resource/mcp");
    }

    @Test
    @ConformanceCase("rfc9728-well-known-url-must-preserve-the-resource-query-component")
    void rfc9728_well_known_url_must_preserve_the_resource_query_component() {
        // RFC 9728 §3 inserts the well-known string "between the host component and the path
        // and/or query components", so the query survives the derivation. The stimulus is the
        // full URL rather than the path, because a path-only accessor cannot express a query.
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://api.example.com/mcp?tenant=a"))
                .isEqualTo(
                        "https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a");

        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://api.example.com/mcp?tenant=b"))
                .isEqualTo(
                        "https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=b");

        // No path and no terminating slash: §3.1 has no slash to remove, so the suffix goes
        // directly after the host and the query follows it.
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://api.example.com?x=1"))
                .isEqualTo("https://api.example.com/.well-known/oauth-protected-resource?x=1");

        // The point of the case: two identifiers differing only by query must not collapse onto
        // one metadata document URL, which is what makes every tenant on a host distinct.
        assertThat(ProtectedResourceMetadata.wellKnownUrl("https://api.example.com/mcp?tenant=a"))
                .isNotEqualTo(
                        ProtectedResourceMetadata.wellKnownUrl(
                                "https://api.example.com/mcp?tenant=b"));
    }

    @Test
    @ConformanceCase("rfc9728-resource-identifier-must-be-an-absolute-url-with-scheme-and-host")
    @ConformanceCoverage(
            level = ConformanceCoverageLevel.PARTIAL,
            gaps = {
                "the host half is not gated at construction: \"https:example.com/mcp\" carries a"
                        + " scheme and no authority, and is refused only at derivation"
            },
            note =
                    "Both values the case exercises are now rejected from the resource factory and"
                            + " from the PRM builder, by requireScheme. PARTIAL rather than FULL"
                            + " because the requirement is scheme *and* host and only the scheme"
                            + " half is enforced where the stimulus points: an identifier with a"
                            + " scheme but no authority still constructs and throws later, on the"
                            + " 401 challenge path, which is the shape of failure moving these"
                            + " gates to construction was meant to remove.")
    void rfc9728_resource_identifier_must_be_an_absolute_url_with_scheme_and_host() {
        // Each value rejects on its own — the case is explicit that rejecting one does not satisfy
        // it, because a guard that only asks "opaque or authority-less?" catches "/mcp" while
        // letting the scheme-relative form through.
        for (String identifier : List.of("/mcp", "//api.example.com/mcp")) {
            assertThatThrownBy(() -> ProtectedResourceMetadata.requireScheme(identifier))
                    .isInstanceOf(IllegalArgumentException.class);

            assertThatThrownBy(
                            () ->
                                    ProtectedResourceMetadata.builder()
                                            .resource(identifier)
                                            .authorizationServer(TestFixtures.ISSUER)
                                            .build())
                    .isInstanceOf(IllegalArgumentException.class);
        }

        // Scheme-and-host, not https-only: local development loops depend on this one constructing.
        assertDoesNotThrow(
                () ->
                        ProtectedResourceMetadata.builder()
                                .resource("http://localhost:8080/mcp")
                                .authorizationServer(TestFixtures.ISSUER)
                                .build());
    }
}
