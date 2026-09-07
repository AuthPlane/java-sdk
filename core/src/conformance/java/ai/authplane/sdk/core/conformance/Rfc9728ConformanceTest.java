package ai.authplane.sdk.core.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.net.URI;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
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
    @Disabled(
            "Feature gap: no construction-time scheme-and-host gate exists. The absoluteness axis"
                    + " was held out when the fragment and query gates landed, pending a decision"
                    + " that has not been taken, and taking it is not part of adopting the catalog"
                    + " case.")
    @ConformanceCase("rfc9728-resource-identifier-must-be-an-absolute-url-with-scheme-and-host")
    @ConformanceCoverage(
            level = ConformanceCoverageLevel.NONE,
            gaps = {
                "\"/mcp\" is accepted at construction; it is refused only at derivation",
                "\"//api.example.com/mcp\" is accepted at construction and at derivation"
            },
            note =
                    "Neither setup value is rejected at the point the resource is constructed, so"
                            + " the case is unsatisfied on both. requireDerivable in"
                            + " ProtectedResourceMetadata asks only whether the identifier is"
                            + " opaque or authority-less and never checks the scheme, and it runs"
                            + " from wellKnownPath rather than from any construction boundary."
                            + " \"/mcp\" therefore throws at derivation, on the 401 challenge path,"
                            + " not from the constructor the stimulus names; and"
                            + " \"//api.example.com/mcp\" parses with a non-empty authority, so it"
                            + " clears that guard entirely and derives the literal"
                            + " \"null://api.example.com/.well-known/oauth-protected-resource/mcp\"."
                            + " Adding the gate is a behaviour change with its own decision to"
                            + " make, so this case is registered as skipped rather than marked"
                            + " covered.")
    void rfc9728_resource_identifier_must_be_an_absolute_url_with_scheme_and_host() {
        // Intentionally empty: implementing the construction-time gate this case asserts is a
        // behaviour change that is out of scope for adopting the catalog case. When it lands, the
        // body must assert that each setup value — "/mcp" and "//api.example.com/mcp" — is
        // rejected on its own from the resource factory and the PRM builder, and that
        // "http://localhost:8080/mcp" still constructs (the case is scheme-and-host, not
        // https-only).
    }
}
