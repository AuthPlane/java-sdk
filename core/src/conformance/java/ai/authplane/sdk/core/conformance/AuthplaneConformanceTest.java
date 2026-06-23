package ai.authplane.sdk.core.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

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
import ai.authplane.sdk.core.TestFixtures;
import ai.authplane.sdk.core.VerifiedClaims;

@ConformanceSuite
class AuthplaneConformanceTest extends AbstractPlaceholderConformanceTest {

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
                client, TestFixtures.RESOURCE, List.of("read:data"));
    }

    @Test
    @ConformanceCase("authplane-agent-id-must-be-exposed-as-first-class-field")
    void authplane_agent_id_must_be_exposed_as_first_class_field() {
        AuthplaneResource resource = assertDoesNotThrow(this::verifier);

        // Token with agent_id present → exposed as first-class field
        String tokenWithAgentId =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .issuer(baseUrl)
                        .claim("agent_id", "research-agent")
                        .build();
        VerifiedClaims claimsWithId =
                assertDoesNotThrow(() -> resource.verify(tokenWithAgentId).get().claims());
        assertThat(claimsWithId.agentId()).isEqualTo("research-agent");

        // Token without agent_id → defaults to empty string (never null)
        String tokenWithoutAgentId = TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).build();
        VerifiedClaims claimsWithoutId =
                assertDoesNotThrow(() -> resource.verify(tokenWithoutAgentId).get().claims());
        assertThat(claimsWithoutId.agentId()).isEqualTo("");
    }

    @Test
    @ConformanceCase("authplane-agent-chain-must-be-exposed-as-first-class-field")
    void authplane_agent_chain_must_be_exposed_as_first_class_field() {
        AuthplaneResource resource = assertDoesNotThrow(this::verifier);

        // Token with agent_chain present → exposed as typed list field
        String tokenWithChain =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .issuer(baseUrl)
                        .claim(
                                "agent_chain",
                                List.of("orchestrator", "research-agent", "summarizer"))
                        .build();
        VerifiedClaims claimsWithChain =
                assertDoesNotThrow(() -> resource.verify(tokenWithChain).get().claims());
        assertThat(claimsWithChain.agentChain())
                .containsExactly("orchestrator", "research-agent", "summarizer");

        // Token without agent_chain → defaults to empty list (never null)
        String tokenWithoutChain = TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).build();
        VerifiedClaims claimsWithoutChain =
                assertDoesNotThrow(() -> resource.verify(tokenWithoutChain).get().claims());
        assertThat(claimsWithoutChain.agentChain()).isEmpty();
    }

    @Test
    @ConformanceCase("authplane-nbf-must-be-exposed-as-typed-field-on-verified-claims")
    void authplane_nbf_must_be_exposed_as_typed_field_on_verified_claims() {
        AuthplaneResource resource = assertDoesNotThrow(this::verifier);

        // Token with nbf present → notBefore() returns the Unix timestamp value
        long expectedNbf =
                System.currentTimeMillis() / 1000L - 60; // 60s in the past (definitely valid)
        String tokenWithNbf =
                TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).notBefore(expectedNbf).build();
        VerifiedClaims claimsWithNbf =
                assertDoesNotThrow(() -> resource.verify(tokenWithNbf).get().claims());
        assertThat(claimsWithNbf.notBefore()).isEqualTo(expectedNbf);

        // Token with nbf omitted → notBefore() returns 0L sentinel
        String tokenNoNbf = TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).omitNbf().build();
        VerifiedClaims claimsNoNbf =
                assertDoesNotThrow(() -> resource.verify(tokenNoNbf).get().claims());
        assertThat(claimsNoNbf.notBefore()).isEqualTo(0L);
    }
}
