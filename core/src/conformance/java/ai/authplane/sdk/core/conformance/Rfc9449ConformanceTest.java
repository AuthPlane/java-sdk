package ai.authplane.sdk.core.conformance;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ai.authplane.sdk.core.ASCredentials;
import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.ResourceOptions;
import ai.authplane.sdk.core.TestFixtures;
import ai.authplane.sdk.core.TokenResponse;
import ai.authplane.sdk.core.VerificationResult;
import ai.authplane.sdk.core.dpop.DPoPAlgorithm;
import ai.authplane.sdk.core.dpop.DPoPBindingMismatchException;
import ai.authplane.sdk.core.dpop.DPoPKeyMaterial;
import ai.authplane.sdk.core.dpop.DPoPNotSupportedException;
import ai.authplane.sdk.core.dpop.DPoPProofMissingException;
import ai.authplane.sdk.core.dpop.DPoPProvider;
import ai.authplane.sdk.core.dpop.DPoPReplayDetectedException;
import ai.authplane.sdk.core.dpop.InMemoryDPoPReplayStore;
import ai.authplane.sdk.core.dpop.InboundDPoPOptions;
import ai.authplane.sdk.core.dpop.InvalidDPoPProofException;
import ai.authplane.sdk.core.dpop.OutboundDPoPOptions;
import ai.authplane.sdk.core.dpop.VerificationRequestContext;
import ai.authplane.sdk.core.errors.InvalidClaimsException;

@ConformanceSuite
class Rfc9449ConformanceTest {

    private static WireMockServer wireMock;
    private static String baseUrl;
    private static TestFixtures.RSAKeyPair rsaKeys;
    private static TestFixtures.ECKeyPair dpopKeys;

    @BeforeAll
    static void startWireMock() {
        rsaKeys = TestFixtures.generateRsaKeyPair();
        dpopKeys = TestFixtures.generateEcKeyPair();
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
                wireMock,
                Map.of(
                        "issuer", baseUrl,
                        "jwks_uri", baseUrl + "/jwks",
                        "token_endpoint", baseUrl + "/token",
                        "introspection_endpoint", baseUrl + "/introspect",
                        "revocation_endpoint", baseUrl + "/revoke"));
        ConformanceTestSupport.stubJwks(wireMock, "/jwks", rsaKeys);
    }

    @Test
    @ConformanceCase("rfc9449-token-response-token-type-dpop-must-be-accepted")
    void rfc9449_token_response_token_type_dpop_must_be_accepted() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"dpop-token\",\"token_type\":\"DPoP\"}")));

        DPoPProvider provider = provider();
        try (AuthplaneClient client = clientWithDpop(provider)) {
            TokenResponse response =
                    client.clientCredentials(List.of("read:data"), List.of()).get();
            assertThat(response.tokenType()).isEqualTo("DPoP");
        }
    }

    @Test
    @ConformanceCase("rfc9449-dpop-grant-token-type-must-be-dpop")
    void rfc9449_dpop_grant_token_type_must_be_dpop() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")));

        DPoPProvider provider = provider();
        try (AuthplaneClient client = clientWithDpop(provider)) {
            assertThatThrownBy(
                            () -> client.clientCredentials(List.of("read:data"), List.of()).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(ai.authplane.sdk.core.errors.TokenExchangeException.class)
                    .hasMessageContaining("token_type");
        }
    }

    @Test
    @ConformanceCase("rfc9449-dpop-proof-htu-must-strip-query-and-fragment")
    void rfc9449_dpop_proof_htu_must_strip_query_and_fragment() throws Exception {
        DPoPProvider provider = provider();
        String urlWithQueryAndFragment = "https://api.example.com/resource?page=1&size=10#section";
        String proof = provider.buildHeaders("GET", urlWithQueryAndFragment).get("DPoP");
        SignedJWT jwt = SignedJWT.parse(proof);
        assertThat(jwt.getJWTClaimsSet().getStringClaim("htu"))
                .isEqualTo("https://api.example.com/resource");
    }

    @Test
    @ConformanceCase("rfc9449-dpop-provider-must-build-dpop-jwt-header")
    void rfc9449_dpop_provider_must_build_dpop_jwt_header() throws Exception {
        DPoPProvider provider = provider();
        SignedJWT jwt =
                SignedJWT.parse(provider.buildHeaders("POST", baseUrl + "/token").get("DPoP"));

        assertThat(jwt.getHeader().getType().toString()).isEqualTo("dpop+jwt");
        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
        assertThat(jwt.getHeader().getJWK()).isNotNull();
        assertThat(jwt.getHeader().getJWK().isPrivate()).isFalse();
    }

    @Test
    @ConformanceCase("rfc9449-dpop-proof-header-typ-must-be-dpop-jwt")
    void rfc9449_dpop_proof_header_typ_must_be_dpop_jwt() throws Exception {
        String token = boundToken(provider());
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);
            String proof =
                    signEcProof(
                            "JWT",
                            dpopKeys.publicJwk(),
                            "GET",
                            requestUrl(),
                            token,
                            Instant.now().getEpochSecond(),
                            Instant.now().plusSeconds(300).getEpochSecond(),
                            true,
                            true,
                            true);

            assertThatThrownBy(() -> verifier.verify(token, context(proof)).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(InvalidDPoPProofException.class)
                    .hasMessageContaining("typ");
        }
    }

    @Test
    @ConformanceCase("rfc9449-dpop-nonce-challenge-must-trigger-single-retry")
    void rfc9449_dpop_nonce_challenge_must_trigger_single_retry() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .inScenario("dpop-nonce")
                        .whenScenarioStateIs("Started")
                        .willReturn(
                                aResponse()
                                        .withStatus(400)
                                        .withHeader("Content-Type", "application/json")
                                        .withHeader("DPoP-Nonce", "nonce-123")
                                        .withBody("{\"error\":\"use_dpop_nonce\"}"))
                        .willSetStateTo("retried"));
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .inScenario("dpop-nonce")
                        .whenScenarioStateIs("retried")
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"ok\",\"token_type\":\"DPoP\"}")));

        DPoPProvider provider = provider();
        try (AuthplaneClient client = clientWithDpop(provider)) {
            TokenResponse response =
                    client.clientCredentials(List.of("read:data"), List.of()).get();
            assertThat(response.accessToken()).isEqualTo("ok");
            assertThat(provider.currentNonce(baseUrl + "/token")).isEqualTo("nonce-123");
            wireMock.verify(2, postRequestedFor(urlEqualTo("/token")));
        }
    }

    @Test
    @ConformanceCase("rfc9449-dpop-nonce-on-success-response-should-be-stored")
    void rfc9449_dpop_nonce_on_success_response_should_be_stored() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withHeader("DPoP-Nonce", "next-nonce")
                                        .withBody(
                                                "{\"access_token\":\"ok\",\"token_type\":\"DPoP\"}")));

        DPoPProvider provider = provider();
        try (AuthplaneClient client = clientWithDpop(provider)) {
            client.clientCredentials(List.of("read:data"), List.of()).get();
            assertThat(provider.currentNonce(baseUrl + "/token")).isEqualTo("next-nonce");
        }
    }

    @Test
    @ConformanceCase("rfc9449-inbound-dpop-proof-must-validate-method-url-and-binding")
    void rfc9449_inbound_dpop_proof_must_validate_method_url_and_binding() throws Exception {
        DPoPProvider provider = provider();
        String token = boundToken(provider);
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);
            String proof = provider.buildHeaders("GET", requestUrl(), token).get("DPoP");

            VerificationResult result = verifier.verify(token, context(proof)).get();
            assertThat(result.claims().dpopThumbprint())
                    .isEqualTo(provider.keyMaterial().thumbprint());
            assertThat(result.hasDpopProof()).isTrue();
            assertThat(result.dpopProof().keyThumbprint())
                    .isEqualTo(provider.keyMaterial().thumbprint());
        }
    }

    @Test
    @ConformanceCase(
            "rfc9449-bearer-token-with-request-context-and-no-proof-must-still-verify-as-bearer")
    void rfc9449_bearer_token_with_request_context_and_no_proof_must_still_verify_as_bearer()
            throws Exception {
        String token = TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).build();

        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);

            VerificationResult result =
                    verifier.verify(token, new VerificationRequestContext("GET", requestUrl()))
                            .get();

            assertThat(result.claims()).isNotNull();
            assertThat(result.claims().isDpopBound()).isFalse();
            assertThat(result.hasDpopProof()).isFalse();
        }
    }

    @Test
    @ConformanceCase(
            "rfc9449-dpop-bound-token-with-request-context-and-no-proof-must-be-rejected-via-main-verify-path")
    void
            rfc9449_dpop_bound_token_with_request_context_and_no_proof_must_be_rejected_via_main_verify_path()
                    throws Exception {
        DPoPProvider provider = provider();
        String token = boundToken(provider);

        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);

            assertThatThrownBy(
                            () ->
                                    verifier.verify(
                                                    token,
                                                    new VerificationRequestContext(
                                                            "GET", requestUrl(), List.of()))
                                            .get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(DPoPProofMissingException.class);
        }
    }

    @Test
    @ConformanceCase("rfc9449-dpop-replay-must-be-detected")
    void rfc9449_dpop_replay_must_be_detected() throws Exception {
        DPoPProvider provider = provider();
        String token = boundToken(provider);
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);
            String proof = provider.buildHeaders("GET", requestUrl(), token).get("DPoP");

            verifier.verify(token, context(proof)).get();
            assertThatThrownBy(() -> verifier.verify(token, context(proof)).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(DPoPReplayDetectedException.class);
        }
    }

    @Test
    @ConformanceCase("rfc9449-dpop-method-mismatch-must-be-rejected")
    void rfc9449_dpop_method_mismatch_must_be_rejected() throws Exception {
        DPoPProvider provider = provider();
        String token = boundToken(provider);
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);
            String proof = provider.buildHeaders("POST", requestUrl(), token).get("DPoP");

            assertThatThrownBy(() -> verifier.verify(token, context(proof)).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(InvalidDPoPProofException.class)
                    .hasMessageContaining("method mismatch");
        }
    }

    @Test
    @ConformanceCase("rfc9449-dpop-url-mismatch-must-be-rejected")
    void rfc9449_dpop_url_mismatch_must_be_rejected() throws Exception {
        DPoPProvider provider = provider();
        String token = boundToken(provider);
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);
            String proof =
                    provider.buildHeaders("GET", "https://api.example.com/other", token)
                            .get("DPoP");

            assertThatThrownBy(() -> verifier.verify(token, context(proof)).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(InvalidDPoPProofException.class)
                    .hasMessageContaining("URL mismatch");
        }
    }

    @Test
    @ConformanceCase("rfc9449-dpop-proof-exp-must-be-enforced-when-present")
    void rfc9449_dpop_proof_exp_must_be_enforced_when_present() throws Exception {
        DPoPProvider provider = provider();
        String token = boundToken(provider);
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);
            String proof =
                    signEcProof(
                            "dpop+jwt",
                            dpopKeys.publicJwk(),
                            "GET",
                            requestUrl(),
                            token,
                            Instant.now().minusSeconds(120).getEpochSecond(),
                            Instant.now().minusSeconds(60).getEpochSecond(),
                            true,
                            true,
                            true);

            assertThatThrownBy(() -> verifier.verify(token, context(proof)).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(InvalidDPoPProofException.class)
                    .hasMessageContaining("expired");
        }
    }

    @Test
    @ConformanceCase("rfc9449-generated-dpop-proof-should-include-exp")
    void rfc9449_generated_dpop_proof_should_include_exp() throws Exception {
        DPoPProvider provider = provider();
        SignedJWT jwt =
                SignedJWT.parse(provider.buildHeaders("POST", baseUrl + "/token").get("DPoP"));
        assertThat(jwt.getJWTClaimsSet().getExpirationTime()).isNotNull();
    }

    @Test
    @ConformanceCase("rfc9449-dpop-proof-must-carry-public-jwk")
    void rfc9449_dpop_proof_must_carry_public_jwk() throws Exception {
        DPoPProvider provider = provider();
        SignedJWT jwt =
                SignedJWT.parse(provider.buildHeaders("POST", baseUrl + "/token").get("DPoP"));
        assertThat(jwt.getHeader().getJWK()).isNotNull();
        assertThat(jwt.getHeader().getJWK().isPrivate()).isFalse();
    }

    @Test
    @ConformanceCase("rfc9449-dpop-proof-jwk-must-not-include-private-key-material")
    @ConformanceCoverage(
            level = ConformanceCoverageLevel.PARTIAL,
            gaps = {"expected.error_hint"},
            note =
                    "Java rejects the proof as invalid_dpop_proof but does not expose a stable private-key diagnostic independent of Nimbus parsing.")
    void rfc9449_dpop_proof_jwk_must_not_include_private_key_material() throws Exception {
        DPoPProvider provider = provider();
        String token = boundToken(provider);
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);
            String proof =
                    signEcProof(
                            "dpop+jwt",
                            dpopKeys.jwk(),
                            "GET",
                            requestUrl(),
                            token,
                            Instant.now().getEpochSecond(),
                            Instant.now().plusSeconds(300).getEpochSecond(),
                            true,
                            true,
                            true);

            assertThatThrownBy(() -> verifier.verify(token, context(proof)).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(InvalidDPoPProofException.class);
        }
    }

    @Test
    @ConformanceCase("rfc9449-dpop-proof-alg-must-be-supported-asymmetric")
    void rfc9449_dpop_proof_alg_must_be_supported_asymmetric() throws Exception {
        DPoPProvider provider = provider();
        String token = boundToken(provider);
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);
            String proof = signHs256Proof("GET", requestUrl(), token);

            assertThatThrownBy(() -> verifier.verify(token, context(proof)).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(InvalidDPoPProofException.class)
                    .hasMessageContaining("algorithm");
        }
    }

    @Test
    @ConformanceCase("rfc9449-dpop-proof-iat-must-not-be-in-the-future-beyond-leeway")
    void rfc9449_dpop_proof_iat_must_not_be_in_the_future_beyond_leeway() throws Exception {
        DPoPProvider provider = provider();
        String token = boundToken(provider);
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);
            String proof =
                    signEcProof(
                            "dpop+jwt",
                            dpopKeys.publicJwk(),
                            "GET",
                            requestUrl(),
                            token,
                            Instant.now().plusSeconds(600).getEpochSecond(),
                            Instant.now().plusSeconds(900).getEpochSecond(),
                            true,
                            true,
                            true);

            assertThatThrownBy(() -> verifier.verify(token, context(proof)).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(InvalidDPoPProofException.class)
                    .hasMessageContaining("future");
        }
    }

    @Test
    @ConformanceCase("rfc9449-dpop-proof-must-not-be-too-old")
    void rfc9449_dpop_proof_must_not_be_too_old() throws Exception {
        DPoPProvider provider = provider();
        String token = boundToken(provider);
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);
            String proof =
                    signEcProof(
                            "dpop+jwt",
                            dpopKeys.publicJwk(),
                            "GET",
                            requestUrl(),
                            token,
                            Instant.now().minusSeconds(600).getEpochSecond(),
                            Instant.now().minusSeconds(300).getEpochSecond(),
                            true,
                            true,
                            true);

            assertThatThrownBy(() -> verifier.verify(token, context(proof)).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(InvalidDPoPProofException.class)
                    .hasMessageContaining("too old");
        }
    }

    @Test
    @ConformanceCase("rfc9449-dpop-proof-required-when-validating-dpop-bound-token")
    void rfc9449_dpop_proof_required_when_validating_dpop_bound_token() throws Exception {
        DPoPProvider provider = provider();
        String token = boundToken(provider);
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);

            // 2-arg verify with context but no proof
            assertThatThrownBy(
                            () ->
                                    verifier.verify(
                                                    token,
                                                    new VerificationRequestContext(
                                                            "GET", requestUrl(), List.of()))
                                            .get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(DPoPProofMissingException.class);

            // 1-arg verify without context — must also reject DPoP-bound tokens
            assertThatThrownBy(() -> verifier.verify(token).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(DPoPProofMissingException.class);
        }
    }

    @Test
    @ConformanceCase("rfc9449-dpop-binding-mismatch-must-be-rejected")
    void rfc9449_dpop_binding_mismatch_must_be_rejected() throws Exception {
        DPoPProvider provider = provider();
        String token =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .issuer(baseUrl)
                        .claim("cnf", Map.of("jkt", "different-thumbprint"))
                        .build();
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);
            String proof = provider.buildHeaders("GET", requestUrl(), token).get("DPoP");

            assertThatThrownBy(() -> verifier.verify(token, context(proof)).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(DPoPBindingMismatchException.class);
        }
    }

    @Test
    @ConformanceCase("rfc9449-dpop-ath-mismatch-must-be-rejected")
    void rfc9449_dpop_ath_mismatch_must_be_rejected() throws Exception {
        DPoPProvider provider = provider();
        String token = boundToken(provider);
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);
            String proof =
                    signEcProof(
                            "dpop+jwt",
                            dpopKeys.publicJwk(),
                            "GET",
                            requestUrl(),
                            "different-token",
                            Instant.now().getEpochSecond(),
                            Instant.now().plusSeconds(300).getEpochSecond(),
                            true,
                            true,
                            true);

            assertThatThrownBy(() -> verifier.verify(token, context(proof)).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(InvalidDPoPProofException.class)
                    .hasMessageContaining("ath");
        }
    }

    @Test
    @ConformanceCase("rfc9449-dpop-bound-token-must-contain-cnf-jkt")
    void rfc9449_dpop_bound_token_must_contain_cnf_jkt() throws Exception {
        DPoPProvider provider = provider();
        // Token with cnf: {} (empty — no jkt). Catalog requires rejection.
        String token =
                TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).claim("cnf", Map.of()).build();
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);
            String proof = provider.buildHeaders("GET", requestUrl(), token).get("DPoP");

            assertThatThrownBy(() -> verifier.verify(token, context(proof)).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(InvalidClaimsException.class)
                    .hasMessageContaining("cnf");
        }
    }

    @Test
    @ConformanceCase(
            "rfc9449-dpop-proof-validation-must-not-skip-binding-when-access-token-is-provided")
    void rfc9449_dpop_proof_validation_must_not_skip_binding_when_access_token_is_provided()
            throws Exception {
        DPoPProvider provider = provider();
        String token = TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).build();
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);
            String proof = provider.buildHeaders("GET", requestUrl(), token).get("DPoP");

            assertThatThrownBy(() -> verifier.verify(token, context(proof)).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(DPoPBindingMismatchException.class)
                    .hasMessageContaining("cnf.jkt");
        }
    }

    @Test
    @ConformanceCase("rfc9449-dpop-proof-htm-must-be-case-sensitive")
    void rfc9449_dpop_proof_htm_must_be_case_sensitive() throws Exception {
        DPoPProvider provider = provider();
        String token = boundToken(provider);
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);
            // Build proof with lowercase "get" instead of "GET"
            String proof =
                    signEcProof(
                            "dpop+jwt",
                            dpopKeys.publicJwk(),
                            "get",
                            requestUrl(),
                            token,
                            Instant.now().getEpochSecond(),
                            Instant.now().plusSeconds(300).getEpochSecond(),
                            true,
                            true,
                            true);

            assertThatThrownBy(() -> verifier.verify(token, context(proof)).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(InvalidDPoPProofException.class)
                    .hasMessageContaining("method mismatch");
        }
    }

    @Test
    @ConformanceCase("rfc9449-dpop-proof-htu-must-be-normalized-before-comparison")
    void rfc9449_dpop_proof_htu_must_be_normalized_before_comparison() throws Exception {
        DPoPProvider provider = provider();
        String token = boundToken(provider);
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);
            // Proof uses non-normalized htu (uppercase scheme/host, default port, query)
            // which should still match after normalization
            String nonNormalizedUrl = "HTTPS://API.EXAMPLE.COM:443/tools?query=ignored";
            String proof =
                    signEcProof(
                            "dpop+jwt",
                            dpopKeys.publicJwk(),
                            "GET",
                            nonNormalizedUrl,
                            token,
                            Instant.now().getEpochSecond(),
                            Instant.now().plusSeconds(300).getEpochSecond(),
                            true,
                            true,
                            true);

            VerificationResult result = verifier.verify(token, context(proof)).get();
            assertThat(result.hasDpopProof()).isTrue();
        }
    }

    @Test
    @ConformanceCase("rfc9449-dpop-replay-store-must-evict-expired-entries")
    void rfc9449_dpop_replay_store_must_evict_expired_entries() {
        InMemoryDPoPReplayStore store = new InMemoryDPoPReplayStore();

        // Store an entry that expires in the past
        Instant past = Instant.now().minusSeconds(10);
        assertThat(store.storeIfAbsent("proof-1", past)).isTrue();

        // Store a new entry — eviction should remove proof-1
        Instant future = Instant.now().plusSeconds(300);
        assertThat(store.storeIfAbsent("proof-2", future)).isTrue();

        // proof-1 should have been evicted, so re-storing it should succeed
        assertThat(store.storeIfAbsent("proof-1", future)).isTrue();

        // proof-2 is still valid, so re-storing it should fail (replay detected)
        assertThat(store.storeIfAbsent("proof-2", future)).isFalse();
    }

    @Test
    @Disabled("Feature gap: inbound nonce enforcement is not yet implemented (RFC 9449 §8)")
    @ConformanceCase("rfc9449-dpop-inbound-nonce-must-be-validated-when-required")
    @ConformanceCoverage(
            level = ConformanceCoverageLevel.PARTIAL,
            gaps = {"inbound nonce policy not implemented"},
            note =
                    "The verifier does not yet support server-issued nonce enforcement. "
                            + "RFC 9449 §8 allows but does not require resource servers to enforce nonces.")
    void rfc9449_dpop_inbound_nonce_must_be_validated_when_required() {
        // TODO: Implement when inbound nonce enforcement is added to DPoPProofVerifier.
        // The test should verify that proofs with wrong or missing nonce are rejected
        // when the resource server has a nonce policy configured.
    }

    @Test
    @ConformanceCase("rfc9449-verifier-must-reject-bearer-only-token-when-resource-requires-dpop")
    void rfc9449_verifier_must_reject_bearer_only_token_when_resource_requires_dpop()
            throws Exception {
        // Bearer-only token (no cnf.jkt) presented to a resource that requires DPoP.
        String token = TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).build();
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = requiredVerifier(client);

            assertThatThrownBy(() -> verifier.verify(token).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(DPoPBindingMismatchException.class);
        }
    }

    @Test
    @ConformanceCase(
            "rfc9449-verifier-must-reject-dpop-bound-token-when-resource-does-not-support-dpop")
    void rfc9449_verifier_must_reject_dpop_bound_token_when_resource_does_not_support_dpop()
            throws Exception {
        DPoPProvider provider = provider();
        String token = boundToken(provider);
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            // Resource not configured for DPoP (no inboundDPoP).
            AuthplaneResource verifier =
                    client.resource(TestFixtures.RESOURCE, TestFixtures.SCOPES);

            assertThatThrownBy(() -> verifier.verify(token).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(DPoPNotSupportedException.class);
        }
    }

    @Test
    @ConformanceCase("rfc9449-verifier-must-reject-dpop-proof-when-access-token-is-not-dpop-bound")
    void rfc9449_verifier_must_reject_dpop_proof_when_access_token_is_not_dpop_bound()
            throws Exception {
        DPoPProvider provider = provider();
        // Bearer-only token, but the request carries a DPoP proof — structurally malformed.
        String token = TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).build();
        try (AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl)) {
            AuthplaneResource verifier = boundVerifier(client);
            String proof = provider.buildHeaders("GET", requestUrl(), token).get("DPoP");

            assertThatThrownBy(() -> verifier.verify(token, context(proof)).get())
                    .isInstanceOf(ExecutionException.class)
                    .cause()
                    .isInstanceOf(DPoPBindingMismatchException.class);
        }
    }

    private AuthplaneClient clientWithDpop(DPoPProvider provider) throws Exception {
        return AuthplaneClient.builder(baseUrl)
                .devMode(true)
                .authProvider(new ASCredentials("client-id", "client-secret"))
                .outboundDPoP(new OutboundDPoPOptions(provider))
                .build()
                .get();
    }

    private AuthplaneResource boundVerifier(AuthplaneClient client) {
        return client.resource(
                TestFixtures.RESOURCE,
                TestFixtures.SCOPES,
                ResourceOptions.builder()
                        .inboundDPoP(InboundDPoPOptions.defaults(new InMemoryDPoPReplayStore()))
                        .build());
    }

    /** "Required" mode verifier — DPoP-bound access tokens are mandatory. */
    private AuthplaneResource requiredVerifier(AuthplaneClient client) {
        return client.resource(
                TestFixtures.RESOURCE,
                TestFixtures.SCOPES,
                ResourceOptions.builder()
                        .inboundDPoP(
                                InboundDPoPOptions.defaults(new InMemoryDPoPReplayStore())
                                        .withRequired(true))
                        .build());
    }

    private DPoPProvider provider() {
        return new DPoPProvider(DPoPKeyMaterial.fromJwk(dpopKeys.jwk(), DPoPAlgorithm.ES256));
    }

    private String boundToken(DPoPProvider provider) {
        return TestFixtures.token()
                .rsaKey(rsaKeys)
                .issuer(baseUrl)
                .claim("cnf", Map.of("jkt", provider.keyMaterial().thumbprint()))
                .build();
    }

    private VerificationRequestContext context(String proof) {
        return new VerificationRequestContext("GET", requestUrl(), List.of(proof));
    }

    private String requestUrl() {
        return TestFixtures.RESOURCE + "/tools";
    }

    private String signEcProof(
            String typ,
            JWK headerJwk,
            String method,
            String url,
            String accessToken,
            long iat,
            long exp,
            boolean includeJti,
            boolean includeHtm,
            boolean includeHtu)
            throws Exception {
        if (headerJwk != null && headerJwk.isPrivate()) {
            String validProof =
                    signEcProof(
                            typ,
                            headerJwk.toPublicJWK(),
                            method,
                            url,
                            accessToken,
                            iat,
                            exp,
                            includeJti,
                            includeHtm,
                            includeHtu);
            return rewriteProofHeaderJwk(validProof, headerJwk.toJSONObject());
        }

        JWTClaimsSet.Builder claims =
                new JWTClaimsSet.Builder()
                        .issueTime(Date.from(Instant.ofEpochSecond(iat)))
                        .expirationTime(Date.from(Instant.ofEpochSecond(exp)));
        if (includeJti) {
            claims.claim("jti", "proof-" + iat);
        }
        if (includeHtm) {
            claims.claim("htm", method);
        }
        if (includeHtu) {
            claims.claim("htu", url);
        }
        claims.claim(
                "ath",
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                                MessageDigest.getInstance("SHA-256")
                                        .digest(accessToken.getBytes(StandardCharsets.UTF_8))));

        JWSHeader.Builder header =
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType(typ));
        if (headerJwk != null) {
            header.jwk(headerJwk);
        }

        SignedJWT jwt = new SignedJWT(header.build(), claims.build());
        jwt.sign(new ECDSASigner(dpopKeys.jwk()));
        return jwt.serialize();
    }

    private String signHs256Proof(String method, String url, String accessToken) throws Exception {
        JWTClaimsSet claims =
                new JWTClaimsSet.Builder()
                        .claim("jti", "proof-hs256")
                        .claim("htm", method)
                        .claim("htu", url)
                        .claim(
                                "ath",
                                Base64.getUrlEncoder()
                                        .withoutPadding()
                                        .encodeToString(
                                                MessageDigest.getInstance("SHA-256")
                                                        .digest(
                                                                accessToken.getBytes(
                                                                        StandardCharsets.UTF_8))))
                        .issueTime(Date.from(Instant.now()))
                        .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                        .build();

        SignedJWT jwt =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.HS256)
                                .type(new JOSEObjectType("dpop+jwt"))
                                .jwk(dpopKeys.publicJwk())
                                .build(),
                        claims);
        jwt.sign(new MACSigner("01234567890123456789012345678912"));
        return jwt.serialize();
    }

    private String rewriteProofHeaderJwk(String proof, Map<String, Object> jwk) throws Exception {
        String[] parts = proof.split("\\.");
        @SuppressWarnings("unchecked")
        Map<String, Object> header =
                (Map<String, Object>)
                        JSONObjectUtils.parse(
                                new String(
                                        Base64.getUrlDecoder().decode(addPadding(parts[0])),
                                        StandardCharsets.UTF_8));
        header.put("jwk", jwk);
        String encodedHeader =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                                TestFixtures.serializeMap(header).getBytes(StandardCharsets.UTF_8));
        return encodedHeader + "." + parts[1] + "." + parts[2];
    }

    private String addPadding(String input) {
        int pad = (4 - input.length() % 4) % 4;
        return input + "=".repeat(pad);
    }
}
