package ai.authplane.sdk.core.conformance;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
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
import ai.authplane.sdk.core.ResourceOptions;
import ai.authplane.sdk.core.TestFixtures;
import ai.authplane.sdk.core.errors.TokenRevokedException;
import ai.authplane.sdk.core.fetching.FetchSettings;
import ai.authplane.sdk.core.fetching.HttpTransport;
import ai.authplane.sdk.core.oauth.Introspection;
import ai.authplane.sdk.core.oauth.IntrospectionResponse;

@ConformanceSuite
class Rfc7662ConformanceTest extends AbstractPlaceholderConformanceTest {

    private static WireMockServer wireMock;
    private static String baseUrl;
    private static String introspectUrl;
    private static HttpTransport transport;
    private static TestFixtures.RSAKeyPair rsaKeys;

    @BeforeAll
    static void startWireMock() {
        rsaKeys = TestFixtures.generateRsaKeyPair();
        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();
        baseUrl = "http://localhost:" + wireMock.port();
        introspectUrl = baseUrl + "/introspect";
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
    @ConformanceCase("rfc7662-introspection-request-must-post-token-and-access-token-hint")
    void rfc7662_introspection_request_must_post_token_and_access_token_hint() {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"active\":true}")));

        IntrospectionResponse response =
                assertDoesNotThrow(
                        () ->
                                Introspection.introspect(
                                        introspectUrl, "raw-token", null, transport));

        assertThat(response.active()).isTrue();
        wireMock.verify(
                postRequestedFor(urlEqualTo("/introspect"))
                        .withRequestBody(containing("token=raw-token"))
                        .withRequestBody(containing("token_type_hint=access_token")));
    }

    @Test
    @ConformanceCase("rfc7662-introspection-without-credentials-must-not-send-authorization-header")
    void rfc7662_introspection_without_credentials_must_not_send_authorization_header() {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"active\":true}")));

        assertDoesNotThrow(
                () -> Introspection.introspect(introspectUrl, "raw-token", null, transport));

        wireMock.verify(postRequestedFor(urlEqualTo("/introspect")).withoutHeader("Authorization"));
    }

    @Test
    @ConformanceCase("rfc7662-introspection-basic-auth-must-be-supported")
    void rfc7662_introspection_basic_auth_must_be_supported() {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"active\":true}")));

        ASCredentials credentials = new ASCredentials("client-id", "client-secret");
        IntrospectionResponse response =
                assertDoesNotThrow(
                        () ->
                                Introspection.introspect(
                                        introspectUrl, "raw-token", credentials, transport));

        assertThat(response.active()).isTrue();
        String encodedId = URLEncoder.encode("client-id", StandardCharsets.UTF_8);
        String encodedSecret = URLEncoder.encode("client-secret", StandardCharsets.UTF_8);
        String expected =
                "Basic "
                        + Base64.getEncoder()
                                .encodeToString(
                                        (encodedId + ":" + encodedSecret)
                                                .getBytes(StandardCharsets.UTF_8));
        wireMock.verify(
                postRequestedFor(urlEqualTo("/introspect"))
                        .withHeader("Authorization", equalTo(expected)));
    }

    @Test
    @ConformanceCase("rfc7662-introspection-active-false-must-parse-as-inactive")
    void rfc7662_introspection_active_false_must_parse_as_inactive() {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"active\":false}")));

        IntrospectionResponse response =
                assertDoesNotThrow(
                        () ->
                                Introspection.introspect(
                                        introspectUrl, "raw-token", null, transport));

        assertThat(response.active()).isFalse();
    }

    @Test
    @ConformanceCase("rfc7662-introspection-missing-active-must-default-to-inactive")
    void rfc7662_introspection_missing_active_must_default_to_inactive() {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"error\":\"invalid_token\"}")));

        IntrospectionResponse response =
                assertDoesNotThrow(
                        () ->
                                Introspection.introspect(
                                        introspectUrl, "raw-token", null, transport));

        assertThat(response.active()).isFalse();
    }

    @Test
    @ConformanceCase("rfc7662-introspection-standard-fields-must-round-trip")
    void rfc7662_introspection_standard_fields_must_round_trip() {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                """
                    {"active":true,"sub":"user-123","client_id":"client-abc","scope":"read write","iss":"https://auth.example.com","token_type":"Bearer","aud":"https://api.example.com","exp":1735689600,"iat":1735686000,"jti":"unique-id-001"}
                    """)));

        IntrospectionResponse response =
                assertDoesNotThrow(
                        () ->
                                Introspection.introspect(
                                        introspectUrl, "raw-token", null, transport));

        assertThat(response.raw()).containsEntry("sub", "user-123");
        assertThat(response.raw()).containsEntry("client_id", "client-abc");
        assertThat(response.raw()).containsEntry("scope", "read write");
        assertThat(response.raw()).containsEntry("iss", "https://auth.example.com");
        assertThat(response.raw()).containsEntry("token_type", "Bearer");
        assertThat(response.raw()).containsEntry("aud", "https://api.example.com");
        assertThat(response.raw()).containsKey("exp");
        assertThat(response.raw()).containsKey("iat");
        assertThat(response.raw()).containsEntry("jti", "unique-id-001");
    }

    // No @ConformanceCase: the catalog has no case for the introspection response exposing
    // cnf.jkt. Its only cnf.jkt case, rfc9449-dpop-bound-token-must-contain-cnf-jkt, covers the
    // verifier rejecting a DPoP-bound token that lacks the claim (mapped in
    // Rfc9449ConformanceTest) — a different requirement. Kept as SDK-side coverage of RFC 9449
    // §6.2 Figure 11, reported under uncatalogued tests.
    @Test
    void rfc9449_introspection_response_must_expose_cnf_jkt() {
        // RFC 9449 §6.2 Figure 11: cnf.jkt is a top-level member of the introspection response.
        // The SDK introspection result type must expose that thumbprint without forcing callers
        // to re-parse raw().
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"active\":true,\"token_type\":\"DPoP\","
                                                        + "\"cnf\":{\"jkt\":\"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I\"}}")));

        IntrospectionResponse response =
                assertDoesNotThrow(
                        () ->
                                Introspection.introspect(
                                        introspectUrl, "raw-token", null, transport));

        assertThat(response.active()).isTrue();
        assertThat(response.dpopThumbprint())
                .isEqualTo("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
        assertThat(response.cnf())
                .containsEntry("jkt", "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
    }

    @Test
    @ConformanceCase("rfc7662-verifier-active-false-must-reject-token")
    void rfc7662_verifier_active_false_must_reject_token() {
        ConformanceTestSupport.stubMetadata(
                wireMock,
                Map.of(
                        "issuer", baseUrl,
                        "jwks_uri", baseUrl + "/jwks",
                        "introspection_endpoint", baseUrl + "/introspect"));
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"active\":false}")));

        assertThatThrownBy(
                        () -> {
                            AuthplaneClient client = ConformanceTestSupport.buildClient(baseUrl);
                            AuthplaneResource verifier =
                                    ConformanceTestSupport.buildVerifier(
                                            client,
                                            TestFixtures.RESOURCE,
                                            List.of("read:data"),
                                            ResourceOptions.builder()
                                                    .useBuiltinRevocationChecker()
                                                    .build());
                            verifier.verify(ConformanceTestSupport.validToken(rsaKeys, baseUrl))
                                    .get();
                        })
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(TokenRevokedException.class);
    }

    @Test
    @ConformanceCase("rfc7662-introspection-fail-open-policy-must-be-explicitly-tested")
    void rfc7662_introspection_fail_open_policy_must_be_explicitly_tested() {
        ConformanceTestSupport.stubMetadata(
                wireMock,
                Map.of(
                        "issuer", baseUrl,
                        "jwks_uri", baseUrl + "/jwks",
                        "introspection_endpoint", baseUrl + "/introspect"));
        wireMock.stubFor(post(urlEqualTo("/introspect")).willReturn(aResponse().withStatus(500)));

        AuthplaneClient client =
                assertDoesNotThrow(() -> ConformanceTestSupport.buildClient(baseUrl));
        AuthplaneResource verifier =
                ConformanceTestSupport.buildVerifier(
                        client,
                        TestFixtures.RESOURCE,
                        List.of("read:data"),
                        ResourceOptions.builder().useBuiltinRevocationChecker().build());

        assertThat(
                        assertDoesNotThrow(
                                        () ->
                                                verifier.verify(
                                                                ConformanceTestSupport.validToken(
                                                                        rsaKeys, baseUrl))
                                                        .get()
                                                        .claims())
                                .jti())
                .isEqualTo(TestFixtures.JTI);
    }

    @Test
    @ConformanceCase("rfc7662-introspection-audience-must-parse-string-or-array")
    void rfc7662_introspection_audience_must_parse_string_or_array() {
        // Sub-case 1: aud as a JSON string
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"active\":true,\"aud\":\"https://api.example.com\"}")));

        IntrospectionResponse stringResp =
                assertDoesNotThrow(
                        () ->
                                Introspection.introspect(
                                        introspectUrl, "raw-token", null, transport));
        assertThat(stringResp.active()).isTrue();
        assertThat(stringResp.raw().get("aud")).isInstanceOf(String.class);
        assertThat((String) stringResp.raw().get("aud")).isEqualTo("https://api.example.com");

        wireMock.resetAll();

        // Sub-case 2: aud as a JSON array
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"active\":true,\"aud\":[\"https://api.example.com\","
                                                        + "\"https://other.example.com\"]}")));

        IntrospectionResponse arrayResp =
                assertDoesNotThrow(
                        () ->
                                Introspection.introspect(
                                        introspectUrl, "raw-token", null, transport));
        assertThat(arrayResp.active()).isTrue();
        assertThat(arrayResp.raw().get("aud")).isInstanceOf(List.class);
        @SuppressWarnings("unchecked")
        List<String> audList = (List<String>) arrayResp.raw().get("aud");
        assertThat(audList).containsExactly("https://api.example.com", "https://other.example.com");
    }
}
