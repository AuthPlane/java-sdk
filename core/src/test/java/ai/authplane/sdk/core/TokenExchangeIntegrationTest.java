package ai.authplane.sdk.core;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.concurrent.ExecutionException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import ai.authplane.sdk.core.errors.TokenExchangeException;

/**
 * End-to-end integration tests for {@link AuthplaneClient#exchange(TokenExchangeOptions)}.
 *
 * <p>Uses WireMock to stub the metadata, JWKS, and token endpoints so the full build + exchange
 * path is exercised through a real AuthplaneClient instance.
 */
class TokenExchangeIntegrationTest {

    private static WireMockServer wireMock;
    private static String baseUrl;
    private static TestFixtures.RSAKeyPair rsaKeys;

    @BeforeAll
    static void setup() {
        rsaKeys = TestFixtures.generateRsaKeyPair();
        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();
        baseUrl = "http://localhost:" + wireMock.port();
    }

    @AfterAll
    static void teardown() {
        wireMock.stop();
    }

    @BeforeEach
    void resetAndStubJwks() {
        wireMock.resetAll();
        wireMock.stubFor(
                get(urlEqualTo("/jwks"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(TestFixtures.jwksJson(rsaKeys.jwksDocument()))));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /** Creates an AuthplaneClient with full metadata discovery via WireMock. */
    private AuthplaneClient buildClient() throws Exception {
        stubMetadata();
        return AuthplaneClient.builder(baseUrl).devMode(true).build().get();
    }

    private void stubMetadata() {
        wireMock.stubFor(
                get(urlEqualTo("/.well-known/oauth-authorization-server"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"issuer\":\""
                                                        + baseUrl
                                                        + "\","
                                                        + "\"jwks_uri\":\""
                                                        + baseUrl
                                                        + "/jwks\","
                                                        + "\"token_endpoint\":\""
                                                        + baseUrl
                                                        + "/token\"}")));
    }

    // -----------------------------------------------------------------------
    // Happy path — full exchange through AuthplaneClient
    // -----------------------------------------------------------------------

    @Test
    void exchange_happyPath_returnsTokenResponse() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"exchanged-token\",\"token_type\":\"Bearer\","
                                                        + "\"expires_in\":1800,\"scope\":\"tools/add\","
                                                        + "\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        AuthplaneClient client = buildClient();

        TokenResponse resp =
                client.exchange(
                                TokenExchangeOptions.builder("user-subject-token")
                                        .scope(List.of("tools/add"))
                                        .resource(TestFixtures.RESOURCE)
                                        .build())
                        .get();

        assertThat(resp.accessToken()).isEqualTo("exchanged-token");
        assertThat(resp.tokenType()).isEqualTo("Bearer");
        assertThat(resp.expiresIn()).isEqualTo(1800);
        assertThat(resp.scopes()).containsExactly("tools/add");
    }

    // -----------------------------------------------------------------------
    // OAuth error response — exception carries oauthError code
    // -----------------------------------------------------------------------

    @Test
    void exchange_invalidGrant_throwsTokenExchangeExceptionWithCode() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(400)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"error\":\"invalid_grant\","
                                                        + "\"error_description\":\"subject token expired\"}")));

        AuthplaneClient client = buildClient();

        assertThatThrownBy(
                        () ->
                                client.exchange(
                                                TokenExchangeOptions.builder("expired-token")
                                                        .build())
                                        .get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(TokenExchangeException.class)
                .satisfies(
                        ex -> {
                            TokenExchangeException tee = (TokenExchangeException) ex;
                            assertThat(tee.oauthError()).isEqualTo("invalid_grant");
                            assertThat(tee.getMessage()).contains("expired");
                        });
    }

    // -----------------------------------------------------------------------
    // asCredentials + introspection — both share the same credentials
    // -----------------------------------------------------------------------

    @Test
    void exchange_withAsCredentials_metadataFetched_exchangeSucceeds() throws Exception {
        stubMetadata();
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"cred-token\",\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        AuthplaneClient client =
                AuthplaneClient.builder(baseUrl)
                        .devMode(true)
                        .authProvider(new ASCredentials("client-id", "client-secret"))
                        .build()
                        .get();

        TokenResponse resp =
                client.exchange(TokenExchangeOptions.builder("user-token").build()).get();

        assertThat(resp.accessToken()).isEqualTo("cred-token");
    }
}
