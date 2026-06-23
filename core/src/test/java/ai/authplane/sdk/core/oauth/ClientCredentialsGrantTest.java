package ai.authplane.sdk.core.oauth;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.notContaining;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import ai.authplane.sdk.core.ASCredentials;
import ai.authplane.sdk.core.AuthProvider;
import ai.authplane.sdk.core.TokenResponse;
import ai.authplane.sdk.core.errors.TokenExchangeException;
import ai.authplane.sdk.core.fetching.FetchSettings;
import ai.authplane.sdk.core.fetching.HttpTransport;

/** Unit tests for the static ClientCredentialsGrant.execute() method. */
class ClientCredentialsGrantTest {

    private static WireMockServer wireMock;
    private static String tokenUrl;
    private static HttpTransport transport;
    private static AuthProvider credentials;

    @BeforeAll
    static void startWireMock() {
        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();
        tokenUrl = "http://localhost:" + wireMock.port() + "/token";
        transport = HttpTransport.from(FetchSettings.devMode());
        credentials = new ASCredentials("my-client", "s3cret");
    }

    @AfterAll
    static void stopWireMock() {
        wireMock.stop();
    }

    @BeforeEach
    void resetStubs() {
        wireMock.resetAll();
    }

    // -----------------------------------------------------------------------
    // Success response
    // -----------------------------------------------------------------------

    @Test
    void execute_success_returnsTokenResponse() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"cc-token\",\"token_type\":\"Bearer\","
                                                        + "\"expires_in\":3600,\"scope\":\"read write\"}")));

        TokenResponse resp =
                ClientCredentialsGrant.execute(
                        tokenUrl, List.of("read write"), List.of(), credentials, transport);

        assertThat(resp.accessToken()).isEqualTo("cc-token");
        assertThat(resp.tokenType()).isEqualTo("Bearer");
        assertThat(resp.expiresIn()).isEqualTo(3600);
        assertThat(resp.scopes()).containsExactly("read", "write");
        assertThat(resp.issuedTokenType()).isNull(); // client_credentials never has this
    }

    @Test
    void execute_minimalSuccess_optionalFieldsNull() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"access_token\":\"tok\"}")));

        TokenResponse resp =
                ClientCredentialsGrant.execute(
                        tokenUrl, List.of(), List.of(), credentials, transport);

        assertThat(resp.accessToken()).isEqualTo("tok");
        assertThat(resp.tokenType()).isEqualTo("Bearer");
        assertThat(resp.expiresIn()).isNull();
        assertThat(resp.scopes()).isNull();
    }

    @Test
    void execute_negativeExpiresIn_throws() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"expires_in\":-1}")));

        assertThatThrownBy(
                        () ->
                                ClientCredentialsGrant.execute(
                                        tokenUrl, List.of(), List.of(), credentials, transport))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("expires_in");
    }

    @Test
    void execute_withResource_includesResourceInBody() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")));

        ClientCredentialsGrant.execute(
                tokenUrl,
                List.of("read"),
                List.of("https://api.example.com"),
                credentials,
                transport);

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(containing("resource=https%3A%2F%2Fapi.example.com")));
    }

    // -----------------------------------------------------------------------
    // OAuth error response
    // -----------------------------------------------------------------------

    @Test
    void execute_oauthError_throwsTokenExchangeException() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(400)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"error\":\"invalid_client\","
                                                        + "\"error_description\":\"Unknown client\"}")));

        assertThatThrownBy(
                        () ->
                                ClientCredentialsGrant.execute(
                                        tokenUrl,
                                        List.of("read"),
                                        List.of(),
                                        credentials,
                                        transport))
                .isInstanceOf(TokenExchangeException.class)
                .satisfies(
                        ex -> {
                            TokenExchangeException tee = (TokenExchangeException) ex;
                            assertThat(tee.oauthError()).isEqualTo("invalid_client");
                            assertThat(tee.getMessage()).contains("Unknown client");
                        });
    }

    @Test
    void execute_oauthErrorWithoutDescription_usesErrorAsMessage() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(400)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"error\":\"unauthorized_client\"}")));

        assertThatThrownBy(
                        () ->
                                ClientCredentialsGrant.execute(
                                        tokenUrl,
                                        List.of("read"),
                                        List.of(),
                                        credentials,
                                        transport))
                .isInstanceOf(TokenExchangeException.class)
                .satisfies(
                        ex -> {
                            TokenExchangeException tee = (TokenExchangeException) ex;
                            assertThat(tee.oauthError()).isEqualTo("unauthorized_client");
                            assertThat(tee.getMessage()).isEqualTo("unauthorized_client");
                        });
    }

    // -----------------------------------------------------------------------
    // Missing access_token
    // -----------------------------------------------------------------------

    @Test
    void execute_missingAccessToken_throws() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"token_type\":\"Bearer\"}")));

        assertThatThrownBy(
                        () ->
                                ClientCredentialsGrant.execute(
                                        tokenUrl,
                                        List.of("read"),
                                        List.of(),
                                        credentials,
                                        transport))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("access_token");
    }

    // -----------------------------------------------------------------------
    // Sends grant_type=client_credentials
    // -----------------------------------------------------------------------

    @Test
    void execute_sendsCorrectGrantType() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")));

        ClientCredentialsGrant.execute(
                tokenUrl, List.of("read"), List.of(), credentials, transport);

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(containing("grant_type=client_credentials")));
    }

    @Test
    void execute_includesScopeInBody() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")));

        ClientCredentialsGrant.execute(
                tokenUrl, List.of("read write"), List.of(), credentials, transport);

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(containing("scope=read+write")));
    }

    @Test
    void execute_nullScope_omitsScopeFromBody() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")));

        ClientCredentialsGrant.execute(tokenUrl, List.of(), List.of(), credentials, transport);

        // Verify the request body contains grant_type but NOT scope
        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(containing("grant_type=client_credentials")));
    }

    // -----------------------------------------------------------------------
    // New list-based API
    // -----------------------------------------------------------------------

    @Test
    void execute_listScopes_joinsWithSpace() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")));

        ClientCredentialsGrant.execute(
                tokenUrl, List.of("read", "write"), List.of(), credentials, transport, null);

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(containing("scope=read+write")));
    }

    @Test
    void execute_multipleResources_emitsRepeatedResourceParams() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")));

        ClientCredentialsGrant.execute(
                tokenUrl,
                List.of("read"),
                List.of("https://api1.example.com", "https://api2.example.com"),
                credentials,
                transport,
                null);

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(containing("resource=https%3A%2F%2Fapi1.example.com"))
                        .withRequestBody(containing("resource=https%3A%2F%2Fapi2.example.com")));
    }

    @Test
    void execute_emptyScopesList_omitsScopeParam() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")));

        ClientCredentialsGrant.execute(
                tokenUrl, List.of(), List.of(), credentials, transport, null);

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(containing("grant_type=client_credentials")));
        // scope should not be present
        wireMock.verify(
                postRequestedFor(urlEqualTo("/token")).withRequestBody(notContaining("scope=")));
    }

    @Test
    void execute_emptyResourcesList_omitsResourceParam() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")));

        ClientCredentialsGrant.execute(
                tokenUrl, List.of("read"), List.of(), credentials, transport, null);

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token")).withRequestBody(notContaining("resource=")));
    }

    @Test
    void execute_singleResourceList_includesResourceInBody() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")));

        ClientCredentialsGrant.execute(
                tokenUrl,
                List.of("read"),
                List.of("https://api.example.com"),
                credentials,
                transport,
                null);

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(containing("resource=https%3A%2F%2Fapi.example.com")));
    }
}
