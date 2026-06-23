package ai.authplane.sdk.core.conformance;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import ai.authplane.sdk.core.ASCredentials;
import ai.authplane.sdk.core.TokenResponse;
import ai.authplane.sdk.core.errors.TokenExchangeException;
import ai.authplane.sdk.core.fetching.FetchSettings;
import ai.authplane.sdk.core.fetching.HttpTransport;
import ai.authplane.sdk.core.oauth.ClientCredentialsGrant;

@ConformanceSuite
class Rfc6749ConformanceTest extends AbstractPlaceholderConformanceTest {

    private static WireMockServer wireMock;
    private static String tokenUrl;
    private static HttpTransport transport;
    private static ASCredentials credentials;

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

    @Test
    @ConformanceCase("rfc6749-client-credentials-success-response")
    void rfc6749_client_credentials_success_response() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                """
                    {"access_token":"cc-token","token_type":"Bearer","expires_in":3600,"scope":"read write"}
                    """)));

        TokenResponse response =
                assertDoesNotThrow(
                        () ->
                                ClientCredentialsGrant.execute(
                                        tokenUrl,
                                        List.of("read write"),
                                        List.of(),
                                        credentials,
                                        transport));

        assertThat(response.accessToken()).isEqualTo("cc-token");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresIn()).isEqualTo(3600);
        assertThat(response.scopes()).containsExactly("read", "write");
    }

    @Test
    @ConformanceCase("rfc6749-basic-auth-credentials-must-be-form-urlencoded-before-base64")
    void rfc6749_basic_auth_credentials_must_be_form_urlencoded_before_base64() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")));

        ASCredentials specialCredentials = new ASCredentials("http://localhost:8080/mcp", "s3cret");

        assertDoesNotThrow(
                () ->
                        ClientCredentialsGrant.execute(
                                tokenUrl,
                                List.of("read"),
                                List.of(),
                                specialCredentials,
                                transport));

        String encodedId = URLEncoder.encode("http://localhost:8080/mcp", StandardCharsets.UTF_8);
        String encodedSecret = URLEncoder.encode("s3cret", StandardCharsets.UTF_8);
        String expected =
                "Basic "
                        + Base64.getEncoder()
                                .encodeToString(
                                        (encodedId + ":" + encodedSecret)
                                                .getBytes(StandardCharsets.UTF_8));

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withHeader("Authorization", equalTo(expected)));
    }

    @Test
    @ConformanceCase("rfc6749-token-response-must-contain-access-token")
    void rfc6749_token_response_must_contain_access_token() {
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

    @Test
    @ConformanceCase("rfc6749-token-response-token-type-must-be-supported")
    void rfc6749_token_response_token_type_must_be_supported() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"N_A\"}")));

        assertThatThrownBy(
                        () ->
                                ClientCredentialsGrant.execute(
                                        tokenUrl, List.of(), List.of(), credentials, transport))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("token_type");
    }

    @Test
    @ConformanceCase("rfc6749-token-response-expires-in-must-be-non-negative-integer")
    void rfc6749_token_response_expires_in_must_be_non_negative_integer() {
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
    @ConformanceCase("rfc6749-invalid-client-must-map-to-authentication-failure")
    void rfc6749_invalid_client_must_map_to_authentication_failure() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(401)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                """
                    {"error":"invalid_client","error_description":"Unknown client"}
                    """)));

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
                        error -> {
                            TokenExchangeException tokenError = (TokenExchangeException) error;
                            assertThat(tokenError.oauthError()).isEqualTo("invalid_client");
                            assertThat(tokenError.getMessage()).contains("Unknown client");
                        });
    }

    @Test
    @ConformanceCase("rfc6749-client-credentials-scopes-must-support-multiple-values")
    void rfc6749_client_credentials_scopes_must_support_multiple_values() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")));

        assertThatCode(
                        () ->
                                ClientCredentialsGrant.execute(
                                        tokenUrl,
                                        List.of("read", "write"),
                                        List.of(),
                                        credentials,
                                        transport))
                .doesNotThrowAnyException();

        // RFC 6749 §3.3: multiple scope values MUST be space-delimited.
        // URL encoding of space is either + (HTML form) or %20 — both are valid.
        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(matching("(?s).*scope=read(%20|\\+)write.*")));
    }
}
