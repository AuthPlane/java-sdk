package ai.authplane.sdk.core.conformance;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import ai.authplane.sdk.core.ASCredentials;
import ai.authplane.sdk.core.TokenExchangeOptions;
import ai.authplane.sdk.core.TokenResponse;
import ai.authplane.sdk.core.errors.TokenExchangeException;
import ai.authplane.sdk.core.fetching.FetchSettings;
import ai.authplane.sdk.core.fetching.HttpTransport;
import ai.authplane.sdk.core.oauth.TokenExchange;

@ConformanceSuite
class Rfc8693ConformanceTest extends AbstractPlaceholderConformanceTest {

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
        credentials = new ASCredentials("my-rs", "secret");
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
    @ConformanceCase("rfc8693-grant-type-must-be-token-exchange")
    void rfc8693_grant_type_must_be_token_exchange() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"new-tok\",\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        assertThatCode(
                        () ->
                                TokenExchange.exchange(
                                        tokenUrl,
                                        TokenExchangeOptions.builder("subject-token").build(),
                                        null,
                                        transport))
                .doesNotThrowAnyException();

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(
                                containing(
                                        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange")));
    }

    @Test
    @ConformanceCase("rfc8693-subject-token-is-required")
    void rfc8693_subject_token_is_required() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"new-tok\",\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        assertThatThrownBy(
                        () ->
                                TokenExchange.exchange(
                                        tokenUrl,
                                        TokenExchangeOptions.builder("").build(),
                                        null,
                                        transport))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("subject_token");
    }

    @Test
    @ConformanceCase("rfc8693-default-subject-token-type-is-access-token")
    void rfc8693_default_subject_token_type_is_access_token() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"new-tok\",\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        assertThatCode(
                        () ->
                                TokenExchange.exchange(
                                        tokenUrl,
                                        TokenExchangeOptions.builder("subject-token").build(),
                                        null,
                                        transport))
                .doesNotThrowAnyException();

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(
                                containing(
                                        "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token")));
    }

    @Test
    @ConformanceCase("rfc8693-actor-token-type-defaults-when-actor-token-is-present")
    void rfc8693_actor_token_type_defaults_when_actor_token_is_present() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"new-tok\",\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        TokenExchangeOptions options =
                TokenExchangeOptions.builder("subject-token").actorToken("actor-token").build();

        assertThatCode(() -> TokenExchange.exchange(tokenUrl, options, null, transport))
                .doesNotThrowAnyException();

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(
                                containing(
                                        "actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token")));
    }

    @Test
    @ConformanceCase("rfc8693-resource-parameter-must-be-sent-when-configured")
    void rfc8693_resource_parameter_must_be_sent_when_configured() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"new-tok\",\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        TokenExchangeOptions options =
                TokenExchangeOptions.builder("subject-token")
                        .resource("https://api.example.com")
                        .build();

        assertThatCode(() -> TokenExchange.exchange(tokenUrl, options, null, transport))
                .doesNotThrowAnyException();

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(containing("resource=https%3A%2F%2Fapi.example.com")));
    }

    @Test
    @ConformanceCase("rfc8693-multiple-resource-parameters-must-be-emitted")
    void rfc8693_multiple_resource_parameters_must_be_emitted() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"new-tok\",\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        TokenExchangeOptions options =
                TokenExchangeOptions.builder("subject-token")
                        .resources(
                                List.of(
                                        "https://api-one.example.com",
                                        "https://api-two.example.com"))
                        .build();

        assertThatCode(() -> TokenExchange.exchange(tokenUrl, options, null, transport))
                .doesNotThrowAnyException();

        String body = wireMock.getAllServeEvents().getFirst().getRequest().getBodyAsString();
        assertThat(body).contains("resource=https%3A%2F%2Fapi-one.example.com");
        assertThat(body).contains("resource=https%3A%2F%2Fapi-two.example.com");
    }

    @Test
    @ConformanceCase("rfc8693-error-mapping-invalid-grant")
    void rfc8693_error_mapping_invalid_grant() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(400)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"error\":\"invalid_grant\",\"error_description\":\"revoked\"}")));

        assertThatThrownBy(
                        () ->
                                TokenExchange.exchange(
                                        tokenUrl,
                                        TokenExchangeOptions.builder("subject-token").build(),
                                        null,
                                        transport))
                .isInstanceOf(TokenExchangeException.class)
                .satisfies(
                        error -> {
                            TokenExchangeException tokenError = (TokenExchangeException) error;
                            assertThat(tokenError.oauthError()).isEqualTo("invalid_grant");
                            assertThat(tokenError.getMessage()).contains("revoked");
                        });
    }

    @Test
    @ConformanceCase("rfc8693-audience-parameter-must-be-sent-when-configured")
    void rfc8693_audience_parameter_must_be_sent_when_configured() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"new-tok\",\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        TokenExchangeOptions options =
                TokenExchangeOptions.builder("subject-token")
                        .audience("https://target.example.com")
                        .build();

        assertThatCode(() -> TokenExchange.exchange(tokenUrl, options, null, transport))
                .doesNotThrowAnyException();

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(containing("audience=https%3A%2F%2Ftarget.example.com")));
    }

    @Test
    @ConformanceCase("rfc8693-multiple-audience-parameters-must-be-emitted")
    void rfc8693_multiple_audience_parameters_must_be_emitted() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"new-tok\",\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        TokenExchangeOptions options =
                TokenExchangeOptions.builder("subject-token")
                        .audiences(
                                List.of(
                                        "https://aud-one.example.com",
                                        "https://aud-two.example.com"))
                        .build();

        assertThatCode(() -> TokenExchange.exchange(tokenUrl, options, null, transport))
                .doesNotThrowAnyException();

        String body = wireMock.getAllServeEvents().getFirst().getRequest().getBodyAsString();
        assertThat(body).contains("audience=https%3A%2F%2Faud-one.example.com");
        assertThat(body).contains("audience=https%3A%2F%2Faud-two.example.com");
    }

    @Test
    @ConformanceCase("rfc8693-empty-resource-and-audience-values-must-be-omitted")
    void rfc8693_empty_resource_and_audience_values_must_be_omitted() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"new-tok\",\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        TokenExchangeOptions options =
                TokenExchangeOptions.builder("subject-token").resource("").audience("").build();

        assertThatCode(() -> TokenExchange.exchange(tokenUrl, options, null, transport))
                .doesNotThrowAnyException();

        String body = wireMock.getAllServeEvents().getFirst().getRequest().getBodyAsString();
        assertThat(body).doesNotContain("resource=");
        assertThat(body).doesNotContain("audience=");
    }

    @Test
    @ConformanceCase(
            "rfc8693-success-response-must-use-access-token-issued-token-type-when-present")
    void rfc8693_success_response_must_use_access_token_issued_token_type_when_present() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                """
                    {"access_token":"new-tok","token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:access_token"}
                    """)));

        TokenResponse response =
                assertDoesNotThrow(
                        () ->
                                TokenExchange.exchange(
                                        tokenUrl,
                                        TokenExchangeOptions.builder("subject-token").build(),
                                        credentials,
                                        transport));

        assertThat(response.issuedTokenType())
                .isEqualTo("urn:ietf:params:oauth:token-type:access_token");
    }

    @Test
    @ConformanceCase("rfc8693-token-exchange-response-must-contain-issued-token-type")
    void rfc8693_token_exchange_response_must_contain_issued_token_type() {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"exchanged_token\",\"token_type\":\"Bearer\"}")));

        assertThatThrownBy(
                        () ->
                                TokenExchange.exchange(
                                        tokenUrl,
                                        TokenExchangeOptions.builder("subject-token").build(),
                                        credentials,
                                        transport))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("issued_token_type");
    }
}
