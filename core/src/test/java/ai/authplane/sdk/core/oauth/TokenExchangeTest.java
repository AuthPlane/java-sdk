package ai.authplane.sdk.core.oauth;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
import ai.authplane.sdk.core.TokenExchangeOptions;
import ai.authplane.sdk.core.TokenResponse;
import ai.authplane.sdk.core.errors.ConsentRequiredException;
import ai.authplane.sdk.core.errors.TokenExchangeException;
import ai.authplane.sdk.core.fetching.FetchSettings;
import ai.authplane.sdk.core.fetching.HttpTransport;

/** Unit tests for the static TokenExchange.exchange() method. */
class TokenExchangeTest {

    private static WireMockServer wireMock;
    private static String tokenUrl;
    private static HttpTransport transport;

    @BeforeAll
    static void startWireMock() {
        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();
        tokenUrl = "http://localhost:" + wireMock.port() + "/token";
        transport = HttpTransport.from(FetchSettings.devMode());
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
    // Helpers
    // -----------------------------------------------------------------------

    private TokenExchangeOptions defaultOptions() {
        return TokenExchangeOptions.builder("subject-token-value").build();
    }

    // -----------------------------------------------------------------------
    // Success with all optional params
    // -----------------------------------------------------------------------

    @Test
    void exchange_successWithAllOptionalParams() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"new-tok\",\"token_type\":\"Bearer\","
                                                        + "\"expires_in\":1800,\"scope\":\"read write\","
                                                        + "\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        TokenExchangeOptions opts =
                TokenExchangeOptions.builder("subject-token")
                        .scope(List.of("read", "write"))
                        .resource("https://api.example.com")
                        .audience("https://target.example.com")
                        .actorToken("actor-token-value")
                        .actorTokenType("urn:ietf:params:oauth:token-type:access_token")
                        .build();

        ASCredentials creds = new ASCredentials("my-rs", "secret");
        TokenResponse resp = TokenExchange.exchange(tokenUrl, opts, creds, transport);

        assertThat(resp.accessToken()).isEqualTo("new-tok");
        assertThat(resp.tokenType()).isEqualTo("Bearer");
        assertThat(resp.expiresIn()).isEqualTo(1800);
        assertThat(resp.scopes()).containsExactly("read", "write");
        assertThat(resp.issuedTokenType())
                .isEqualTo("urn:ietf:params:oauth:token-type:access_token");

        // Verify all form fields were sent
        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(
                                containing(
                                        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"))
                        .withRequestBody(containing("subject_token=subject-token"))
                        .withRequestBody(containing("scope=read+write"))
                        .withRequestBody(containing("resource=https%3A%2F%2Fapi.example.com"))
                        .withRequestBody(containing("audience=https%3A%2F%2Ftarget.example.com"))
                        .withRequestBody(containing("actor_token=actor-token-value"))
                        .withRequestBody(containing("actor_token_type=")));
    }

    // -----------------------------------------------------------------------
    // OAuth error response
    // -----------------------------------------------------------------------

    @Test
    void exchange_oauthErrorResponse_throwsWithErrorCode() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(400)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"error\":\"invalid_grant\","
                                                        + "\"error_description\":\"Token has been revoked\"}")));

        assertThatThrownBy(
                        () -> TokenExchange.exchange(tokenUrl, defaultOptions(), null, transport))
                .isInstanceOf(TokenExchangeException.class)
                .satisfies(
                        ex -> {
                            TokenExchangeException tee = (TokenExchangeException) ex;
                            assertThat(tee.oauthError()).isEqualTo("invalid_grant");
                            assertThat(tee.getMessage()).contains("revoked");
                        });
    }

    @Test
    void exchange_oauthErrorWithoutDescription_usesErrorAsMessage() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(400)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"error\":\"invalid_scope\"}")));

        assertThatThrownBy(
                        () -> TokenExchange.exchange(tokenUrl, defaultOptions(), null, transport))
                .isInstanceOf(TokenExchangeException.class)
                .satisfies(
                        ex -> {
                            TokenExchangeException tee = (TokenExchangeException) ex;
                            assertThat(tee.oauthError()).isEqualTo("invalid_scope");
                            assertThat(tee.getMessage()).isEqualTo("invalid_scope");
                        });
    }

    @Test
    void exchange_consentRequired_mapsToConsentRequiredException() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(400)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"error\":\"consent_required\","
                                                        + "\"error_description\":\"User must grant access\","
                                                        + "\"service_id\":\"calendar\","
                                                        + "\"cause\":\"missing_user_consent\","
                                                        + "\"consent_url\":\"https://as.example.com/consent?service=calendar\"}")));

        assertThatThrownBy(
                        () -> TokenExchange.exchange(tokenUrl, defaultOptions(), null, transport))
                .isInstanceOf(ConsentRequiredException.class)
                .satisfies(
                        ex -> {
                            ConsentRequiredException cre = (ConsentRequiredException) ex;
                            assertThat(cre.oauthError()).isEqualTo("consent_required");
                            assertThat(cre.serviceId()).isEqualTo("calendar");
                            assertThat(cre.causeDetail()).isEqualTo("missing_user_consent");
                            assertThat(cre.consentUrl())
                                    .isEqualTo("https://as.example.com/consent?service=calendar");
                        });
    }

    @Test
    void exchange_interactionRequired_mapsToConsentRequiredException() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(400)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"error\":\"interaction_required\","
                                                        + "\"error_description\":\"User interaction required\","
                                                        + "\"service\":\"profile\"}")));

        assertThatThrownBy(
                        () -> TokenExchange.exchange(tokenUrl, defaultOptions(), null, transport))
                .isInstanceOf(ConsentRequiredException.class)
                .satisfies(
                        ex -> {
                            ConsentRequiredException cre = (ConsentRequiredException) ex;
                            assertThat(cre.oauthError()).isEqualTo("interaction_required");
                            assertThat(cre.serviceId()).isEqualTo("profile");
                            assertThat(cre.causeDetail()).isEqualTo("User interaction required");
                            assertThat(cre.consentUrl()).isNull();
                        });
    }

    // -----------------------------------------------------------------------
    // Missing access_token
    // -----------------------------------------------------------------------

    @Test
    void exchange_missingAccessToken_throws() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"token_type\":\"Bearer\"}")));

        assertThatThrownBy(
                        () -> TokenExchange.exchange(tokenUrl, defaultOptions(), null, transport))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("access_token");
    }

    @Test
    void exchange_blankAccessToken_throws() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"\",\"token_type\":\"Bearer\"}")));

        assertThatThrownBy(
                        () -> TokenExchange.exchange(tokenUrl, defaultOptions(), null, transport))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("access_token");
    }

    @Test
    void exchange_blankSubjectToken_throws() {
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
    void exchange_actorTokenWithoutType_defaultsActorTokenType() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        TokenExchangeOptions opts =
                TokenExchangeOptions.builder("subject-token").actorToken("actor-token").build();

        TokenExchange.exchange(tokenUrl, opts, null, transport);

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(
                                containing(
                                        "actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token")));
    }

    @Test
    void exchange_blankResourceAndAudience_omitsBoth() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        TokenExchangeOptions opts =
                TokenExchangeOptions.builder("subject-token").resource("").audience("").build();

        TokenExchange.exchange(tokenUrl, opts, null, transport);

        String body = wireMock.getAllServeEvents().getFirst().getRequest().getBodyAsString();
        assertThat(body).doesNotContain("resource=");
        assertThat(body).doesNotContain("audience=");
    }

    @Test
    void exchange_negativeExpiresIn_throws() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"expires_in\":-1}")));

        assertThatThrownBy(
                        () -> TokenExchange.exchange(tokenUrl, defaultOptions(), null, transport))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("expires_in");
    }

    // -----------------------------------------------------------------------
    // With/without credentials
    // -----------------------------------------------------------------------

    @Test
    void exchange_withCredentials_sendsBasicAuth() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        ASCredentials creds = new ASCredentials("client-id", "client-secret");
        TokenExchange.exchange(tokenUrl, defaultOptions(), creds, transport);

        String encodedId = URLEncoder.encode("client-id", StandardCharsets.UTF_8);
        String encodedSecret = URLEncoder.encode("client-secret", StandardCharsets.UTF_8);
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
    void exchange_withoutCredentials_noAuthHeader() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        TokenExchange.exchange(tokenUrl, defaultOptions(), null, transport);

        wireMock.verify(postRequestedFor(urlEqualTo("/token")).withoutHeader("Authorization"));
    }

    // -----------------------------------------------------------------------
    // Minimal success — optional fields missing in response
    // -----------------------------------------------------------------------

    @Test
    void exchange_minimalSuccess_optionalFieldsAreNull() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\","
                                                        + "\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        TokenResponse resp = TokenExchange.exchange(tokenUrl, defaultOptions(), null, transport);

        assertThat(resp.accessToken()).isEqualTo("tok");
        assertThat(resp.tokenType()).isEqualTo("Bearer"); // defaults to Bearer
        assertThat(resp.expiresIn()).isNull();
        assertThat(resp.scopes()).isNull();
        assertThat(resp.issuedTokenType())
                .isEqualTo("urn:ietf:params:oauth:token-type:access_token");
    }

    @Test
    void exchange_missingIssuedTokenType_throws() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")));

        assertThatThrownBy(
                        () -> TokenExchange.exchange(tokenUrl, defaultOptions(), null, transport))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("issued_token_type");
    }
}
