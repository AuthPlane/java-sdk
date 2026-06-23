package ai.authplane.sdk.core;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.stubbing.Scenario;

import ai.authplane.sdk.core.errors.MetadataFetchException;
import ai.authplane.sdk.core.errors.TokenExchangeException;
import ai.authplane.sdk.core.oauth.IntrospectionResponse;

/**
 * Unit tests for AuthplaneClient.
 *
 * <p>Exercises building with metadata discovery, resource() factory, exchange(),
 * clientCredentials(), introspect(), revoke(), close(), Builder validation, jwks_uri rotation, and
 * circuit breaker integration.
 */
class AuthplaneClientTest {

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
        stubMetadata();
        stubJwks();
    }

    // -----------------------------------------------------------------------
    // Stub helpers
    // -----------------------------------------------------------------------

    private void stubMetadata() {
        String metadataBody =
                TestFixtures.serializeMap(
                        Map.of(
                                "issuer", baseUrl,
                                "jwks_uri", baseUrl + "/jwks",
                                "token_endpoint", baseUrl + "/token",
                                "introspection_endpoint", baseUrl + "/introspect",
                                "revocation_endpoint", baseUrl + "/revoke"));
        wireMock.stubFor(
                get(urlEqualTo("/.well-known/oauth-authorization-server"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(metadataBody)));
    }

    private void stubJwks() {
        String jwksBody = TestFixtures.serializeMap(rsaKeys.jwksDocument());
        wireMock.stubFor(
                get(urlEqualTo("/jwks"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(jwksBody)));
    }

    private AuthplaneClient buildClient() throws Exception {
        return AuthplaneClient.builder(baseUrl)
                .devMode(true)
                .authProvider(new ASCredentials("test-client", "test-secret"))
                .build()
                .get();
    }

    private AuthplaneClient buildClientNoCredentials() throws Exception {
        return AuthplaneClient.builder(baseUrl).devMode(true).build().get();
    }

    private String validToken() {
        return TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).build();
    }

    // -----------------------------------------------------------------------
    // Building with metadata discovery
    // -----------------------------------------------------------------------

    @Test
    void build_discoversMetadata_andFetchesJwks() throws Exception {
        AuthplaneClient client = buildClient();
        assertThat(client.issuer()).isEqualTo(baseUrl);
        assertThat(client.devMode()).isTrue();
        client.close();
    }

    @Test
    void build_metadataUnavailable_failsFuture() {
        wireMock.resetAll();
        // No metadata stub → fetch will fail
        wireMock.stubFor(
                get(urlEqualTo("/.well-known/oauth-authorization-server"))
                        .willReturn(aResponse().withStatus(404)));

        assertThatThrownBy(() -> AuthplaneClient.builder(baseUrl).devMode(true).build().get())
                .isInstanceOf(ExecutionException.class);
    }

    @Test
    void build_metadataMissingIssuer_failsFuture() {
        wireMock.resetAll();
        wireMock.stubFor(
                get(urlEqualTo("/.well-known/oauth-authorization-server"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                TestFixtures.serializeMap(
                                                        Map.of("jwks_uri", baseUrl + "/jwks")))));
        stubJwks();

        assertThatThrownBy(() -> AuthplaneClient.builder(baseUrl).devMode(true).build().get())
                .isInstanceOf(ExecutionException.class)
                .satisfies(
                        error -> {
                            Throwable root = rootCause(error);
                            assertThat(root).isInstanceOf(MetadataFetchException.class);
                            assertThat(root).hasMessageContaining("issuer");
                        });
    }

    @Test
    void build_metadataIssuerMismatch_failsFuture() {
        wireMock.resetAll();
        wireMock.stubFor(
                get(urlEqualTo("/.well-known/oauth-authorization-server"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                TestFixtures.serializeMap(
                                                        Map.of(
                                                                "issuer",
                                                                "https://evil.example.com",
                                                                "jwks_uri",
                                                                baseUrl + "/jwks")))));
        stubJwks();

        assertThatThrownBy(() -> AuthplaneClient.builder(baseUrl).devMode(true).build().get())
                .isInstanceOf(ExecutionException.class)
                .satisfies(
                        error -> {
                            Throwable root = rootCause(error);
                            assertThat(root).isInstanceOf(MetadataFetchException.class);
                            assertThat(root).hasMessageContaining("issuer");
                        });
    }

    // -----------------------------------------------------------------------
    // resource() factory creates working resources
    // -----------------------------------------------------------------------

    @Test
    void resource_createsWorkingResource() throws Exception {
        AuthplaneClient client = buildClient();
        AuthplaneResource verifier = client.resource(TestFixtures.RESOURCE, TestFixtures.SCOPES);

        VerifiedClaims claims = verifier.verify(validToken()).get().claims();
        assertThat(claims.sub()).isEqualTo(TestFixtures.SUBJECT);
        assertThat(claims.issuer()).isEqualTo(baseUrl);
        client.close();
    }

    @Test
    void resource_withOptions_createsWorkingResource() throws Exception {
        AuthplaneClient client = buildClient();
        ResourceOptions opts = ResourceOptions.builder().clockSkewSeconds(60).build();
        AuthplaneResource verifier =
                client.resource(TestFixtures.RESOURCE, TestFixtures.SCOPES, opts);

        VerifiedClaims claims = verifier.verify(validToken()).get().claims();
        assertThat(claims.sub()).isEqualTo(TestFixtures.SUBJECT);
        client.close();
    }

    @Test
    void resource_nullResource_throwsNPE() throws Exception {
        AuthplaneClient client = buildClient();
        assertThatThrownBy(() -> client.resource(null, TestFixtures.SCOPES))
                .isInstanceOf(NullPointerException.class);
        client.close();
    }

    @Test
    void resource_blankResource_throwsIAE() throws Exception {
        AuthplaneClient client = buildClient();
        assertThatThrownBy(() -> client.resource("  ", TestFixtures.SCOPES))
                .isInstanceOf(IllegalArgumentException.class);
        client.close();
    }

    @Test
    void resource_nullScopes_throwsNPE() throws Exception {
        AuthplaneClient client = buildClient();
        assertThatThrownBy(() -> client.resource(TestFixtures.RESOURCE, null))
                .isInstanceOf(NullPointerException.class);
        client.close();
    }

    @Test
    void resource_dangerousAlgorithm_throwsIAE() throws Exception {
        AuthplaneClient client = buildClient();
        ResourceOptions opts =
                ResourceOptions.builder().allowedAlgorithms(List.of("HS256")).build();
        assertThatThrownBy(() -> client.resource(TestFixtures.RESOURCE, TestFixtures.SCOPES, opts))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("HS256");
        client.close();
    }

    // -----------------------------------------------------------------------
    // exchange() delegates to token endpoint
    // -----------------------------------------------------------------------

    @Test
    void exchange_delegatesToTokenEndpoint() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"exchanged\",\"token_type\":\"Bearer\","
                                                        + "\"expires_in\":1800,"
                                                        + "\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        AuthplaneClient client = buildClient();
        TokenExchangeOptions opts =
                TokenExchangeOptions.builder("subject-tok").scope(List.of("read")).build();
        TokenResponse resp = client.exchange(opts).get();

        assertThat(resp.accessToken()).isEqualTo("exchanged");
        assertThat(resp.expiresIn()).isEqualTo(1800);
        client.close();
    }

    @Test
    void exchange_oauthError_throwsTokenExchangeException() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(400)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"error\":\"invalid_grant\","
                                                        + "\"error_description\":\"Token expired\"}")));

        AuthplaneClient client = buildClient();
        assertThatThrownBy(
                        () ->
                                client.exchange(
                                                TokenExchangeOptions.builder("expired-token")
                                                        .build())
                                        .get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(TokenExchangeException.class);
        client.close();
    }

    @Test
    void exchange_sameInputs_cachesTokenAndReusesIt() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .inScenario("exchange-cache")
                        .whenScenarioStateIs(Scenario.STARTED)
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"first-exchange\",\"token_type\":\"Bearer\","
                                                        + "\"expires_in\":3600,"
                                                        + "\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}"))
                        .willSetStateTo("called"));

        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .inScenario("exchange-cache")
                        .whenScenarioStateIs("called")
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"second-exchange\",\"token_type\":\"Bearer\","
                                                        + "\"expires_in\":3600,"
                                                        + "\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        AuthplaneClient client = buildClient();
        TokenExchangeOptions opts =
                TokenExchangeOptions.builder("subject-tok")
                        .scope(List.of("read"))
                        .resource("https://api.example.com")
                        .build();

        TokenResponse resp1 = client.exchange(opts).get();
        TokenResponse resp2 = client.exchange(opts).get();

        assertThat(resp1.accessToken()).isEqualTo("first-exchange");
        assertThat(resp2.accessToken()).isEqualTo("first-exchange");
        wireMock.verify(1, postRequestedFor(urlEqualTo("/token")));
        client.close();
    }

    @Test
    void exchange_withoutExpiresIn_usesDefaultTtlAndReusesToken() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .inScenario("exchange-default-ttl-cache")
                        .whenScenarioStateIs(Scenario.STARTED)
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"first-default-ttl\",\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}"))
                        .willSetStateTo("called"));

        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .inScenario("exchange-default-ttl-cache")
                        .whenScenarioStateIs("called")
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"second-default-ttl\",\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        AuthplaneClient client =
                AuthplaneClient.builder(baseUrl)
                        .devMode(true)
                        .tokenCacheConfig(TokenCacheConfig.of(30, 120))
                        .authProvider(new ASCredentials("test-client", "test-secret"))
                        .build()
                        .get();
        TokenExchangeOptions opts =
                TokenExchangeOptions.builder("subject-tok")
                        .scope(List.of("read"))
                        .resource("https://api.example.com")
                        .build();

        TokenResponse resp1 = client.exchange(opts).get();
        TokenResponse resp2 = client.exchange(opts).get();

        assertThat(resp1.accessToken()).isEqualTo("first-default-ttl");
        assertThat(resp2.accessToken()).isEqualTo("first-default-ttl");
        wireMock.verify(1, postRequestedFor(urlEqualTo("/token")));
        client.close();
    }

    @Test
    void exchange_distinctInputs_doNotReuseCachedToken() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .withRequestBody(containing("subject_token=subject-token-1"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"subject-token-1-issued\",\"token_type\":\"Bearer\","
                                                        + "\"expires_in\":3600,"
                                                        + "\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .withRequestBody(containing("subject_token=subject-token-2"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"subject-token-2-issued\",\"token_type\":\"Bearer\","
                                                        + "\"expires_in\":3600,"
                                                        + "\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}")));

        AuthplaneClient client = buildClient();

        TokenResponse resp1 =
                client.exchange(
                                TokenExchangeOptions.builder("subject-token-1")
                                        .scope(List.of("read"))
                                        .resource("https://api.example.com")
                                        .build())
                        .get();

        TokenResponse resp2 =
                client.exchange(
                                TokenExchangeOptions.builder("subject-token-2")
                                        .scope(List.of("read"))
                                        .resource("https://api.example.com")
                                        .build())
                        .get();

        assertThat(resp1.accessToken()).isEqualTo("subject-token-1-issued");
        assertThat(resp2.accessToken()).isEqualTo("subject-token-2-issued");
        wireMock.verify(2, postRequestedFor(urlEqualTo("/token")));
        client.close();
    }

    // -----------------------------------------------------------------------
    // clientCredentials() grant
    // -----------------------------------------------------------------------

    @Test
    void clientCredentials_success() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"cc-token\",\"token_type\":\"Bearer\","
                                                        + "\"expires_in\":3600,\"scope\":\"read write\"}")));

        AuthplaneClient client = buildClient();
        TokenResponse resp = client.clientCredentials(List.of("read write"), List.of()).get();

        assertThat(resp.accessToken()).isEqualTo("cc-token");
        assertThat(resp.expiresIn()).isEqualTo(3600);

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(containing("grant_type=client_credentials")));
        client.close();
    }

    @Test
    void clientCredentials_withResource_sendsResource() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"cc-tok\",\"token_type\":\"Bearer\"}")));

        AuthplaneClient client = buildClient();
        client.clientCredentials(List.of("read"), List.of("https://api.example.com")).get();

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withRequestBody(containing("resource=https%3A%2F%2Fapi.example.com")));
        client.close();
    }

    @Test
    void authProvider_invokedPerRequest_appliesRotatedCredentials() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"t\",\"token_type\":\"Bearer\","
                                                        + "\"expires_in\":3600}")));

        AtomicReference<String> header = new AtomicReference<>("Basic first");
        AuthProvider rotating = () -> Map.of("Authorization", header.get());

        AuthplaneClient client =
                AuthplaneClient.builder(baseUrl).devMode(true).authProvider(rotating).build().get();

        client.clientCredentials(List.of("read"), List.of()).get();
        header.set("Basic second");
        // Different scope → distinct cache key, so this is a fresh AS request.
        client.clientCredentials(List.of("write"), List.of()).get();

        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withHeader("Authorization", equalTo("Basic first")));
        wireMock.verify(
                postRequestedFor(urlEqualTo("/token"))
                        .withHeader("Authorization", equalTo("Basic second")));
        client.close();
    }

    @Test
    void clientCredentials_noCredentials_throwsISE() throws Exception {
        AuthplaneClient client = buildClientNoCredentials();
        assertThatThrownBy(() -> client.clientCredentials(List.of("read"), List.of()).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("authProvider");
        client.close();
    }

    // -----------------------------------------------------------------------
    // introspect() call
    // -----------------------------------------------------------------------

    @Test
    void introspect_activeTrue_returnsResponse() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"active\":true,\"sub\":\"user-123\"}")));

        AuthplaneClient client = buildClient();
        IntrospectionResponse resp = client.introspect("some-token").get();

        assertThat(resp.active()).isTrue();
        assertThat(resp.raw()).containsEntry("sub", "user-123");
        client.close();
    }

    @Test
    void introspect_activeFalse_returnsResponse() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"active\":false}")));

        AuthplaneClient client = buildClient();
        IntrospectionResponse resp = client.introspect("revoked-token").get();

        assertThat(resp.active()).isFalse();
        client.close();
    }

    // -----------------------------------------------------------------------
    // revoke() call
    // -----------------------------------------------------------------------

    @Test
    void revoke_sendsTokenToEndpoint() throws Exception {
        wireMock.stubFor(post(urlEqualTo("/revoke")).willReturn(aResponse().withStatus(200)));

        AuthplaneClient client = buildClient();
        client.revoke("token-to-revoke").get();

        wireMock.verify(
                postRequestedFor(urlEqualTo("/revoke"))
                        .withRequestBody(containing("token=token-to-revoke")));
        client.close();
    }

    // -----------------------------------------------------------------------
    // close() lifecycle
    // -----------------------------------------------------------------------

    @Test
    void close_clearsTokenCache() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"cached-tok\",\"token_type\":\"Bearer\","
                                                        + "\"expires_in\":3600}")));

        AuthplaneClient client = buildClient();
        // Populate the cache
        client.clientCredentials(List.of("read"), List.of()).get();
        assertThat(client.tokenCache.size()).isGreaterThan(0);

        client.close();

        assertThat(client.tokenCache.size()).isEqualTo(0);
    }

    // -----------------------------------------------------------------------
    // Builder validation
    // -----------------------------------------------------------------------

    @Test
    void builder_nullIssuer_throwsNPE() {
        assertThatThrownBy(() -> AuthplaneClient.builder(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("issuer");
    }

    @Test
    void builder_blankIssuer_throwsIAE() {
        assertThatThrownBy(() -> AuthplaneClient.builder("  "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("issuer");
    }

    @Test
    void builder_negativeJwksRefreshSeconds_failsFuture() {
        assertThatThrownBy(
                        () ->
                                AuthplaneClient.builder(baseUrl)
                                        .devMode(true)
                                        .jwksRefreshSeconds(-1)
                                        .build()
                                        .get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("jwksRefreshSeconds");
    }

    @Test
    void builder_zeroJwksRefreshSeconds_failsFuture() {
        assertThatThrownBy(
                        () ->
                                AuthplaneClient.builder(baseUrl)
                                        .devMode(true)
                                        .jwksRefreshSeconds(0)
                                        .build()
                                        .get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void builder_negativeMetadataRefreshSeconds_failsFuture() {
        assertThatThrownBy(
                        () ->
                                AuthplaneClient.builder(baseUrl)
                                        .devMode(true)
                                        .metadataRefreshSeconds(-1)
                                        .build()
                                        .get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("metadataRefreshSeconds");
    }

    @Test
    void builder_nullFetchSettings_throwsNPE() {
        assertThatThrownBy(() -> AuthplaneClient.builder(baseUrl).fetchSettings(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void builder_nullAuthProvider_throwsNPE() {
        assertThatThrownBy(() -> AuthplaneClient.builder(baseUrl).authProvider(null))
                .isInstanceOf(NullPointerException.class);
    }

    // -----------------------------------------------------------------------
    // jwks_uri rotation via metadata change callback
    // -----------------------------------------------------------------------

    @Test
    void jwksUriRotation_updatesJwksCache() throws Exception {
        // Build client with initial metadata
        AuthplaneClient client = buildClient();

        // Generate new keys for the rotated endpoint
        TestFixtures.RSAKeyPair rotatedKeys = TestFixtures.generateRsaKeyPair();
        String rotatedJwksBody = TestFixtures.serializeMap(rotatedKeys.jwksDocument());
        wireMock.stubFor(
                get(urlEqualTo("/jwks2"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(rotatedJwksBody)));

        // Verify baseline: token signed with original keys works
        AuthplaneResource verifier = client.resource(TestFixtures.RESOURCE, TestFixtures.SCOPES);
        VerifiedClaims claims = verifier.verify(validToken()).get().claims();
        assertThat(claims.sub()).isEqualTo(TestFixtures.SUBJECT);

        // Update metadata to point to /jwks2
        String updatedMetadata =
                TestFixtures.serializeMap(
                        Map.of(
                                "issuer", baseUrl,
                                "jwks_uri", baseUrl + "/jwks2",
                                "token_endpoint", baseUrl + "/token",
                                "introspection_endpoint", baseUrl + "/introspect",
                                "revocation_endpoint", baseUrl + "/revoke"));
        wireMock.stubFor(
                get(urlEqualTo("/.well-known/oauth-authorization-server"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(updatedMetadata)));

        // Force metadata refresh — triggers rotation callback
        client.forceMetadataRefreshForTest();

        // Token signed with rotated keys should now verify
        String rotatedToken = TestFixtures.token().rsaKey(rotatedKeys).issuer(baseUrl).build();
        AuthplaneResource verifier2 = client.resource(TestFixtures.RESOURCE, TestFixtures.SCOPES);
        VerifiedClaims rotatedClaims = verifier2.verify(rotatedToken).get().claims();
        assertThat(rotatedClaims.sub()).isEqualTo(TestFixtures.SUBJECT);

        client.close();
    }

    // -----------------------------------------------------------------------
    // Circuit breaker integration
    // -----------------------------------------------------------------------

    @Test
    void circuitBreaker_opensAfterFailures_thenRejectsRequests() throws Exception {
        // Build client with low circuit breaker threshold
        AuthplaneClient client =
                AuthplaneClient.builder(baseUrl)
                        .devMode(true)
                        .authProvider(new ASCredentials("test-client", "test-secret"))
                        .circuitBreakerThreshold(2)
                        .circuitBreakerCooldownSeconds(60)
                        .build()
                        .get();

        // Stub token endpoint to return errors
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(400)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"error\":\"server_error\","
                                                        + "\"error_description\":\"Internal error\"}")));

        // Two failures should open the circuit
        try {
            client.clientCredentials(List.of("read"), List.of()).get();
        } catch (Exception ignored) {
        }
        try {
            client.clientCredentials(List.of("other"), List.of()).get();
        } catch (Exception ignored) {
        }

        // Circuit should now be OPEN — next request rejected immediately
        assertThat(client.circuitBreaker.state()).isEqualTo(CircuitBreaker.State.OPEN);

        assertThatThrownBy(() -> client.clientCredentials(List.of("yet-another"), List.of()).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("Circuit breaker");

        client.close();
    }

    @Test
    void circuitBreaker_doesNotOpenOnRepeatedInvalidScope() throws Exception {
        AuthplaneClient client =
                AuthplaneClient.builder(baseUrl)
                        .devMode(true)
                        .authProvider(new ASCredentials("test-client", "test-secret"))
                        .circuitBreakerThreshold(2)
                        .circuitBreakerCooldownSeconds(60)
                        .build()
                        .get();

        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(400)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"error\":\"invalid_scope\","
                                                        + "\"error_description\":\"not allowed\"}")));

        for (int i = 0; i < 4; i++) {
            try {
                client.clientCredentials(List.of("read"), List.of()).get();
            } catch (Exception ignored) {
            }
        }

        assertThat(client.circuitBreaker.state()).isNotEqualTo(CircuitBreaker.State.OPEN);

        client.close();
    }

    // -----------------------------------------------------------------------
    // Token caching in clientCredentials
    // -----------------------------------------------------------------------

    @Test
    void clientCredentials_cachesTokenAndReusesIt() throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"cached\",\"token_type\":\"Bearer\","
                                                        + "\"expires_in\":3600}")));

        AuthplaneClient client = buildClient();

        // First call hits the endpoint
        TokenResponse resp1 = client.clientCredentials(List.of("read"), List.of()).get();
        assertThat(resp1.accessToken()).isEqualTo("cached");

        // Change the stub to return a different token
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"different\",\"token_type\":\"Bearer\","
                                                        + "\"expires_in\":3600}")));

        // Second call with same scope should return cached token
        TokenResponse resp2 = client.clientCredentials(List.of("read"), List.of()).get();
        assertThat(resp2.accessToken()).isEqualTo("cached");

        client.close();
    }

    // -----------------------------------------------------------------------
    // Inflight deduplication in clientCredentials
    // -----------------------------------------------------------------------

    @Test
    void clientCredentials_concurrentColdMisses_deduplicateToSingleCall() throws Exception {
        // Use a slow-responding stub so concurrent calls overlap
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"deduped\",\"token_type\":\"Bearer\","
                                                        + "\"expires_in\":3600}")
                                        .withFixedDelay(200)));

        AuthplaneClient client = buildClient();

        int concurrency = 10;
        CountDownLatch startGate = new CountDownLatch(1);
        List<CompletableFuture<TokenResponse>> futures = new ArrayList<>();

        for (int i = 0; i < concurrency; i++) {
            futures.add(
                    CompletableFuture.supplyAsync(
                            () -> {
                                try {
                                    startGate.await(5, TimeUnit.SECONDS);
                                    return client.clientCredentials(List.of("read"), List.of())
                                            .get();
                                } catch (Exception e) {
                                    throw new RuntimeException(e);
                                }
                            }));
        }

        // Release all threads at once
        startGate.countDown();

        // All should get the same token
        for (CompletableFuture<TokenResponse> f : futures) {
            assertThat(f.get(5, TimeUnit.SECONDS).accessToken()).isEqualTo("deduped");
        }

        // Only one POST should have been made
        wireMock.verify(1, postRequestedFor(urlEqualTo("/token")));
        client.close();
    }

    @Test
    void clientCredentials_afterInflightCompletes_secondCallUsesCacheNotEndpoint()
            throws Exception {
        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .inScenario("dedup")
                        .whenScenarioStateIs(Scenario.STARTED)
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"first\",\"token_type\":\"Bearer\","
                                                        + "\"expires_in\":3600}"))
                        .willSetStateTo("called"));

        wireMock.stubFor(
                post(urlEqualTo("/token"))
                        .inScenario("dedup")
                        .whenScenarioStateIs("called")
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"second\",\"token_type\":\"Bearer\","
                                                        + "\"expires_in\":3600}")));

        AuthplaneClient client = buildClient();

        // First call populates cache
        TokenResponse resp1 = client.clientCredentials(List.of("read"), List.of()).get();
        assertThat(resp1.accessToken()).isEqualTo("first");

        // Second call after inflight is gone should use cache, not call endpoint again
        TokenResponse resp2 = client.clientCredentials(List.of("read"), List.of()).get();
        assertThat(resp2.accessToken()).isEqualTo("first");

        // Only one POST
        wireMock.verify(1, postRequestedFor(urlEqualTo("/token")));
        client.close();
    }

    // -----------------------------------------------------------------------
    // Builder setter chaining
    // -----------------------------------------------------------------------

    @Test
    void builder_settersAreChainable() throws Exception {
        AuthplaneClient client =
                AuthplaneClient.builder(baseUrl)
                        .devMode(true)
                        .jwksRefreshSeconds(120)
                        .metadataRefreshSeconds(600)
                        .circuitBreakerThreshold(10)
                        .circuitBreakerCooldownSeconds(30)
                        .tokenCacheConfig(TokenCacheConfig.of(15, 120))
                        .authProvider(new ASCredentials("c", "s"))
                        .build()
                        .get();

        assertThat(client.issuer()).isEqualTo(baseUrl);
        client.close();
    }

    private static Throwable rootCause(Throwable throwable) {
        Throwable current = throwable;
        while (current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }
}
