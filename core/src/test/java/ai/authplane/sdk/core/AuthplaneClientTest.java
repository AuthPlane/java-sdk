package ai.authplane.sdk.core;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.stubbing.Scenario;

import ai.authplane.sdk.core.errors.MetadataFetchException;
import ai.authplane.sdk.core.errors.TokenExchangeException;
import ai.authplane.sdk.core.fetching.DocumentCache;
import ai.authplane.sdk.core.oauth.IntrospectionResponse;

/**
 * Unit tests for AuthplaneClient.
 *
 * <p>Exercises building with metadata discovery, resource() factory, exchange(),
 * clientCredentials(), introspect(), revoke(), close(), Builder validation, jwks_uri rotation, and
 * circuit breaker integration.
 */
class AuthplaneClientTest {

    private static final String WELL_KNOWN_PATH = "/.well-known/oauth-authorization-server";

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

    /**
     * Clients built by this class, closed after every test.
     *
     * <p>Closing at the end of each test body leaks the client whenever an assertion above it fails
     * — which is exactly when a test is already telling you something — and the failure then
     * arrives with an executor and a JWKS refresh task still attached. Registering here keeps the
     * cleanup on a path that runs either way, without a try/finally around every test body.
     */
    private final List<AuthplaneClient> clients = new ArrayList<>();

    @BeforeEach
    void resetStubs() {
        wireMock.resetAll();
        stubMetadata();
        stubJwks();
    }

    @AfterEach
    void closeClients() {
        for (AuthplaneClient client : clients) {
            client.close();
        }
        clients.clear();
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
        return register(
                AuthplaneClient.builder(baseUrl)
                        .devMode(true)
                        .authProvider(new ASCredentials("test-client", "test-secret"))
                        .build()
                        .get());
    }

    private AuthplaneClient register(AuthplaneClient client) {
        clients.add(client);
        return client;
    }

    private AuthplaneClient buildClientNoCredentials() throws Exception {
        return register(AuthplaneClient.builder(baseUrl).devMode(true).build().get());
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

    @Test
    void build_issuerWithTrailingSlash_reachesMetadataCacheAndValidatorVerbatim() throws Exception {
        // The builder stores the configured issuer verbatim and passes it to MetadataCache (and,
        // via the client, to each resource's JwtValidator) as the expected issuer. Metadata and
        // token validation compare byte-for-byte (RFC 8414 §3.3), so a trailing-slash issuer
        // verifies only against a metadata document — and a token — whose `iss` carries the same
        // trailing slash. If the builder silently normalized the issuer (stripping the slash), the
        // metadata comparison would fail and build() would throw; a green build therefore proves
        // the configured value reached MetadataCache unmodified.
        String issuerWithSlash = baseUrl + "/";
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
                                                                issuerWithSlash,
                                                                "jwks_uri",
                                                                baseUrl + "/jwks")))));
        stubJwks();

        AuthplaneClient client =
                AuthplaneClient.builder(issuerWithSlash).devMode(true).build().get();

        // Builder stored the issuer byte-for-byte.
        assertThat(client.issuer()).isEqualTo(issuerWithSlash);

        // The JwtValidator built for a resource inherits the same verbatim issuer: a token whose
        // `iss` carries the identical trailing slash verifies.
        AuthplaneResource verifier = client.resource(TestFixtures.RESOURCE, TestFixtures.SCOPES);
        String token = TestFixtures.token().rsaKey(rsaKeys).issuer(issuerWithSlash).build();
        VerifiedClaims claims = verifier.verify(token).get().claims();
        assertThat(claims.issuer()).isEqualTo(issuerWithSlash);
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
    }

    @Test
    void resource_withOptions_createsWorkingResource() throws Exception {
        AuthplaneClient client = buildClient();
        ResourceOptions opts = ResourceOptions.builder().clockSkewSeconds(60).build();
        AuthplaneResource verifier =
                client.resource(TestFixtures.RESOURCE, TestFixtures.SCOPES, opts);

        VerifiedClaims claims = verifier.verify(validToken()).get().claims();
        assertThat(claims.sub()).isEqualTo(TestFixtures.SUBJECT);
    }

    @Test
    void resource_nullResource_throwsNPE() throws Exception {
        AuthplaneClient client = buildClient();
        assertThatThrownBy(() -> client.resource(null, TestFixtures.SCOPES))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void resource_blankResource_throwsIAE() throws Exception {
        AuthplaneClient client = buildClient();
        assertThatThrownBy(() -> client.resource("  ", TestFixtures.SCOPES))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void resource_fragmentInResource_throwsIAE() throws Exception {
        // RFC 8707 §2 forbids a fragment in a resource indicator. java.net.URI splits it off when
        // the PRM URL is derived while prmResponse() publishes the identifier verbatim, so the
        // served document would name an identifier its own URL disagrees with (RFC 9728 §3.3
        // requires a client to discard it). Reject at construction, not on the 401 path.
        AuthplaneClient client = buildClient();
        assertThatThrownBy(
                        () ->
                                client.resource(
                                        TestFixtures.RESOURCE + "/mcp#section",
                                        TestFixtures.SCOPES))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not include a fragment component")
                // The fragment itself is elided from the message; the prefix identifies the config.
                .hasMessageContaining(TestFixtures.RESOURCE + "/mcp")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("section"));
        client.close();
    }

    @Test
    void resourceConstructor_fragmentInResource_throwsIAE() throws Exception {
        // The constructor gate is what the guarantee rests on — every AuthplaneResource is built
        // here, including the ones the client factory never sees. Every other fragment case enters
        // through client.resource(...), which throws at its own gate first, so without this the
        // authoritative line is the one no test pins: delete it and the suite stays green.
        AuthplaneClient client = buildClient();
        assertThatThrownBy(
                        () ->
                                new AuthplaneResource(
                                        client,
                                        TestFixtures.RESOURCE + "/mcp#section",
                                        TestFixtures.SCOPES,
                                        ResourceOptions.defaults()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not include a fragment component");
        client.close();
    }

    @Test
    void resource_schemeRelativeResource_throwsIAE() throws Exception {
        // RFC 8707 §2 requires an absolute URI, which always begins with a scheme (RFC 3986
        // §4.3). A scheme-relative identifier used to construct cleanly and then fail at every
        // sink that splices the scheme — the PRM derivation on the 401 path and the DPoP htu
        // binding target, both reading the missing scheme as the literal text "null". Reject at
        // construction, where the operator sees the line they wrote.
        AuthplaneClient client = buildClient();
        assertThatThrownBy(() -> client.resource("//api.example.com/mcp", TestFixtures.SCOPES))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("has no scheme");
        client.close();
    }

    @Test
    void resourceConstructor_schemeRelativeResource_throwsIAE() throws Exception {
        // Same authoritative-line reasoning as the fragment case above: every other scheme-less
        // identifier enters through client.resource(...), which throws at its own gate first, so
        // without this test the constructor's gate is the line no test pins.
        AuthplaneClient client = buildClient();
        assertThatThrownBy(
                        () ->
                                new AuthplaneResource(
                                        client,
                                        "//api.example.com/mcp",
                                        TestFixtures.SCOPES,
                                        ResourceOptions.defaults()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("has no scheme");
        client.close();
    }

    @Test
    void resource_userinfoInResource_throwsIAE() throws Exception {
        // RFC 9110 §4.2.4 deprecates userinfo and directs a recipient to reject a URI carrying
        // it. Here it is a disclosure, not a style question: the identifier is published verbatim
        // as the PRM `resource` member (served to unauthenticated callers) and in the
        // resource_metadata parameter of the 401 challenge, so the credential would be handed to
        // anyone who asks. Reject at construction rather than redacting it at each sink.
        AuthplaneClient client = buildClient();
        assertThatThrownBy(
                        () ->
                                client.resource(
                                        "https://svc:s3cr3t@api.example.com/mcp",
                                        TestFixtures.SCOPES))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not include a userinfo component")
                // The credential is elided from the message; the host and path identify the
                // configuration that has to change.
                .hasMessageContaining("***@api.example.com/mcp")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("s3cr3t"));
        client.close();
    }

    @Test
    void resourceConstructor_userinfoInResource_throwsIAE() throws Exception {
        // Same authoritative-line reasoning as the fragment and scheme cases above: every other
        // userinfo-bearing identifier enters through client.resource(...), which throws at its
        // own gate first, so without this test the constructor's gate is the line no test pins.
        AuthplaneClient client = buildClient();
        assertThatThrownBy(
                        () ->
                                new AuthplaneResource(
                                        client,
                                        "https://svc:s3cr3t@api.example.com/mcp",
                                        TestFixtures.SCOPES,
                                        ResourceOptions.defaults()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not include a userinfo component")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("s3cr3t"));
        client.close();
    }

    @Test
    void resource_hostWithPort_isAccepted() throws Exception {
        // A ':' in the authority is a port delimiter far more often than a userinfo one, so the
        // userinfo gate must not be a bare scan for ':'. An ordinary host:port identifier still
        // constructs and is published verbatim.
        AuthplaneClient client = buildClient();
        AuthplaneResource verifier =
                client.resource("https://api.example.com:8443/mcp", TestFixtures.SCOPES);
        assertThat(verifier.prmResponse())
                .containsEntry("resource", "https://api.example.com:8443/mcp");
        client.close();
    }

    @Test
    void resource_percentEncodedHashInPath_isAccepted() throws Exception {
        // "%23" is a literal '#' inside the path, not a fragment delimiter (RFC 3986 §3.5), so the
        // identifier is fragment-free and must survive the gate.
        AuthplaneClient client = buildClient();
        AuthplaneResource verifier =
                client.resource(TestFixtures.RESOURCE + "/a%23b", TestFixtures.SCOPES);
        assertThat(verifier.prmResponse())
                .containsEntry("resource", TestFixtures.RESOURCE + "/a%23b");
        client.close();
    }

    @Test
    void resource_nullScopes_throwsNPE() throws Exception {
        AuthplaneClient client = buildClient();
        assertThatThrownBy(() -> client.resource(TestFixtures.RESOURCE, null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void resource_dangerousAlgorithm_throwsIAE() throws Exception {
        AuthplaneClient client = buildClient();
        ResourceOptions opts =
                ResourceOptions.builder().allowedAlgorithms(List.of("HS256")).build();
        assertThatThrownBy(() -> client.resource(TestFixtures.RESOURCE, TestFixtures.SCOPES, opts))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("HS256");
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
    }

    @Test
    void clientCredentials_noCredentials_throwsISE() throws Exception {
        AuthplaneClient client = buildClientNoCredentials();
        assertThatThrownBy(() -> client.clientCredentials(List.of("read"), List.of()).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("authProvider");
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
    // jwks_uri rotation, reconciled on the verification path
    // -----------------------------------------------------------------------

    /**
     * A rebind that fails must be retried, not stranded.
     *
     * <p>The metadata cache publishes a refreshed document before anything acts on it, so a rebind
     * driven by the document *changing* gets exactly one attempt: every later refresh returns that
     * same document, and the change never fires again. One 503 at the new URI while the old one is
     * withdrawn would then reject every token for the life of the process. Reconciling the binding
     * against the document instead means the next key lookup simply tries again.
     */
    @Test
    void jwksUriRotation_transientFailureAtTheNewUri_recoversOnALaterLookup() throws Exception {
        int refreshSeconds = 60;
        TestFixtures.AdvanceableClock clock = new TestFixtures.AdvanceableClock();
        AuthplaneClient client = buildClientWithClock(clock, refreshSeconds);
        AuthplaneResource verifier = client.resource(TestFixtures.RESOURCE, TestFixtures.SCOPES);
        assertThat(verifier.verify(validToken()).get().claims().sub())
                .isEqualTo(TestFixtures.SUBJECT);

        // The AS moves its key set to /jwks2 and withdraws /jwks. /jwks2 is down.
        TestFixtures.RSAKeyPair rotatedKeys = TestFixtures.generateRsaKeyPair();
        wireMock.stubFor(get(urlEqualTo("/jwks2")).willReturn(aResponse().withStatus(503)));
        wireMock.stubFor(get(urlEqualTo("/jwks")).willReturn(aResponse().withStatus(404)));
        stubMetadataWithJwksUri(baseUrl + "/jwks2");

        clock.advanceSeconds(refreshSeconds + 1);

        // Both key pairs publish the same kid, so the withdrawn key set still answers the lookup
        // and the token fails on the signature — the shape a stranded binding takes in production.
        String rotatedToken = TestFixtures.token().rsaKey(rotatedKeys).issuer(baseUrl).build();
        assertThatThrownBy(() -> verifier.verify(rotatedToken).get())
                .isInstanceOf(ExecutionException.class);
        assertThat(client.jwksCache.getUrl()).isEqualTo(baseUrl + "/jwks");

        // The new endpoint comes up. Nothing else changes — in particular the metadata document is
        // byte-identical to the one already cached, so there is no edge left for a change-triggered
        // rebind to fire on.
        wireMock.stubFor(
                get(urlEqualTo("/jwks2"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                TestFixtures.serializeMap(
                                                        rotatedKeys.jwksDocument()))));

        // The failed attempt above put the rebind in backoff, so recovery is deferred rather than
        // immediate — that is the trade for not paying an HTTP timeout on every lookup during the
        // outage. The binding is still stale here, and the token still fails, without a fetch.
        assertThatThrownBy(() -> verifier.verify(rotatedToken).get())
                .isInstanceOf(ExecutionException.class);
        assertThat(client.jwksCache.getUrl()).isEqualTo(baseUrl + "/jwks");

        clock.advanceSeconds(DocumentCache.failureBackoffSeconds(refreshSeconds) + 1);

        assertThat(verifier.verify(rotatedToken).get().claims().sub())
                .isEqualTo(TestFixtures.SUBJECT);
        assertThat(client.jwksCache.getUrl()).isEqualTo(baseUrl + "/jwks2");
    }

    /**
     * A rotated {@code jwks_uri} that is down must not cost a JWKS fetch on every verification.
     *
     * <p>Reconciling the binding against the document means the mismatch is re-detected on every
     * key lookup, so without a backoff every lookup pays a full HTTP timeout for as long as the new
     * endpoint stays down — on a low-QPS resource server that is every request, and the caches' own
     * backoff cannot help because the factory builds a fresh {@code JwksCache} per attempt. Tokens
     * whose keys are already cached never needed that fetch to succeed; they only needed it not to
     * block them.
     */
    @Test
    void jwksUriRotation_newUriDown_retriesOnBackoffRatherThanEveryVerification() throws Exception {
        int refreshSeconds = 60;
        TestFixtures.AdvanceableClock clock = new TestFixtures.AdvanceableClock();
        AuthplaneClient client = buildClientWithClock(clock, refreshSeconds);
        AuthplaneResource verifier = client.resource(TestFixtures.RESOURCE, TestFixtures.SCOPES);
        assertThat(verifier.verify(validToken()).get().claims().sub())
                .isEqualTo(TestFixtures.SUBJECT);

        // The AS moves its key set, and the new endpoint is down. The old one keeps serving, so
        // every key these tokens need is already cached and verification is never in danger — the
        // rebind is the only thing failing.
        wireMock.stubFor(get(urlEqualTo("/jwks2")).willReturn(aResponse().withStatus(500)));
        stubMetadataWithJwksUri(baseUrl + "/jwks2");
        clock.advanceSeconds(refreshSeconds + 1);

        assertThat(verifier.verify(validToken()).get().claims().sub())
                .isEqualTo(TestFixtures.SUBJECT);
        // One rebind attempt. Counted rather than asserted as a literal: the SSRF-safe fetcher
        // walks every address `localhost` resolves to, so a single attempt is more than one
        // request here. What the finding is about is whether this number grows per verification.
        int requestsAfterFirstAttempt =
                wireMock.findAll(getRequestedFor(urlEqualTo("/jwks2"))).size();
        assertThat(requestsAfterFirstAttempt).isGreaterThan(0);

        for (int i = 0; i < 5; i++) {
            assertThat(verifier.verify(validToken()).get().claims().sub())
                    .isEqualTo(TestFixtures.SUBJECT);
        }

        // Unchanged: five more verifications cost nothing. Before the backoff each one paid a full
        // JWKS fetch at the dead endpoint, on the thread the caller is blocked on.
        assertThat(wireMock.findAll(getRequestedFor(urlEqualTo("/jwks2"))).size())
                .isEqualTo(requestsAfterFirstAttempt);
        assertThat(client.jwksCache.getUrl()).isEqualTo(baseUrl + "/jwks");

        // The mismatch persists, so it is still retried — on the backoff rather than on every
        // lookup. This is the reconcile property the previous round established, unchanged.
        clock.advanceSeconds(DocumentCache.failureBackoffSeconds(refreshSeconds) + 1);
        assertThat(verifier.verify(validToken()).get().claims().sub())
                .isEqualTo(TestFixtures.SUBJECT);
        assertThat(wireMock.findAll(getRequestedFor(urlEqualTo("/jwks2"))).size())
                .isEqualTo(requestsAfterFirstAttempt * 2);
    }

    /**
     * A refresh that returns an invalid document must not displace the good one, and — because the
     * document is what key retrieval is reconciled against — must not be able to repoint it either.
     */
    @Test
    void metadataRefresh_invalidDocument_keepsTheGoodDocumentAndTheJwksBinding() throws Exception {
        int refreshSeconds = 60;
        TestFixtures.AdvanceableClock clock = new TestFixtures.AdvanceableClock();
        AuthplaneClient client = buildClientWithClock(clock, refreshSeconds);
        AuthplaneResource verifier = client.resource(TestFixtures.RESOURCE, TestFixtures.SCOPES);
        assertThat(verifier.verify(validToken()).get().claims().sub())
                .isEqualTo(TestFixtures.SUBJECT);

        // The endpoint starts answering for a different issuer, pointing jwks_uri at a key set the
        // SDK must never fetch (RFC 8414 §3.3).
        TestFixtures.RSAKeyPair foreignKeys = TestFixtures.generateRsaKeyPair();
        wireMock.stubFor(
                get(urlEqualTo("/jwks-foreign"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                TestFixtures.serializeMap(
                                                        foreignKeys.jwksDocument()))));
        wireMock.stubFor(
                get(urlEqualTo(WELL_KNOWN_PATH))
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
                                                                baseUrl + "/jwks-foreign")))));

        clock.advanceSeconds(refreshSeconds + 1);

        assertThat(verifier.verify(validToken()).get().claims().sub())
                .isEqualTo(TestFixtures.SUBJECT);
        assertThat(client.jwksCache.getUrl()).isEqualTo(baseUrl + "/jwks");
        assertThat(requestCount("/jwks-foreign"))
                .as("a document that failed validation must not repoint key retrieval")
                .isZero();
    }

    /**
     * An unreachable metadata endpoint costs neither a failed verification nor a network round trip
     * per verification. {@code doFetch} advances the cache timestamp only on success, so without a
     * retry backoff the document stays permanently expired and every lookup pays a full HTTP
     * timeout — on a request path, behind an exclusive lock.
     */
    @Test
    void metadataEndpointDown_verificationKeepsWorkingAndTheRefreshBacksOff() throws Exception {
        int refreshSeconds = 60;
        TestFixtures.AdvanceableClock clock = new TestFixtures.AdvanceableClock();
        AuthplaneClient client = buildClientWithClock(clock, refreshSeconds);
        AuthplaneResource verifier = client.resource(TestFixtures.RESOURCE, TestFixtures.SCOPES);
        verifier.verify(validToken()).get();

        wireMock.stubFor(get(urlEqualTo(WELL_KNOWN_PATH)).willReturn(aResponse().withStatus(500)));
        clock.advanceSeconds(refreshSeconds + 1);

        int readsBeforeOutage = requestCount(WELL_KNOWN_PATH);
        assertThat(verifier.verify(validToken()).get().claims().sub())
                .as("keys the JWKS cache already holds must still verify")
                .isEqualTo(TestFixtures.SUBJECT);
        int readsAfterOneAttempt = requestCount(WELL_KNOWN_PATH);
        assertThat(readsAfterOneAttempt)
                .as("the refresh was attempted")
                .isGreaterThan(readsBeforeOutage);

        for (int i = 0; i < 4; i++) {
            assertThat(verifier.verify(validToken()).get().claims().sub())
                    .isEqualTo(TestFixtures.SUBJECT);
        }
        assertThat(requestCount(WELL_KNOWN_PATH))
                .as("a failed refresh must back off, not retry on every verification")
                .isEqualTo(readsAfterOneAttempt);

        clock.advanceSeconds(31); // past the backoff
        verifier.verify(validToken()).get();
        assertThat(requestCount(WELL_KNOWN_PATH))
                .as("the retry resumes once the backoff elapses")
                .isGreaterThan(readsAfterOneAttempt);
    }

    /**
     * Sets both refresh intervals to the same value.
     *
     * <p>Only the metadata one used to be set, which left the rebind backoff — computed from the
     * JWKS interval — reading a knob the test never named. The two agreed at 60 only because both
     * exceed the 30 s ceiling, so the tests below would have kept passing while measuring the wrong
     * thing, and stopped agreeing at any interval under 30.
     */
    private AuthplaneClient buildClientWithClock(Clock clock, int refreshSeconds) throws Exception {
        return register(
                AuthplaneClient.builder(baseUrl)
                        .devMode(true)
                        .metadataRefreshSeconds(refreshSeconds)
                        .jwksRefreshSeconds(refreshSeconds)
                        .clock(clock)
                        .build()
                        .get());
    }

    private void stubMetadataWithJwksUri(String jwksUri) {
        wireMock.stubFor(
                get(urlEqualTo(WELL_KNOWN_PATH))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                TestFixtures.serializeMap(
                                                        Map.of(
                                                                "issuer", baseUrl,
                                                                "jwks_uri", jwksUri)))));
    }

    private static int requestCount(String path) {
        return wireMock.countRequestsMatching(getRequestedFor(urlEqualTo(path)).build()).getCount();
    }

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
    }

    private static Throwable rootCause(Throwable throwable) {
        Throwable current = throwable;
        while (current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }
}
