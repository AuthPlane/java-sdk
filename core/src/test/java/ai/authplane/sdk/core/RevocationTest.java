package ai.authplane.sdk.core;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import ai.authplane.sdk.core.errors.TokenRevokedException;

/**
 * Integration tests for the revocation checking path in AuthplaneResource.
 *
 * <p>Uses WireMock to stub metadata and JWKS endpoints, then exercises custom and built-in
 * revocation checkers via AuthplaneClient + ResourceOptions.
 */
class RevocationTest {

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
    void resetStubs() {
        wireMock.resetAll();
        // Stub JWKS endpoint used by all tests
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

    /**
     * Stubs metadata with the standard issuer pointing to WireMock so that the client's metadata
     * discovery succeeds. Uses TestFixtures.ISSUER as the issuer value for tokens that use the
     * default issuer.
     */
    private void stubMetadataForIssuer(String issuer) {
        String metadataBody =
                TestFixtures.serializeMap(Map.of("issuer", issuer, "jwks_uri", baseUrl + "/jwks"));
        wireMock.stubFor(
                get(urlEqualTo("/.well-known/oauth-authorization-server"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(metadataBody)));
    }

    /** Creates a client with metadata discovery pointing to WireMock (issuer=baseUrl). */
    private AuthplaneClient buildClient() throws Exception {
        stubMetadataForIssuer(baseUrl);
        return AuthplaneClient.builder(baseUrl).devMode(true).build().get();
    }

    /** Creates a verifier from a client with the given verifier options. */
    private AuthplaneResource buildVerifier(AuthplaneClient client, ResourceOptions options) {
        return client.resource(TestFixtures.RESOURCE, List.of("read:data"), options);
    }

    /** Token signed with the WireMock server as issuer. */
    private String localIssuerToken() {
        return TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).build();
    }

    // -----------------------------------------------------------------------
    // Revocation disabled (null)
    // -----------------------------------------------------------------------

    @Test
    void verify_revocationDisabled_noOpChecker_returnsClaimsWithoutChecking() throws Exception {
        AuthplaneClient client = buildClient();
        AuthplaneResource verifier =
                buildVerifier(
                        client,
                        ResourceOptions.builder()
                                .revocationChecker(RevocationChecker.noOp())
                                .build());

        VerifiedClaims claims = verifier.verify(localIssuerToken()).get().claims();
        assertThat(claims.jti()).isEqualTo(TestFixtures.JTI);
    }

    // -----------------------------------------------------------------------
    // Custom revocation checker
    // -----------------------------------------------------------------------

    @Test
    void verify_customChecker_accepts_returnsVerifiedClaims() throws Exception {
        RevocationChecker acceptAll = (token, jti) -> false;
        AuthplaneClient client = buildClient();
        AuthplaneResource verifier =
                buildVerifier(
                        client, ResourceOptions.builder().revocationChecker(acceptAll).build());

        VerifiedClaims claims = verifier.verify(localIssuerToken()).get().claims();
        assertThat(claims.sub()).isEqualTo(TestFixtures.SUBJECT);
    }

    @Test
    void verify_customChecker_rejectsKnownJti_throwsTokenRevoked() throws Exception {
        RevocationChecker rejectAll = (token, jti) -> true;
        AuthplaneClient client = buildClient();
        AuthplaneResource verifier =
                buildVerifier(
                        client, ResourceOptions.builder().revocationChecker(rejectAll).build());

        assertThatThrownBy(() -> verifier.verify(localIssuerToken()).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(TokenRevokedException.class)
                .hasMessageContaining(TestFixtures.JTI);
    }

    @Test
    void verify_customChecker_specificJti_rejectsOnlyMatchingToken() throws Exception {
        String targetJti = TestFixtures.JTI;
        RevocationChecker selective = (token, jti) -> targetJti.equals(jti);
        AuthplaneClient client = buildClient();
        AuthplaneResource verifier =
                buildVerifier(
                        client, ResourceOptions.builder().revocationChecker(selective).build());

        // Token with the targeted jti -> rejected
        assertThatThrownBy(() -> verifier.verify(localIssuerToken()).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(TokenRevokedException.class);

        // Token with a different jti -> accepted
        String otherToken =
                TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).jti("other-jti").build();
        VerifiedClaims claims = verifier.verify(otherToken).get().claims();
        assertThat(claims.jti()).isEqualTo("other-jti");
    }

    @Test
    void verify_customChecker_throwsException_failOpenByDefault() throws Exception {
        RevocationChecker broken =
                (token, jti) -> {
                    throw new RuntimeException("checker exploded");
                };
        AuthplaneClient client = buildClient();
        AuthplaneResource verifier =
                buildVerifier(client, ResourceOptions.builder().revocationChecker(broken).build());

        // Default is fail-open: checker exception is swallowed, token accepted
        VerifiedClaims claims = verifier.verify(localIssuerToken()).get().claims();
        assertThat(claims.jti()).isEqualTo(TestFixtures.JTI);
    }

    @Test
    void verify_customChecker_throwsException_failClosed_rejectsToken() throws Exception {
        RevocationChecker broken =
                (token, jti) -> {
                    throw new RuntimeException("checker exploded");
                };
        AuthplaneClient client = buildClient();
        AuthplaneResource verifier =
                buildVerifier(
                        client,
                        ResourceOptions.builder().revocationChecker(broken).failClosed().build());

        assertThatThrownBy(() -> verifier.verify(localIssuerToken()).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(TokenRevokedException.class);
    }

    // -----------------------------------------------------------------------
    // Built-in introspection (default)
    // -----------------------------------------------------------------------

    @Test
    void verify_builtinIntrospection_noEndpointInMetadata_failsOpen() throws Exception {
        // Metadata has no introspection_endpoint -> fail-open
        AuthplaneClient client = buildClient();
        AuthplaneResource verifier =
                buildVerifier(
                        client, ResourceOptions.builder().useBuiltinRevocationChecker().build());

        // Introspection endpoint absent -> fail-open
        VerifiedClaims claims = verifier.verify(localIssuerToken()).get().claims();
        assertThat(claims.jti()).isEqualTo(TestFixtures.JTI);
    }

    @Test
    void verify_builtinIntrospection_activeTrue_returnsVerifiedClaims() throws Exception {
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
                                                        + "\"introspection_endpoint\":\""
                                                        + baseUrl
                                                        + "/introspect\"}")));

        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"active\":true}")));

        AuthplaneClient client = AuthplaneClient.builder(baseUrl).devMode(true).build().get();
        AuthplaneResource verifier =
                buildVerifier(
                        client, ResourceOptions.builder().useBuiltinRevocationChecker().build());

        VerifiedClaims claims = verifier.verify(localIssuerToken()).get().claims();
        assertThat(claims.jti()).isEqualTo(TestFixtures.JTI);
    }

    @Test
    void verify_builtinIntrospection_activeFalse_throwsTokenRevoked() throws Exception {
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
                                                        + "\"introspection_endpoint\":\""
                                                        + baseUrl
                                                        + "/introspect\"}")));

        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"active\":false}")));

        AuthplaneClient client = AuthplaneClient.builder(baseUrl).devMode(true).build().get();
        AuthplaneResource verifier =
                buildVerifier(
                        client, ResourceOptions.builder().useBuiltinRevocationChecker().build());

        assertThatThrownBy(() -> verifier.verify(localIssuerToken()).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(TokenRevokedException.class);
    }

    @Test
    void verify_defaultRevocation_noRevocationCheck() throws Exception {
        // Default (no revocation options) = no revocation checking.
        // Token is accepted without any introspection call.
        AuthplaneClient client = buildClient();
        AuthplaneResource verifier = buildVerifier(client, ResourceOptions.defaults());
        VerifiedClaims claims = verifier.verify(localIssuerToken()).get().claims();
        assertThat(claims.jti()).isEqualTo(TestFixtures.JTI);
    }
}
