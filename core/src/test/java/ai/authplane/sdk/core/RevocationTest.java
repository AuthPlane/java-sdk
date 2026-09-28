package ai.authplane.sdk.core;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

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

    /** Stubs metadata (issuer=baseUrl) that also advertises an introspection endpoint. */
    private void stubMetadataWithIntrospection() {
        String metadataBody =
                TestFixtures.serializeMap(
                        Map.of(
                                "issuer",
                                baseUrl,
                                "jwks_uri",
                                baseUrl + "/jwks",
                                "introspection_endpoint",
                                baseUrl + "/introspect"));
        wireMock.stubFor(
                get(urlEqualTo("/.well-known/oauth-authorization-server"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(metadataBody)));
    }

    private void stubIntrospection(String body) {
        wireMock.stubFor(
                post(urlEqualTo("/introspect"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(body)));
    }

    /** Runs {@code body} while capturing WARNING records emitted by the built-in checker. */
    private static List<LogRecord> captureCheckerWarnings(ThrowingRunnable body) throws Exception {
        Logger logger = Logger.getLogger(IntrospectionChecker.class.getName());
        List<LogRecord> records = new ArrayList<>();
        Handler handler =
                new Handler() {
                    @Override
                    public void publish(LogRecord record) {
                        if (record.getLevel().intValue() >= Level.WARNING.intValue()) {
                            records.add(record);
                        }
                    }

                    @Override
                    public void flush() {}

                    @Override
                    public void close() {}
                };
        logger.addHandler(handler);
        try {
            body.run();
        } finally {
            logger.removeHandler(handler);
        }
        return records;
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
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

    /**
     * The interrupt arm also restores the flag the catch consumed. That half is not asserted here:
     * verify() runs on the common ForkJoinPool, whose worker clears the flag as the task completes,
     * so it is no longer readable from this thread by the time get() returns.
     */
    @Test
    void verify_customChecker_interrupted_failOpenByDefault() throws Exception {
        RevocationChecker interrupted =
                (token, jti) -> {
                    throw new InterruptedException("executor shutting down");
                };
        AuthplaneClient client = buildClient();
        AuthplaneResource verifier =
                buildVerifier(
                        client, ResourceOptions.builder().revocationChecker(interrupted).build());

        VerifiedClaims claims = verifier.verify(localIssuerToken()).get().claims();

        assertThat(claims.jti()).isEqualTo(TestFixtures.JTI);
    }

    @Test
    void verify_customChecker_interrupted_failClosed_rejectsAsInterruptedNotRevoked()
            throws Exception {
        RevocationChecker interrupted =
                (token, jti) -> {
                    throw new InterruptedException("executor shutting down");
                };
        AuthplaneClient client = buildClient();
        AuthplaneResource verifier =
                buildVerifier(
                        client,
                        ResourceOptions.builder()
                                .revocationChecker(interrupted)
                                .failClosed()
                                .build());

        assertThatThrownBy(() -> verifier.verify(localIssuerToken()).get())
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(TokenRevokedException.class)
                .hasMessageContaining("revocation check was interrupted");
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
    void builtinIntrospection_withoutAuthProvider_warnsAtConstruction() throws Exception {
        // authserver >= 0.1.2 answers active=false to unauthenticated introspection, so a checker
        // wired without credentials rejects every token; say so when it is built, not per token.
        stubMetadataWithIntrospection();
        AuthplaneClient client = AuthplaneClient.builder(baseUrl).devMode(true).build().get();

        List<LogRecord> warnings =
                captureCheckerWarnings(
                        () ->
                                buildVerifier(
                                        client,
                                        ResourceOptions.builder()
                                                .useBuiltinRevocationChecker()
                                                .build()));

        assertThat(warnings).hasSize(1);
        assertThat(warnings.get(0).getMessage())
                .contains("without an AuthProvider")
                .contains("active=false")
                .contains("runtime-client");
    }

    @Test
    void builtinIntrospection_withAuthProvider_noConstructionWarning() throws Exception {
        stubMetadataWithIntrospection();
        AuthplaneClient client =
                AuthplaneClient.builder(baseUrl)
                        .devMode(true)
                        .authProvider(new ASCredentials("my-rs", "s3cret"))
                        .build()
                        .get();

        List<LogRecord> warnings =
                captureCheckerWarnings(
                        () ->
                                buildVerifier(
                                        client,
                                        ResourceOptions.builder()
                                                .useBuiltinRevocationChecker()
                                                .build()));

        assertThat(warnings).isEmpty();
    }

    @Test
    void builtinIntrospection_activeFalseAfterLocalVerify_logsOwnershipWarningOnce()
            throws Exception {
        stubMetadataWithIntrospection();
        stubIntrospection("{\"active\":false}");
        AuthplaneClient client =
                AuthplaneClient.builder(baseUrl)
                        .devMode(true)
                        .authProvider(new ASCredentials("my-rs", "s3cret"))
                        .build()
                        .get();
        AuthplaneResource verifier =
                buildVerifier(
                        client, ResourceOptions.builder().useBuiltinRevocationChecker().build());

        List<LogRecord> warnings =
                captureCheckerWarnings(
                        () -> {
                            for (int i = 0; i < 2; i++) {
                                assertThatThrownBy(() -> verifier.verify(localIssuerToken()).get())
                                        .isInstanceOf(ExecutionException.class)
                                        .cause()
                                        .isInstanceOf(TokenRevokedException.class);
                            }
                        });

        // Two rejected tokens, one warning: the guidance is logged once per checker.
        assertThat(warnings).hasSize(1);
        assertThat(warnings.get(0).getMessage())
                .contains("jti='" + TestFixtures.JTI + "'")
                .contains("passed local JWT verification")
                .contains("runtime-client add --client-id <rs-client-id> --slug <resource-slug>");
    }

    @Test
    void builtinIntrospection_activeTrue_noOwnershipWarning() throws Exception {
        stubMetadataWithIntrospection();
        stubIntrospection("{\"active\":true}");
        AuthplaneClient client =
                AuthplaneClient.builder(baseUrl)
                        .devMode(true)
                        .authProvider(new ASCredentials("my-rs", "s3cret"))
                        .build()
                        .get();
        AuthplaneResource verifier =
                buildVerifier(
                        client, ResourceOptions.builder().useBuiltinRevocationChecker().build());

        List<LogRecord> warnings =
                captureCheckerWarnings(() -> verifier.verify(localIssuerToken()).get());

        assertThat(warnings).isEmpty();
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
