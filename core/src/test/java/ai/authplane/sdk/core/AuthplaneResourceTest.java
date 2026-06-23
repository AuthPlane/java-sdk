package ai.authplane.sdk.core;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import ai.authplane.sdk.core.errors.AuthplaneException;
import ai.authplane.sdk.core.errors.InsufficientScopeException;
import ai.authplane.sdk.core.errors.InvalidClaimsException;
import ai.authplane.sdk.core.errors.InvalidSignatureException;
import ai.authplane.sdk.core.errors.TokenExpiredException;

class AuthplaneResourceTest {

    private static WireMockServer wireMock;
    private static TestFixtures.RSAKeyPair rsaKeys;
    private static String baseUrl;

    private AuthplaneClient client;
    private AuthplaneResource resource;

    @BeforeAll
    static void startWireMock() {
        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();
        baseUrl = "http://localhost:" + wireMock.port();
        rsaKeys = TestFixtures.generateRsaKeyPair();
    }

    @AfterAll
    static void stopWireMock() {
        wireMock.stop();
    }

    @BeforeEach
    void setupStubs() throws Exception {
        wireMock.resetAll();
        stubMetadata();
        stubJwks();
    }

    // -----------------------------------------------------------------------
    // Setup helpers
    // -----------------------------------------------------------------------

    private void stubMetadata() {
        String jwksUrl = baseUrl + "/jwks";
        String metadataBody =
                TestFixtures.serializeMap(Map.of("issuer", baseUrl, "jwks_uri", jwksUrl));
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

    private AuthplaneResource createResource() throws Exception {
        client = AuthplaneClient.builder(baseUrl).devMode(true).build().get();
        return client.resource(TestFixtures.RESOURCE, TestFixtures.SCOPES);
    }

    private AuthplaneResource createResource(String resourceUri) throws Exception {
        client = AuthplaneClient.builder(baseUrl).devMode(true).build().get();
        return client.resource(resourceUri, TestFixtures.SCOPES);
    }

    /**
     * Builds a valid token using the baseUrl as issuer to match the resource's configuration. The
     * resource is built with baseUrl as the issuer, so tokens must carry iss=baseUrl.
     */
    private String validToken() {
        return TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).build();
    }

    // -----------------------------------------------------------------------
    // Happy path
    // -----------------------------------------------------------------------

    @Test
    void verify_validToken_returnsVerifiedClaims() throws Exception {
        resource = createResource();
        VerifiedClaims claims = resource.verify(validToken()).get().claims();

        assertThat(claims.sub()).isEqualTo(TestFixtures.SUBJECT);
        assertThat(claims.clientId()).isEqualTo(TestFixtures.CLIENT_ID);
        assertThat(claims.issuer()).isEqualTo(baseUrl);
        assertThat(claims.audience()).containsExactly(TestFixtures.RESOURCE);
        assertThat(claims.jti()).isEqualTo(TestFixtures.JTI);
        assertThat(claims.scopes()).contains("read:data", "write:data");

        // hasClaim variants
        assertThat(claims.hasClaim("sub")).isTrue();
        assertThat(claims.hasClaim("nonexistent_claim")).isFalse();
        assertThat(claims.hasClaim("sub", TestFixtures.SUBJECT)).isTrue();
        assertThat(claims.hasClaim("sub", "wrong-value")).isFalse();
    }

    @Test
    void verify_multiAudienceToken_withResource_accepted() throws Exception {
        // Token contains [resource, "https://other.example.com"] — the SDK must accept
        // it because the configured resource is present. audience() returns all values.
        resource = createResource();
        String token =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .issuer(baseUrl)
                        .audienceList(List.of(TestFixtures.RESOURCE, "https://other.example.com"))
                        .build();
        VerifiedClaims claims = resource.verify(token).get().claims();
        assertThat(claims.audience())
                .containsExactlyInAnyOrder(TestFixtures.RESOURCE, "https://other.example.com");
    }

    @Test
    void verify_hasScope_returnsTrue_forGrantedScope() throws Exception {
        resource = createResource();
        VerifiedClaims claims = resource.verify(validToken()).get().claims();
        assertThat(claims.hasScope("read:data")).isTrue();
    }

    @Test
    void verify_hasScope_returnsFalse_forAbsentScope() throws Exception {
        resource = createResource();
        VerifiedClaims claims = resource.verify(validToken()).get().claims();
        assertThat(claims.hasScope("admin:delete")).isFalse();
    }

    @Test
    void verify_requireScope_throws_InsufficientScope() throws Exception {
        resource = createResource();
        VerifiedClaims claims = resource.verify(validToken()).get().claims();
        assertThatThrownBy(() -> claims.requireScope("admin:delete"))
                .isInstanceOf(InsufficientScopeException.class);
    }

    // -----------------------------------------------------------------------
    // Algorithm rejection
    // -----------------------------------------------------------------------

    @Test
    void verify_rejects_algNotInAllowlist() throws Exception {
        // Create a client, then a resource that only allows RS256;
        // an ES256 token must be rejected at the alg-check step
        client = AuthplaneClient.builder(baseUrl).devMode(true).build().get();
        AuthplaneResource rsOnlyResource =
                client.resource(
                        TestFixtures.RESOURCE,
                        TestFixtures.SCOPES,
                        ResourceOptions.builder().allowedAlgorithms(List.of("RS256")).build());
        TestFixtures.ECKeyPair ecKeys = TestFixtures.generateEcKeyPair();
        String token = TestFixtures.token().ecKey(ecKeys).alg("ES256").issuer(baseUrl).build();
        assertThatThrownBy(
                        () -> {
                            try {
                                rsOnlyResource.verify(token).get();
                            } catch (ExecutionException e) {
                                throw e.getCause();
                            }
                        })
                .isInstanceOf(InvalidClaimsException.class);
    }

    // -----------------------------------------------------------------------
    // JWT header validation
    // -----------------------------------------------------------------------

    @Test
    void verify_rejects_wrongTypHeader() throws Exception {
        resource = createResource();
        String token = TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).typ("JWT").build();
        assertVerifyThrows(token, InvalidClaimsException.class);
    }

    // -----------------------------------------------------------------------
    // Claims validation
    // -----------------------------------------------------------------------

    @Test
    void verify_rejects_wrongIssuer() throws Exception {
        resource = createResource();
        String token =
                TestFixtures.token().rsaKey(rsaKeys).issuer("https://evil.example.com").build();
        assertVerifyThrows(token, InvalidClaimsException.class);
    }

    @Test
    void verify_rejects_wrongAudience() throws Exception {
        resource = createResource();
        String token =
                TestFixtures.token()
                        .rsaKey(rsaKeys)
                        .issuer(baseUrl)
                        .audience("https://other.example.com")
                        .build();
        assertVerifyThrows(token, InvalidClaimsException.class);
    }

    @Test
    void verify_rejects_expiredToken() throws Exception {
        resource = createResource();
        String token = TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).expired().build();
        assertVerifyThrows(token, TokenExpiredException.class);
    }

    @Test
    void verify_rejects_futureIat() throws Exception {
        resource = createResource();
        long future = System.currentTimeMillis() / 1000L + 9999;
        String token =
                TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).issuedAt(future).build();
        assertVerifyThrows(token, InvalidClaimsException.class);
    }

    @Test
    void verify_rejects_missingClientId() throws Exception {
        resource = createResource();
        // Build token without client_id (null means omit the claim)
        String token = TestFixtures.token().rsaKey(rsaKeys).issuer(baseUrl).clientId(null).build();
        assertVerifyThrows(token, InvalidClaimsException.class);
    }

    @Test
    void verify_rejects_malformedJwt() throws Exception {
        resource = createResource();
        assertVerifyThrows("not.a.jwt", InvalidSignatureException.class);
    }

    @Test
    void verify_rejects_nullToken() throws Exception {
        resource = createResource();
        assertVerifyThrows(null, InvalidClaimsException.class);
    }

    // -----------------------------------------------------------------------
    // Signature validation
    // -----------------------------------------------------------------------

    @Test
    void verify_rejects_wrongSignature() throws Exception {
        resource = createResource();
        // Sign with different key pair — signature won't match JWKS key
        TestFixtures.RSAKeyPair otherKeys = TestFixtures.generateRsaKeyPair();
        String token = TestFixtures.token().rsaKey(otherKeys).issuer(baseUrl).build();
        assertVerifyThrows(token, InvalidSignatureException.class);
    }

    // -----------------------------------------------------------------------
    // PRM
    // -----------------------------------------------------------------------

    @Test
    void prmResponse_containsAllRequiredFields() throws Exception {
        resource = createResource();
        var prm = resource.prmResponse();
        assertThat(prm).containsKey("resource");
        assertThat(prm).containsKey("authorization_servers");
        assertThat(prm).containsKey("bearer_methods_supported");
        assertThat(prm).containsKey("scopes_supported");
        assertThat(prm.get("resource")).isEqualTo(TestFixtures.RESOURCE);
    }

    @Test
    void prmPath_simpleResource_returnsWellKnownPath() throws Exception {
        resource = createResource("https://api.example.com");
        assertThat(resource.prmPath()).isEqualTo("/.well-known/oauth-protected-resource");
    }

    @Test
    void prmUrl_simpleResource_returnsFullWellKnownUrl() throws Exception {
        resource = createResource("https://api.example.com");
        assertThat(resource.prmUrl())
                .isEqualTo("https://api.example.com/.well-known/oauth-protected-resource");
    }

    @Test
    void prmPath_resourceWithPathSuffix_appendsSuffix() throws Exception {
        resource = createResource("https://mcp.example.com/mcp");
        assertThat(resource.prmPath()).isEqualTo("/.well-known/oauth-protected-resource/mcp");
    }

    @Test
    void prmUrl_resourceWithPathSuffix_appendsSuffix() throws Exception {
        resource = createResource("https://mcp.example.com/mcp");
        assertThat(resource.prmUrl())
                .isEqualTo("https://mcp.example.com/.well-known/oauth-protected-resource/mcp");
    }

    @Test
    void normalizeRequestUrl_substitutesResourceHost_keepsRequestPath() throws Exception {
        resource = createResource("https://api.example.com/mcp");
        // The request arrives on an internal/proxy host; htu must use the canonical resource host
        // (proxy-independent) while keeping the request path.
        assertThat(resource.normalizeRequestUrl("http://10.0.0.5:8080/mcp"))
                .isEqualTo("https://api.example.com/mcp");
    }

    @Test
    void normalizeRequestUrl_keepsResourceSubPath() throws Exception {
        resource = createResource("https://my.mcp.org/mcp1");
        // Request to a sub-path of the resource binds htu to the full target URL.
        assertThat(resource.normalizeRequestUrl("http://internal-host/mcp1/tool"))
                .isEqualTo("https://my.mcp.org/mcp1/tool");
    }

    @Test
    void normalizeRequestUrl_ignoresQuery() throws Exception {
        resource = createResource("https://api.example.com/mcp");
        assertThat(resource.normalizeRequestUrl("https://api.example.com/mcp?x=1"))
                .isEqualTo("https://api.example.com/mcp");
    }

    @Test
    void path_returnsResourceUriPath() throws Exception {
        resource = createResource("https://mcp.example.com/mcp");
        assertThat(resource.path()).isEqualTo("/mcp");
    }

    @Test
    void path_resourceWithoutPath_returnsEmpty() throws Exception {
        resource = createResource("https://api.example.com");
        assertThat(resource.path()).isEmpty();
    }

    // -----------------------------------------------------------------------
    // JWKS key rotation
    // -----------------------------------------------------------------------

    @Test
    void verify_forceRefreshesJwks_whenKidNotFound() throws Exception {
        // Initially serve empty JWKS
        wireMock.stubFor(
                get(urlEqualTo("/jwks"))
                        .inScenario("rotation")
                        .whenScenarioStateIs("Started")
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody("{\"keys\":[]}"))
                        .willSetStateTo("rotated"));

        // After first call, serve the real key
        wireMock.stubFor(
                get(urlEqualTo("/jwks"))
                        .inScenario("rotation")
                        .whenScenarioStateIs("rotated")
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                TestFixtures.serializeMap(
                                                        rsaKeys.jwksDocument()))));

        resource = createResource();
        // Should succeed because it force-refreshes when kid not found
        VerifiedClaims claims = resource.verify(validToken()).get().claims();
        assertThat(claims.sub()).isEqualTo(TestFixtures.SUBJECT);
    }

    @Test
    void verify_rejectsJwkMarkedForEncryptionOnly() throws Exception {
        Map<String, Object> badKey = new LinkedHashMap<>(rsaKeys.publicJwkMap());
        badKey.put("use", "enc");
        badKey.put("key_ops", List.of("encrypt"));
        wireMock.stubFor(
                get(urlEqualTo("/jwks"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                TestFixtures.serializeMap(
                                                        Map.of("keys", List.of(badKey))))));

        resource = createResource();
        assertVerifyThrows(validToken(), InvalidSignatureException.class);
    }

    // -----------------------------------------------------------------------
    // JWKS URI rotation (jwksCache field update)
    // -----------------------------------------------------------------------

    @Test
    void verify_usesRotatedJwksCache_afterJwksUriRotation() throws Exception {
        // A second, independent key pair — the kid is the same ("test-key-1") but
        // the key material is entirely different, so a token signed with rotatedKeys
        // cannot be verified using the original keys and vice-versa.
        TestFixtures.RSAKeyPair rotatedKeys = TestFixtures.generateRsaKeyPair();
        String rotatedJwksBody = TestFixtures.serializeMap(rotatedKeys.jwksDocument());

        wireMock.stubFor(
                get(urlEqualTo("/jwks2"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(rotatedJwksBody)));

        resource = createResource();

        // Baseline: token signed with the original keys must verify.
        assertThat(resource.verify(validToken()).get().claims().sub())
                .isEqualTo(TestFixtures.SUBJECT);

        // Update the AS metadata so jwks_uri now points to /jwks2.
        String updatedMetadata =
                TestFixtures.serializeMap(
                        Map.of("issuer", baseUrl, "jwks_uri", baseUrl + "/jwks2"));
        wireMock.stubFor(
                get(urlEqualTo("/.well-known/oauth-authorization-server"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(updatedMetadata)));

        // Force a metadata refresh on the client — this triggers the rotation callback
        // synchronously, which creates a new JwksCache pointing at /jwks2.
        client.forceMetadataRefreshForTest();

        // A token signed with the rotated keys must now verify successfully.
        String tokenWithRotatedKey =
                TestFixtures.token().rsaKey(rotatedKeys).issuer(baseUrl).build();
        VerifiedClaims claims = resource.verify(tokenWithRotatedKey).get().claims();
        assertThat(claims.sub()).isEqualTo(TestFixtures.SUBJECT);
    }

    // -----------------------------------------------------------------------
    // Builder setters exercise (via client builder + resource options)
    // -----------------------------------------------------------------------

    @Test
    void builder_setters_areChainableAndApplied() throws Exception {
        // Exercises clockSkewSeconds(), jwksRefreshSeconds(), metadataRefreshSeconds()
        // The resource must still build and work — values just need not to throw.
        client =
                AuthplaneClient.builder(baseUrl)
                        .devMode(true)
                        .jwksRefreshSeconds(120)
                        .metadataRefreshSeconds(600)
                        .build()
                        .get();
        resource =
                client.resource(
                        TestFixtures.RESOURCE,
                        TestFixtures.SCOPES,
                        ResourceOptions.builder().clockSkewSeconds(60).build());
        VerifiedClaims claims = resource.verify(validToken()).get().claims();
        assertThat(claims.sub()).isEqualTo(TestFixtures.SUBJECT);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private void assertVerifyThrows(
            String token, Class<? extends AuthplaneException> exceptionClass) throws Exception {
        assertThatThrownBy(
                        () -> {
                            try {
                                resource.verify(token).get();
                            } catch (ExecutionException e) {
                                throw e.getCause();
                            }
                        })
                .isInstanceOf(exceptionClass);
    }
}
