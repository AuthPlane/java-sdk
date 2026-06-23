package ai.authplane.sdk.spring.mcp;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import ai.authplane.sdk.core.ASCredentials;
import ai.authplane.sdk.core.AuthProvider;
import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.RevocationChecker;
import ai.authplane.sdk.core.dpop.DPoPProvider;
import ai.authplane.sdk.core.dpop.InMemoryDPoPReplayStore;
import ai.authplane.sdk.core.dpop.InboundDPoPOptions;
import ai.authplane.sdk.core.dpop.OutboundDPoPOptions;

@ExtendWith(MockitoExtension.class)
class AuthplaneMcpServerConfigTest {

    static WireMockServer wireMock;
    static String baseUrl;
    static String jwksJson;

    @Mock ObjectProvider<RevocationChecker> revocationCheckerProvider;

    @Mock ObjectProvider<OutboundDPoPOptions> outboundDPoPProvider;

    @Mock ObjectProvider<Executor> executorProvider;

    @Mock ObjectProvider<InboundDPoPOptions> inboundDPoPProvider;

    @Mock ObjectProvider<AuthProvider> authProviderProvider;

    final AuthplaneMcpServerConfig config = new AuthplaneMcpServerConfig();

    @BeforeAll
    static void startWireMock() throws Exception {
        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();
        baseUrl = "http://localhost:" + wireMock.port();

        RSAKey rsaKey =
                new RSAKeyGenerator(2048)
                        .keyID("test-key-1")
                        .algorithm(JWSAlgorithm.RS256)
                        .keyUse(KeyUse.SIGNATURE)
                        .generate();
        jwksJson = toJwksJson(rsaKey);
    }

    @AfterAll
    static void stopWireMock() {
        wireMock.stop();
    }

    @BeforeEach
    void setupStubs() {
        wireMock.resetAll();
        stubMetadataAndJwks(null);
    }

    // -----------------------------------------------------------------------
    // Basic build
    // -----------------------------------------------------------------------

    @Test
    void authplaneClient_basicBuild_succeeds() throws Exception {
        AuthplaneClient client = buildClient(0);
        assertThat(client).isNotNull();
        assertThat(client.issuer()).isEqualTo(baseUrl);
    }

    @Test
    void authplaneVerifier_basicBuild_succeeds() throws Exception {
        AuthplaneClient client = buildClient(0);
        AuthplaneResource v = buildVerifier(client, false);

        assertThat(v).isNotNull();
        assertThat(v.prmResponse()).containsEntry("resource", baseUrl + "/mcp");
    }

    // -----------------------------------------------------------------------
    // Credentials (AuthProvider bean)
    // -----------------------------------------------------------------------

    @Test
    void authplaneClient_withCredentials_succeeds() throws Exception {
        when(authProviderProvider.getIfAvailable())
                .thenReturn(new ASCredentials("my-client", "my-secret"));

        AuthplaneClient client = buildClient(0);
        assertThat(client).isNotNull();
    }

    // -----------------------------------------------------------------------
    // Built-in revocation checker (authplane.introspection.enabled=true)
    // -----------------------------------------------------------------------

    @Test
    void authplaneVerifier_introspectionEnabled_withCredentials_succeeds() throws Exception {
        wireMock.resetAll();
        stubMetadataAndJwks(baseUrl + "/introspect");
        when(authProviderProvider.getIfAvailable())
                .thenReturn(new ASCredentials("my-client", "my-secret"));

        AuthplaneClient client = buildClient(0);
        AuthplaneResource v = buildVerifier(client, true);

        assertThat(v).isNotNull();
    }

    // -----------------------------------------------------------------------
    // Custom RevocationChecker bean takes precedence over introspection flag
    // -----------------------------------------------------------------------

    @Test
    void authplaneVerifier_customRevocationCheckerBean_preferred() throws Exception {
        RevocationChecker customChecker = (token, jti) -> false;
        when(revocationCheckerProvider.getIfAvailable()).thenReturn(customChecker);

        AuthplaneClient client = buildClient(0);
        // introspectionEnabled=true should be overridden by the bean
        AuthplaneResource v = buildVerifier(client, true);

        assertThat(v).isNotNull();
    }

    // -----------------------------------------------------------------------
    // Custom timeout (authplane.timeout-seconds > 0)
    // -----------------------------------------------------------------------

    @Test
    void authplaneClient_withTimeout_succeeds() throws Exception {
        AuthplaneClient client = buildClient(5);
        assertThat(client).isNotNull();
    }

    // -----------------------------------------------------------------------
    // Other bean methods
    // -----------------------------------------------------------------------

    @Test
    void authplaneMcpServerAdapter_wrapsVerifier() throws Exception {
        AuthplaneClient client = buildClient(0);
        AuthplaneResource v = buildVerifier(client, false);
        var adapter = config.authplaneMcpServerAdapter(v);
        assertThat(adapter).isNotNull();
    }

    @Test
    void authplanePrmEndpoint_returnsRouterFunction() throws Exception {
        AuthplaneClient client = buildClient(0);
        AuthplaneResource v = buildVerifier(client, false);
        var router = config.authplanePrmEndpoint(v);
        assertThat(router).isNotNull();
    }

    @Test
    void webMvcStreamableServerTransportProvider_isBuilt() throws Exception {
        AuthplaneClient client = buildClient(0);
        AuthplaneResource v = buildVerifier(client, false);
        var adapter = config.authplaneMcpServerAdapter(v);

        var provider = config.webMvcStreamableServerTransportProvider(adapter);

        assertThat(provider).isNotNull();
    }

    // -----------------------------------------------------------------------
    // Config branch coverage: circuit breaker, token cache TTL, custom executor
    // -----------------------------------------------------------------------

    @Test
    void authplaneClient_circuitBreakerOverrides_succeed() throws Exception {
        AuthplaneClient client =
                config.authplaneClient(
                        baseUrl,
                        true,
                        300,
                        3600,
                        0,
                        7,
                        45,
                        15,
                        0, // tokenCacheDefaultTtlSeconds
                        0, // tokenCacheMaxEntries
                        outboundDPoPProvider,
                        executorProvider,
                        authProviderProvider);

        assertThat(client).isNotNull();
    }

    @Test
    void authplaneClient_withCustomExecutor_applied() throws Exception {
        Executor exec = ForkJoinPool.commonPool();
        when(executorProvider.getIfAvailable()).thenReturn(exec);

        AuthplaneClient client = buildClient(0);

        assertThat(client).isNotNull();
        verify(executorProvider).getIfAvailable();
    }

    // -----------------------------------------------------------------------
    // Optional bean branches (custom AuthProvider / outbound + inbound DPoP)
    // and the token-cache default-substitution branch.
    // -----------------------------------------------------------------------

    @Test
    void authplaneClient_customAuthProviderBean_applied() throws Exception {
        AuthProvider custom = () -> Map.of("Authorization", "Bearer custom");
        when(authProviderProvider.getIfAvailable()).thenReturn(custom);

        AuthplaneClient client = buildClient(0);

        assertThat(client).isNotNull();
    }

    @Test
    void authplaneClient_outboundDpopBean_applied() throws Exception {
        when(outboundDPoPProvider.getIfAvailable())
                .thenReturn(new OutboundDPoPOptions(mock(DPoPProvider.class)));

        AuthplaneClient client = buildClient(0);

        assertThat(client).isNotNull();
    }

    @Test
    void authplaneClient_tokenCacheDefaultTtlBuffer_substituted() throws Exception {
        // ttlBuffer=0 with defaultTtl>0 keeps the config non-null while exercising the
        // DEFAULT_TTL_BUFFER_SECONDS substitution branch.
        AuthplaneClient client =
                config.authplaneClient(
                        baseUrl,
                        true,
                        300,
                        3600,
                        0,
                        0,
                        0,
                        0, // tokenCacheTtlBufferSeconds = 0 -> DEFAULT branch
                        120, // tokenCacheDefaultTtlSeconds > 0
                        0,
                        outboundDPoPProvider,
                        executorProvider,
                        authProviderProvider);

        assertThat(client).isNotNull();
    }

    @Test
    void authplaneResource_inboundDpopBean_applied() throws Exception {
        when(inboundDPoPProvider.getIfAvailable())
                .thenReturn(InboundDPoPOptions.defaults(new InMemoryDPoPReplayStore()));

        AuthplaneResource v = buildVerifier(buildClient(0), false);

        assertThat(v).isNotNull();
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /** Calls authplaneClient() with the given timeout argument. */
    private AuthplaneClient buildClient(int timeoutSeconds) throws Exception {
        return config.authplaneClient(
                baseUrl, // issuer
                true, // devMode — allow HTTP to localhost
                300, // jwksRefreshSeconds
                3600, // metadataRefreshSeconds
                timeoutSeconds,
                0, // circuitBreakerThreshold
                0, // circuitBreakerCooldownSeconds
                0, // tokenCacheTtlBufferSeconds
                0, // tokenCacheDefaultTtlSeconds
                0, // tokenCacheMaxEntries
                outboundDPoPProvider,
                executorProvider,
                authProviderProvider);
    }

    /** Calls authplaneVerifier() with the given client and introspection flag. */
    private AuthplaneResource buildVerifier(AuthplaneClient client, boolean introspectionEnabled) {
        return config.authplaneResource(
                client,
                baseUrl + "/mcp", // resource
                List.of("tools/add"),
                List.of("RS256"),
                30, // clockSkewSeconds
                introspectionEnabled,
                revocationCheckerProvider,
                inboundDPoPProvider);
    }

    private void stubMetadataAndJwks(String introspectionUrl) {
        StringBuilder meta =
                new StringBuilder()
                        .append("{\"issuer\":\"")
                        .append(baseUrl)
                        .append("\",")
                        .append("\"jwks_uri\":\"")
                        .append(baseUrl)
                        .append("/jwks\"");
        if (introspectionUrl != null) {
            meta.append(",\"introspection_endpoint\":\"").append(introspectionUrl).append("\"");
        }
        meta.append("}");

        wireMock.stubFor(
                get(urlEqualTo("/.well-known/oauth-authorization-server"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(meta.toString())));
        wireMock.stubFor(
                get(urlEqualTo("/jwks"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(jwksJson)));
    }

    private static String toJwksJson(RSAKey rsaKey) {
        return "{\"keys\":[" + jsonObject(rsaKey.toPublicJWK().toJSONObject()) + "]}";
    }

    private static String jsonObject(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : map.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(e.getKey()).append("\":").append(jsonValue(e.getValue()));
        }
        return sb.append("}").toString();
    }

    @SuppressWarnings("unchecked")
    private static String jsonValue(Object v) {
        if (v instanceof String s) return "\"" + s.replace("\"", "\\\"") + "\"";
        if (v instanceof Number || v instanceof Boolean) return v.toString();
        if (v instanceof List<?> list) {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append(jsonValue(list.get(i)));
            }
            return sb.append("]").toString();
        }
        if (v instanceof Map<?, ?> m) return jsonObject((Map<String, Object>) m);
        return "null";
    }
}
