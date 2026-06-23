package ai.authplane.sdk.mcp;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import ai.authplane.sdk.core.ASCredentials;
import ai.authplane.sdk.core.RevocationChecker;
import ai.authplane.sdk.core.dpop.InMemoryDPoPReplayStore;
import ai.authplane.sdk.core.dpop.InboundDPoPOptions;
import ai.authplane.sdk.core.fetching.FetchSettings;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;

class AuthplaneMcpSetupTest {

    static WireMockServer wireMock;
    static String baseUrl;
    static String jwksJson;

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
        stubMetadataAndJwks(baseUrl + "/jwks", null);
    }

    // -----------------------------------------------------------------------
    // Builder setter methods — fluent chaining, no network needed
    // -----------------------------------------------------------------------

    @Test
    void builder_authProvider_returnsSelf() {
        AuthplaneMcpSetup.Builder builder = AuthplaneMcpSetup.builder();
        assertThat(builder.authProvider(new ASCredentials("cid", "secret"))).isSameAs(builder);
    }

    @Test
    void builder_useBuiltinRevocationChecker_returnsSelf() {
        AuthplaneMcpSetup.Builder builder = AuthplaneMcpSetup.builder();
        assertThat(builder.useBuiltinRevocationChecker()).isSameAs(builder);
    }

    @Test
    void builder_fetchSettings_returnsSelf() {
        AuthplaneMcpSetup.Builder builder = AuthplaneMcpSetup.builder();
        assertThat(builder.fetchSettings(FetchSettings.production())).isSameAs(builder);
    }

    // -----------------------------------------------------------------------
    // verifier() accessor — WireMock
    // -----------------------------------------------------------------------

    @Test
    void build_exposesAllAccessors() throws Exception {
        AuthplaneMcpSetup setup =
                AuthplaneMcpSetup.builder()
                        .issuer(baseUrl)
                        .resource(baseUrl + "/mcp")
                        .scopes(List.of("tools/query"))
                        .devMode(true)
                        .build()
                        .get();

        assertThat(setup.resource()).isNotNull();
        assertThat(setup.resource().prmResponse()).containsEntry("resource", baseUrl + "/mcp");
        assertThat(setup.adapter()).isNotNull();
        assertThat(setup.prmServlet()).isNotNull();
        assertThat(setup.mcpPath()).isEqualTo("/mcp");
        assertThat(setup.prmPath()).contains("oauth-protected-resource");
    }

    @Test
    void build_withCredentials_exposesVerifier() throws Exception {
        AuthplaneMcpSetup setup =
                AuthplaneMcpSetup.builder()
                        .issuer(baseUrl)
                        .resource(baseUrl + "/mcp")
                        .scopes(List.of("tools/query"))
                        .devMode(true)
                        .authProvider(new ASCredentials("my-client", "my-secret"))
                        .build()
                        .get();

        assertThat(setup.resource()).isNotNull();
    }

    @Test
    void build_withBuiltinRevocationChecker_exposesVerifier() throws Exception {
        // Metadata includes introspection_endpoint for built-in revocation checking
        wireMock.resetAll();
        stubMetadataAndJwks(baseUrl + "/jwks", baseUrl + "/introspect");

        AuthplaneMcpSetup setup =
                AuthplaneMcpSetup.builder()
                        .issuer(baseUrl)
                        .resource(baseUrl + "/mcp")
                        .scopes(List.of("tools/query"))
                        .devMode(true)
                        .authProvider(new ASCredentials("my-client", "my-secret"))
                        .useBuiltinRevocationChecker()
                        .build()
                        .get();

        assertThat(setup.resource()).isNotNull();
    }

    // -----------------------------------------------------------------------
    // Builder — optional methods coverage
    // -----------------------------------------------------------------------

    @Test
    void builder_optionalMethods_returnSelf() {
        AuthplaneMcpSetup.Builder b = AuthplaneMcpSetup.builder();
        assertThat(b.allowedAlgorithms(List.of("RS256"))).isSameAs(b);
        assertThat(b.clockSkewSeconds(30)).isSameAs(b);
        assertThat(b.jwksRefreshSeconds(600)).isSameAs(b);
        assertThat(b.metadataRefreshSeconds(7200)).isSameAs(b);
        assertThat(b.revocationChecker(RevocationChecker.noOp())).isSameAs(b);
    }

    @Test
    void build_withAllOptionalSettings() throws Exception {
        AuthplaneMcpSetup setup =
                AuthplaneMcpSetup.builder()
                        .issuer(baseUrl)
                        .resource(baseUrl + "/mcp")
                        .scopes(List.of("tools/query"))
                        .devMode(true)
                        .allowedAlgorithms(List.of("RS256"))
                        .clockSkewSeconds(30)
                        .jwksRefreshSeconds(600)
                        .metadataRefreshSeconds(7200)
                        .fetchSettings(FetchSettings.devMode())
                        .build()
                        .get();

        assertThat(setup.resource()).isNotNull();
    }

    // -----------------------------------------------------------------------
    // PRM served from the resource (single source) — DPoP advertisement
    // -----------------------------------------------------------------------

    @Test
    void prmServlet_advertisesDpop_whenInboundDpopRequired() throws Exception {
        InboundDPoPOptions dpop =
                new InboundDPoPOptions(
                        new InMemoryDPoPReplayStore(), 300, 30, Set.of("RS256", "ES256"), true);

        AuthplaneMcpSetup setup =
                AuthplaneMcpSetup.builder()
                        .issuer(baseUrl)
                        .resource(baseUrl + "/mcp")
                        .scopes(List.of("tools/query"))
                        .devMode(true)
                        .inboundDPoP(dpop)
                        .build()
                        .get();

        StringWriter writer = new StringWriter();
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse res = mock(HttpServletResponse.class);
        when(res.getWriter()).thenReturn(new PrintWriter(writer));

        setup.prmServlet().doGet(req, res);

        assertThat(writer.toString()).contains("\"dpop_bound_access_tokens_required\":true");
    }

    // -----------------------------------------------------------------------
    // registerServlets
    // -----------------------------------------------------------------------

    @Test
    void registerServlets_registersTransportAndPrm() throws Exception {
        AuthplaneMcpSetup setup =
                AuthplaneMcpSetup.builder()
                        .issuer(baseUrl)
                        .resource(baseUrl + "/mcp")
                        .scopes(List.of("tools/query"))
                        .devMode(true)
                        .build()
                        .get();

        HttpServletStreamableServerTransportProvider transport =
                HttpServletStreamableServerTransportProvider.builder()
                        .mcpEndpoint(setup.mcpPath())
                        .securityValidator(setup.adapter())
                        .contextExtractor(setup.adapter())
                        .build();

        ServletContext ctx = mock(ServletContext.class);
        ServletRegistration.Dynamic mcpReg = mock(ServletRegistration.Dynamic.class);
        ServletRegistration.Dynamic prmReg = mock(ServletRegistration.Dynamic.class);

        when(ctx.addServlet(eq("authplane-mcp"), same(transport))).thenReturn(mcpReg);
        when(ctx.addServlet(eq("authplane-prm"), same(setup.prmServlet()))).thenReturn(prmReg);

        setup.registerServlets(ctx, transport);

        verify(mcpReg).addMapping(setup.mcpPath());
        verify(mcpReg).setAsyncSupported(true);
        verify(prmReg).addMapping(setup.prmPath());
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private void stubMetadataAndJwks(String jwksUrl, String introspectionUrl) {
        StringBuilder meta = new StringBuilder();
        meta.append("{\"issuer\":\"")
                .append(baseUrl)
                .append("\",")
                .append("\"jwks_uri\":\"")
                .append(jwksUrl)
                .append("\"");
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
        Map<String, Object> jwkMap = rsaKey.toPublicJWK().toJSONObject();
        return "{\"keys\":[" + jsonObject(jwkMap) + "]}";
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
