package ai.authplane.sdk.core.conformance;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import com.github.tomakehurst.wiremock.WireMockServer;

import ai.authplane.sdk.core.ASCredentials;
import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.ResourceOptions;
import ai.authplane.sdk.core.TestFixtures;
import ai.authplane.sdk.core.fetching.FetchSettings;

final class ConformanceTestSupport {

    private ConformanceTestSupport() {}

    static void stubMetadata(WireMockServer wireMock, Map<String, Object> metadataDocument) {
        wireMock.stubFor(
                get(urlEqualTo("/.well-known/oauth-authorization-server"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(TestFixtures.serializeMap(metadataDocument))));
    }

    static void stubJwks(WireMockServer wireMock, String path, TestFixtures.RSAKeyPair rsaKeys) {
        wireMock.stubFor(
                get(urlEqualTo(path))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                TestFixtures.serializeMap(
                                                        rsaKeys.jwksDocument()))));
    }

    static AuthplaneClient buildClient(String issuer) throws Exception {
        return AuthplaneClient.builder(issuer).devMode(true).build().get();
    }

    static AuthplaneClient buildClient(String issuer, ASCredentials credentials) throws Exception {
        return AuthplaneClient.builder(issuer)
                .devMode(true)
                .authProvider(credentials)
                .build()
                .get();
    }

    /**
     * Builds a client that allows localhost/HTTP for transport but enforces HTTPS for metadata
     * endpoint URLs. Used for conformance tests that verify HTTPS enforcement on endpoint URLs.
     */
    static AuthplaneClient buildClientStrictEndpoints(String issuer) throws Exception {
        return AuthplaneClient.builder(issuer)
                .fetchSettings(new FetchSettings(false, false, true, true, 10))
                .build()
                .get();
    }

    static AuthplaneClient buildClientStrictEndpoints(String issuer, ASCredentials credentials)
            throws Exception {
        return AuthplaneClient.builder(issuer)
                .fetchSettings(new FetchSettings(false, false, true, true, 10))
                .authProvider(credentials)
                .build()
                .get();
    }

    static AuthplaneResource buildVerifier(
            AuthplaneClient client, String resource, List<String> scopes) {
        return client.resource(resource, scopes);
    }

    static AuthplaneResource buildVerifier(
            AuthplaneClient client, String resource, List<String> scopes, ResourceOptions options) {
        return client.resource(resource, scopes, options);
    }

    static String validToken(TestFixtures.RSAKeyPair rsaKeys, String issuer) {
        return TestFixtures.token().rsaKey(rsaKeys).issuer(issuer).build();
    }

    static Throwable unwrapExecutionException(Throwable throwable) {
        Throwable cursor = throwable;
        while (cursor instanceof ExecutionException && cursor.getCause() != null) {
            cursor = cursor.getCause();
        }
        return cursor;
    }

    static void forceMetadataRefresh(AuthplaneClient client) throws Exception {
        Method method = AuthplaneClient.class.getDeclaredMethod("forceMetadataRefreshForTest");
        method.setAccessible(true);
        method.invoke(client);
    }
}
