package ai.authplane.sdk.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import ai.authplane.sdk.core.prm.ProtectedResourceMetadata;

@ExtendWith(MockitoExtension.class)
class PrmServletTest {

    @Mock HttpServletRequest request;

    @Mock HttpServletResponse response;

    @Test
    void doGet_returnsJsonWithCorrectContentType() throws Exception {
        ProtectedResourceMetadata prm =
                ProtectedResourceMetadata.builder()
                        .resource("https://mcp.example.com/mcp")
                        .authorizationServer("https://auth.example.com")
                        .scopes(List.of("tools/read", "tools/write"))
                        .build();

        PrmServlet servlet = new PrmServlet(prm);

        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        servlet.doGet(request, response);

        verify(response).setContentType("application/json");
        verify(response).setCharacterEncoding("UTF-8");

        String json = writer.toString();
        assertThat(json).contains("\"resource\":\"https://mcp.example.com/mcp\"");
        assertThat(json).contains("\"authorization_servers\":");
        assertThat(json).contains("\"scopes_supported\":");
    }

    @Test
    void doGet_serializesMapBody_includingDpopFields() throws Exception {
        Map<String, Object> prm = new LinkedHashMap<>();
        prm.put("resource", "https://mcp.example.com/mcp");
        prm.put("authorization_servers", List.of("https://auth.example.com"));
        prm.put("dpop_bound_access_tokens_required", true);

        PrmServlet servlet = new PrmServlet(prm);

        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        servlet.doGet(request, response);

        String json = writer.toString();
        assertThat(json).contains("\"resource\":\"https://mcp.example.com/mcp\"");
        assertThat(json).contains("\"dpop_bound_access_tokens_required\":true");
    }

    @Test
    void queryBearingRequest_reachesThePathRegisteredServlet() throws Exception {
        // The advertised PRM URL may carry the resource identifier's query component, while the
        // servlet is registered path-keyed (wellKnownPath ignores the query). This pins the claim
        // that makes that split safe: a query-bearing GET at the advertised path still reaches the
        // servlet mapping and is served the document. Registration mirrors the class javadoc
        // (ServletHolder at wellKnownPath) against a real container, not a mocked dispatch.
        ProtectedResourceMetadata prm =
                ProtectedResourceMetadata.builder()
                        .resource("https://mcp.example.com/mcp?tenant=a")
                        .authorizationServer("https://auth.example.com")
                        .scopes(List.of("tools/read"))
                        .build();
        String path = ProtectedResourceMetadata.wellKnownPath(URI.create(prm.getResource()));

        Server server = new Server(0);
        ServletContextHandler context = new ServletContextHandler();
        context.addServlet(new ServletHolder(new PrmServlet(prm)), path);
        server.setHandler(context);
        server.start();
        try {
            int port = ((ServerConnector) server.getConnectors()[0]).getLocalPort();
            HttpResponse<String> res =
                    HttpClient.newHttpClient()
                            .send(
                                    HttpRequest.newBuilder(
                                                    URI.create(
                                                            "http://localhost:"
                                                                    + port
                                                                    + path
                                                                    + "?tenant=a"))
                                            .GET()
                                            .build(),
                                    HttpResponse.BodyHandlers.ofString());

            assertThat(res.statusCode()).isEqualTo(200);
            assertThat(res.headers().firstValue("Content-Type").orElse(""))
                    .startsWith("application/json");
            assertThat(res.body())
                    .contains("\"resource\":\"https://mcp.example.com/mcp?tenant=a\"");
        } finally {
            server.stop();
        }
    }

    @Test
    void constructor_rejectsNullPrm() {
        assertThatNullPointerException()
                .isThrownBy(() -> new PrmServlet((ProtectedResourceMetadata) null))
                .withMessage("prm must not be null");
    }

    @Test
    void constructor_rejectsNullMapBody() {
        assertThatNullPointerException()
                .isThrownBy(() -> new PrmServlet((Map<String, Object>) null))
                .withMessage("prmDocument must not be null");
    }
}
