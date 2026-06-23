package ai.authplane.sdk.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

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
