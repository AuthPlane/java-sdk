package ai.authplane.sdk.mcp;

import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.Objects;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.nimbusds.jose.util.JSONObjectUtils;

import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.prm.ProtectedResourceMetadata;

/**
 * Servlet that serves an RFC 9728 Protected Resource Metadata document as JSON.
 *
 * <p>Register it at the path returned by {@link ProtectedResourceMetadata#wellKnownPath(URI)}.
 *
 * <p>Example:
 *
 * <pre>{@code
 * ProtectedResourceMetadata prm = ProtectedResourceMetadata.builder()
 *     .resource("https://mcp.example.com/mcp")
 *     .authorizationServer("https://auth.example.com")
 *     .scopes(List.of("tools/read"))
 *     .build();
 *
 * String path = ProtectedResourceMetadata.wellKnownPath(URI.create(prm.getResource()));
 * context.addServlet(new ServletHolder(new PrmServlet(prm)), path);
 * }</pre>
 */
public class PrmServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private final String json;

    public PrmServlet(ProtectedResourceMetadata prm) {
        Objects.requireNonNull(prm, "prm must not be null");
        this.json = prm.toJson();
    }

    /**
     * Serves a pre-built PRM document, typically obtained from {@link
     * AuthplaneResource#prmResponse()} so that all fields (including DPoP advertisement) come from
     * the single authoritative source.
     *
     * @param prmDocument the PRM document as an ordered map of JSON members
     */
    public PrmServlet(Map<String, Object> prmDocument) {
        Objects.requireNonNull(prmDocument, "prmDocument must not be null");
        this.json = JSONObjectUtils.toJSONString(prmDocument);
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
        res.setContentType("application/json");
        res.setCharacterEncoding("UTF-8");
        res.getWriter().write(json);
    }
}
