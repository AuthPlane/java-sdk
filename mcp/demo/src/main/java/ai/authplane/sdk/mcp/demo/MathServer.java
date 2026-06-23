package ai.authplane.sdk.mcp.demo;

import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.logging.Logger;

import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.server.Server;

import ai.authplane.sdk.core.ASCredentials;
import ai.authplane.sdk.core.VerifiedClaims;
import ai.authplane.sdk.core.errors.AuthplaneException;
import ai.authplane.sdk.mcp.AuthplaneMcpAdapter;
import ai.authplane.sdk.mcp.AuthplaneMcpSetup;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Implementation;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;

/**
 * Calculator MCP server demo for the authplane-mcp adapter.
 *
 * <p>Reads configuration from environment variables (populated by run.sh; see demo/README.md):
 *
 * <ul>
 *   <li>{@code ISSUER_URL} — Authorization Server issuer (default: http://localhost:9000)
 *   <li>{@code RESOURCE_URL} — This server's resource URI (default: http://localhost:8080/mcp)
 *   <li>{@code CLIENT_ID} — OAuth client ID (defaults to RESOURCE_URL)
 *   <li>{@code CLIENT_SECRET} — Client secret for token introspection (required)
 * </ul>
 */
public class MathServer {

    private static final Logger LOG = Logger.getLogger(MathServer.class.getName());

    // JSON Schema 2020-12 document (validated at build time in 2.0.0).
    private static final Map<String, Object> MATH_SCHEMA = Map.of(
            "type", "object",
            "properties", Map.of(
                    "a", Map.of("type", "number"),
                    "b", Map.of("type", "number")),
            "required", List.of("a", "b"),
            "additionalProperties", false);

    public static void main(String[] args) throws Exception {
        String issuer = env("ISSUER_URL", "http://localhost:9000");
        String resource = env("RESOURCE_URL", "http://localhost:8080/mcp");
        String clientId = env("CLIENT_ID", resource);
        String secret = env("CLIENT_SECRET", null);

        if (secret == null || secret.isBlank()) {
            System.err.println("ERROR: CLIENT_SECRET environment variable is required.");
            System.err.println(
                    "Set CLIENT_SECRET, or run ./demo/run.sh after starting the authserver"
                            + " demo (see demo/README.md).");
            System.exit(1);
        }

        AuthplaneMcpSetup setup =
                AuthplaneMcpSetup.builder()
                        .issuer(issuer)
                        .resource(resource)
                        .scopes(List.of("tools/add", "tools/multiply"))
                        .devMode(true)
                        .authProvider(new ASCredentials(clientId, secret))
                        .useBuiltinRevocationChecker()
                        .build()
                        .get();

        HttpServletStreamableServerTransportProvider transport =
                HttpServletStreamableServerTransportProvider.builder()
                        .mcpEndpoint(setup.mcpPath())
                        .securityValidator(setup.adapter())
                        .contextExtractor(setup.adapter())
                        .build();

        McpServer.sync(transport)
                .serverInfo(Implementation.builder("MathServer", "1.0.0").build())
                .tools(
                        makeTool("add", "Adds two numbers", "tools/add", Double::sum),
                        makeTool(
                                "multiply",
                                "Multiplies two numbers",
                                "tools/multiply",
                                (a, b) -> a * b))
                .build();

        ServletContextHandler context = new ServletContextHandler();
        context.setContextPath("/");
        setup.registerServlets(context.getServletContext(), transport);

        Server jetty = new Server(8080);
        jetty.setHandler(context);
        jetty.start();

        LOG.info("MathServer listening on http://localhost:8080" + setup.mcpPath());
        LOG.info("PRM served at   http://localhost:8080" + setup.prmPath());
        jetty.join();
    }

    private static SyncToolSpecification makeTool(
            String name, String description, String scope, BiFunction<Double, Double, Double> op) {
        return new SyncToolSpecification(
                Tool.builder(name, MATH_SCHEMA).description(description).build(),
                (exchange, request) -> {
                    VerifiedClaims claims =
                            AuthplaneMcpAdapter.getClaims(exchange.transportContext());
                    if (claims == null) {
                        throw new AuthplaneException("Unauthorized: missing claims");
                    }
                    claims.requireScope(scope);

                    Map<String, Object> args = request.arguments();
                    double a = ((Number) args.get("a")).doubleValue();
                    double b = ((Number) args.get("b")).doubleValue();
                    return new CallToolResult(
                            List.of(new TextContent(String.valueOf(op.apply(a, b)))),
                            false,
                            null,
                            null);
                });
    }

    private static String env(String name, String defaultValue) {
        String v = System.getenv(name);
        return (v != null && !v.isBlank()) ? v : defaultValue;
    }
}
