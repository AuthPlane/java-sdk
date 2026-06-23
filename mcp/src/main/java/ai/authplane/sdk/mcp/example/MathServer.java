package ai.authplane.sdk.mcp.example;

import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.logging.Logger;

import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.server.Server;

import ai.authplane.sdk.core.VerifiedClaims;
import ai.authplane.sdk.core.dpop.InMemoryDPoPReplayStore;
import ai.authplane.sdk.core.dpop.InboundDPoPOptions;
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

/** Example MathServer that uses AuthplaneMcpAdapter for authentication and authorization. */
public final class MathServer {
    private static final Logger LOG = Logger.getLogger(MathServer.class.getName());

    // JSON Schema 2020-12 document (validated at build time in 2.0.0).
    private static final Map<String, Object> MATH_SCHEMA =
            Map.of(
                    "type",
                    "object",
                    "properties",
                    Map.of(
                            "a", Map.of("type", "number"),
                            "b", Map.of("type", "number")),
                    "required",
                    List.of("a", "b"),
                    "additionalProperties",
                    false);

    private MathServer() {}

    /**
     * Starts the example MCP server on port 8080. Used by the {@code authplane-mcp} demo runner;
     * see {@code mcp/demo/README.md} for prerequisites and how to invoke it.
     *
     * @param args ignored
     * @throws Exception if Jetty fails to start or the Authplane setup cannot complete discovery
     */
    public static void main(String[] args) throws Exception {
        // 1. One builder — issuer, resource, scopes — wires auth + PRM automatically.
        //
        // To enable inbound DPoP (RFC 9449), set AUTHPLANE_INBOUND_DPOP=optional or =required.
        // In "optional" mode the server accepts both bearer-only and DPoP-bound tokens; in
        // "required" mode every access token MUST carry a cnf.jkt thumbprint and a matching
        // proof. The adapter handles the validateHeaders/extract split internally — see
        // AuthplaneMcpAdapter.validateHeaders for the contract.
        AuthplaneMcpSetup.Builder setupBuilder =
                AuthplaneMcpSetup.builder()
                        .issuer("http://localhost:9000")
                        .resource("http://localhost:8080/mcp")
                        .scopes(List.of("tools/add", "tools/multiply"))
                        .devMode(true);

        String dpopMode = System.getenv().getOrDefault("AUTHPLANE_INBOUND_DPOP", "");
        if (!dpopMode.isEmpty()) {
            InboundDPoPOptions dpop = InboundDPoPOptions.defaults(new InMemoryDPoPReplayStore());
            if ("required".equalsIgnoreCase(dpopMode)) {
                dpop = dpop.withRequired(true);
            } else if (!"optional".equalsIgnoreCase(dpopMode)) {
                throw new IllegalArgumentException(
                        "AUTHPLANE_INBOUND_DPOP must be 'optional' or 'required', was: "
                                + dpopMode);
            }
            setupBuilder.inboundDPoP(dpop);
            LOG.info(() -> "Inbound DPoP enabled in '" + dpopMode + "' mode");
        }

        AuthplaneMcpSetup setup = setupBuilder.build().get();

        // 2. Build the MCP transport, wiring in Authplane auth via the adapter
        HttpServletStreamableServerTransportProvider transport =
                HttpServletStreamableServerTransportProvider.builder()
                        .mcpEndpoint(setup.mcpPath())
                        .securityValidator(setup.adapter())
                        .contextExtractor(setup.adapter())
                        .build();

        // 3. Register tools with the MCP server
        McpServer.sync(transport)
                .serverInfo(Implementation.builder("MathServer", "1.0.0").build())
                .tools(createAddTool(), createMultiplyTool())
                .build();

        // 4. Register servlets before starting Jetty (ServletContext.addServlet requires this)
        ServletContextHandler context = new ServletContextHandler();
        context.setContextPath("/");
        setup.registerServlets(context.getServletContext(), transport);

        Server jetty = new Server(8080);
        jetty.setHandler(context);
        jetty.start();

        LOG.info(() -> "MathServer listening on http://localhost:8080" + setup.mcpPath());
        LOG.info(() -> "PRM served at   http://localhost:8080" + setup.prmPath());
        jetty.join();
    }

    private static SyncToolSpecification createAddTool() {
        return createMathTool("add", "Adds two numbers", "tools/add", Double::sum);
    }

    private static SyncToolSpecification createMultiplyTool() {
        return createMathTool(
                "multiply", "Multiplies two numbers", "tools/multiply", (a, b) -> a * b);
    }

    private static SyncToolSpecification createMathTool(
            String name,
            String description,
            String requiredScope,
            BiFunction<Double, Double, Double> operation) {

        return new SyncToolSpecification(
                Tool.builder(name, MATH_SCHEMA).description(description).build(),
                (exchange, request) -> {
                    VerifiedClaims claims =
                            AuthplaneMcpAdapter.getClaims(exchange.transportContext());
                    if (claims == null) {
                        throw new AuthplaneException("Unauthorized: missing claims");
                    }

                    // requireScope throws InsufficientScopeException (403)
                    claims.requireScope(requiredScope);

                    Map<String, Object> argsMap = request.arguments();
                    double a = ((Number) argsMap.get("a")).doubleValue();
                    double b = ((Number) argsMap.get("b")).doubleValue();
                    double result = operation.apply(a, b);

                    return new CallToolResult(
                            List.of(new TextContent(String.valueOf(result))), false, null, null);
                });
    }
}
