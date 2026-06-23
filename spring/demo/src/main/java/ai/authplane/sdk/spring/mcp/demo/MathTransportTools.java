package ai.authplane.sdk.spring.mcp.demo;

import org.springframework.ai.chat.model.ToolContext;
import org.springframework.ai.mcp.McpToolUtils;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Component;

import ai.authplane.sdk.spring.mcp.AuthplaneMcpServerAdapter;

import io.modelcontextprotocol.server.McpSyncServerExchange;

@Component
public class MathTransportTools {

  @Tool(description = "Adds two integers and returns the result")
  public int add(int a, int b, ToolContext toolContext) {
    McpSyncServerExchange exchange = McpToolUtils.getMcpExchange(toolContext).orElseThrow();
    AuthplaneMcpServerAdapter.getClaims(exchange.transportContext()).requireScope("tools/add");
    return a + b;
  }

  @Tool(description = "Multiplies two integers and returns the result")
  public int multiply(int a, int b, ToolContext toolContext) {
    McpSyncServerExchange exchange = McpToolUtils.getMcpExchange(toolContext).orElseThrow();
    AuthplaneMcpServerAdapter.getClaims(exchange.transportContext()).requireScope("tools/multiply");
    return a * b;
  }
}
