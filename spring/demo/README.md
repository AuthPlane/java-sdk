# Calculator Service — authplane-spring Demo

A Math MCP server built with **Spring Boot 4** + **Spring AI 2** that exposes two tools
(`add`, `multiply`) protected by OAuth 2.1 JWT validation. Two independent runnable
applications demonstrate both integration paths provided by `authplane-spring`.

| Tool | Required scope |
|------|----------------|
| `add` | `tools/add` |
| `multiply` | `tools/multiply` |

## Two approaches, one codebase

| Profile | Main class | Auth mechanism | Claims access |
|---------|------------|----------------|---------------|
| `-Psecurity` | `MathMcpServerApplication` | Spring Security `SecurityFilterChain` | `AuthplaneAuthentication.current()` |
| `-Ptransport` | `MathMcpTransportApplication` | MCP transport hooks (`securityValidator` / `contextExtractor`) | `AuthplaneMcpServerAdapter.getClaims(exchange.transportContext())` |

Both read the same `application.properties` and listen on the same port.

## Prerequisites

- Java 21+
- Maven 3.9+
- The **Authplane authserver** running locally — from a checkout of the `authserver` repo, run:

  ```bash
  bash demo/mcp-demo-server-start.sh
  ```

  This starts the auth server on `http://localhost:9000`, registers the calculator client and scopes, and creates a demo user.

## Run

```bash
cd authplane-spring

# MCP transport-level auth (default, no Spring Security)
./demo/run.sh

# Spring Security filter-chain auth
./demo/run.sh security
```

`run.sh` installs the SDK and adapter to your local Maven repo, then starts the server on port `8080`. All demo credentials are pre-configured — no additional setup needed.

## Project structure

```
demo/
├── pom.xml                          # Two Maven profiles: security, transport
├── run.sh                           # Build and run script
└── src/main/
    ├── java/ai/authplane/sdk/spring/
    │   ├── security/demo/
    │   │   ├── MathMcpServerApplication.java     # -Psecurity entry point
    │   │   └── MathTools.java                    # @Tool methods using AuthplaneAuthentication
    │   └── mcp/demo/
    │       ├── MathMcpTransportApplication.java  # -Ptransport entry point
    │       └── MathTransportTools.java           # @Tool methods using AuthplaneMcpServerAdapter
    └── resources/
        └── application.properties               # Shared by both profiles
```

## Security flows

### `-Ptransport` — MCP transport hooks

```
POST /mcp  Authorization: Bearer <token>
  │
  ▼
WebMvcStreamableServerTransportProvider
  │  securityValidator.validateHeaders(headers)
  │  → AuthplaneResource.verify(token) — rejects 401/403 before MCP protocol runs
  │
  │  contextExtractor.extract(serverRequest)
  │  → AuthplaneResource.verify(token) — stores VerifiedClaims in McpTransportContext
  ▼
MathTransportTools.add(int a, int b, ToolContext toolContext)
  │  McpSyncServerExchange exchange = McpToolUtils.getMcpExchange(toolContext).orElseThrow()
  │  AuthplaneMcpServerAdapter.getClaims(exchange.transportContext()).requireScope("tools/add")
  │  throws InsufficientScopeException → MCP protocol error if scope missing
  ▼
result
```

No Spring Security filter chain is active. Spring Security auto-configuration is
excluded from `MathMcpTransportApplication`.

### `-Psecurity` — Spring Security filter chain

```
POST /mcp  Authorization: Bearer <token>
  │
  ▼
AuthplaneAuthenticationConfigurer's BearerTokenAuthenticationFilter (Bearer + DPoP)
  │  extracts the token → BearerTokenAuthenticationToken
  ▼
AuthplaneAuthenticationProvider          (from authplane-spring)
  │  AuthplaneResource.verify(token)
  │  verifies: signature, iss, aud, exp, typ=at+jwt
  │  stores AuthplaneAuthentication in SecurityContextHolder
  ▼
MathTools.add()
  │  AuthplaneAuthentication.current().requireScope("tools/add")
  │  throws AccessDeniedException → HTTP 403 if scope missing
  ▼
result
```

## Endpoints

| Path | Description |
|------|-------------|
| `POST /mcp` | MCP streamable-HTTP endpoint (requires Bearer token) |
| `GET /.well-known/oauth-protected-resource/mcp` | RFC 9728 PRM document (public) |

## Testing with curl

### PRM document (no auth required)

```bash
curl http://localhost:8080/.well-known/oauth-protected-resource/mcp
```

```json
{
  "resource": "http://localhost:8080/mcp",
  "authorization_servers": ["http://localhost:9000"],
  "scopes_supported": ["tools/add", "tools/multiply"],
  "bearer_methods_supported": ["header"]
}
```

### Call a tool (valid Bearer token)

```bash
TOKEN=<your-access-token>

curl -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": { "name": "add", "arguments": { "a": 3, "b": 4 } }
  }'
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{ "type": "text", "text": "7" }],
    "isError": false
  }
}
```

### Missing token (401)

```bash
curl -i -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

**`-Ptransport`** response:
```
HTTP/1.1 401 Unauthorized

Authorization header is required
```

**`-Psecurity`** response:
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource/mcp"
Content-Type: application/json

{"error":"invalid_token","error_description":"Bearer token is missing or invalid"}
```

### Insufficient scope (403)

A token without `tools/multiply` calling `multiply`:

- **`-Ptransport`**: MCP protocol error (HTTP 200, JSON-RPC error body) from `InsufficientScopeException`
- **`-Psecurity`**: HTTP 403 from Spring Security's `AccessDeniedException`
