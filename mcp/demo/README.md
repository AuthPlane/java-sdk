# Calculator Service — authplane-mcp Demo

A minimal MCP server demonstrating Authplane JWT authentication with per-tool scope enforcement,
built with the **authplane-mcp** adapter and an embedded Jetty server.

The server exposes two tools:

| Tool | Required scope |
|------|----------------|
| `add` | `tools/add` |
| `multiply` | `tools/multiply` |

Tokens must carry the scope for the specific tool being called. A token with only `tools/add`
can call `add` but not `multiply`.

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
cd authplane-mcp
./demo/run.sh
```

`run.sh` installs the SDK and adapter to your local Maven repo, then starts the server on port `8080`. All demo credentials are pre-configured — no additional setup needed.

## How it works

```
MCP Client ──Bearer JWT──► MathServer (port 8080)
                                │
                                ├─ AuthplaneMcpSetup.builder()
                                │    • Discovers JWKS from ISSUER_URL via RFC 8414 metadata
                                │    • Validates JWT signature, aud, exp, typ=at+jwt
                                │    • Introspects token for revocation (RFC 7662)
                                │    • Stores VerifiedClaims in McpTransportContext
                                │
                                └─ claims.requireScope("tools/add")
                                     • Reads VerifiedClaims from transport context
                                     • Throws InsufficientScopeException if scope missing
                                       → MCP returns isError=true to client
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
    "content": [{ "type": "text", "text": "7.0" }],
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

```
HTTP/1.1 401 Unauthorized

Authorization header is required
```

### Insufficient scope (tool-handler error)

A token with `tools/add` but not `tools/multiply` calling `multiply`. Because the scope
check runs *inside* the tool handler, the failure surfaces as a JSON-RPC success envelope
with `"isError": true` (a protocol-tier error), not an HTTP 403:

```bash
curl -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": { "name": "multiply", "arguments": { "a": 3, "b": 4 } }
  }'
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{ "type": "text", "text": "Insufficient scope: required tools/multiply ..." }],
    "isError": true
  }
}
```

## Key patterns shown

**`AuthplaneMcpSetup.builder()`** — single entry point that wires JWT validation, JWKS discovery,
token introspection, and the RFC 9728 PRM endpoint in one call.

**`claims.requireScope(scope)`** — enforces per-tool scope from the verified token claims
stored in `McpTransportContext`. Missing scope raises `InsufficientScopeException`,
which the MCP server returns as `isError: true`.
