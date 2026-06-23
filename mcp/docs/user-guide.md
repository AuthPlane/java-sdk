# authplane-mcp User Guide

OAuth 2.1 JWT authentication for servers built on the [MCP Java SDK](https://github.com/modelcontextprotocol/java-sdk), powered by the [Authplane Java SDK](../../core/README.md).

## 1. Install

```xml
<dependency>
  <groupId>ai.authplane.sdk</groupId>
  <artifactId>authplane-mcp</artifactId>
  <version>1.0.0-SNAPSHOT</version>
</dependency>
```

The MCP Java SDK and `jakarta.servlet-api` are declared `provided` — your application pulls them in directly. Requires Java 21+.

## 2. Quickstart

```java
import ai.authplane.sdk.mcp.AuthplaneMcpSetup;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema.Implementation;

import java.util.List;

AuthplaneMcpSetup setup = AuthplaneMcpSetup.builder()
        .issuer("https://auth.company.com")
        .resource("https://mcp.company.com/mcp")
        .scopes(List.of("tools/query", "tools/write"))
        .build()
        .get();

// The host owns the transport provider; wire in Authplane auth via the adapter.
HttpServletStreamableServerTransportProvider transport =
        HttpServletStreamableServerTransportProvider.builder()
                .mcpEndpoint(setup.mcpPath())
                .securityValidator(setup.adapter())
                .contextExtractor(setup.adapter())
                .build();

McpServer.sync(transport)
        .serverInfo(Implementation.builder("My Server", "1.0.0").build())
        .tools(/* your tool specifications */)
        .build();

setup.registerServlets(servletContext, transport);  // any Jakarta Servlet container
```

`AuthplaneMcpSetup.builder().build()` performs RFC 8414 metadata discovery, fetches the JWKS, and produces a pre-wired security adapter and PRM servlet. The host builds the MCP transport provider (wiring `setup.adapter()` as both security validator and context extractor) and hands it to `registerServlets(...)`. The returned `CompletableFuture<AuthplaneMcpSetup>` completes once the adapter is ready to verify tokens.

## 3. Core concepts

### Components wired by `AuthplaneMcpSetup`

| Accessor | Returns | Role |
|---|---|---|
| `client()` | `AuthplaneClient` | Owns AS metadata, JWKS, transport, token cache, circuit breaker |
| `resource()` | `AuthplaneResource` | Scoped JWT verifier |
| `adapter()` | `AuthplaneMcpAdapter` | MCP security validator + context extractor |
| `prmServlet()` | `PrmServlet` | Serves the RFC 9728 document (created on demand) |
| `mcpPath()` | `String` | MCP endpoint path (derived from the resource URI) |
| `prmPath()` | `String` | PRM endpoint path |
| `registerServlets(ServletContext, HttpServletStreamableServerTransportProvider)` | `void` | Registers the host-owned transport at `mcpPath()` and the PRM servlet at `prmPath()` |

### Two transport-layer hooks

`AuthplaneMcpAdapter` implements `ServerTransportSecurityValidator` (called with headers only) and `McpTransportContextExtractor<HttpServletRequest>` (called with the full servlet request). The two hooks run independent verifications with no shared state — each call verifies the Bearer token from scratch. This keeps the adapter free of threading assumptions about the MCP transport.

Claims are stored in the `McpTransportContext` at key `AuthplaneMcpAdapter.CLAIMS_KEY` (`"authplane.claims"`). Retrieve them in a tool handler with `AuthplaneMcpAdapter.getClaims(exchange.transportContext())`.

## 4. Configuration reference

Every builder method on `AuthplaneMcpSetup.Builder`:

| Method | Default | Purpose |
|---|---|---|
| `issuer(String)` | *required* | Authorization server URL |
| `resource(String)` | *required* | URL of this MCP server — also the JWT `aud` claim |
| `scopes(List<String>)` | *required* | Scopes this server supports |
| `allowedAlgorithms(List<String>)` | `["RS256", "ES256"]` | Allowed JWT signature algorithms (asymmetric only) |
| `jwksRefreshSeconds(int)` | `300` | JWKS cache refresh interval |
| `metadataRefreshSeconds(int)` | `3600` | AS metadata refresh interval |
| `clockSkewSeconds(int)` | `30` | Leeway for `exp`/`nbf`/`iat` |
| `devMode(boolean)` | `false` | Relaxes SSRF for local development |
| `fetchSettings(FetchSettings)` | — | Full control over SSRF / fetch behaviour; overrides `devMode` |
| `authProvider(AuthProvider)` | `null` | AS authentication for introspection and token exchange. Pass `new ASCredentials(clientId, clientSecret)` for static HTTP Basic, or a custom provider |
| `useBuiltinRevocationChecker()` | disabled | Enables RFC 7662 introspection-based revocation |
| `revocationChecker(RevocationChecker)` | `null` | Custom revocation strategy |
| `executor(Executor)` | `ForkJoinPool.commonPool()` | Executor for all async operations |
| `circuitBreakerThreshold(int)` | `5` | Failures before the breaker opens |
| `circuitBreakerCooldownSeconds(int)` | `30` | Cooldown before half-open |
| `tokenCacheConfig(TokenCacheConfig)` | `TokenCacheConfig.defaults()` | Token cache tuning: TTL buffer (default `30`s), fallback TTL (default `3600`s), max entries (default `10000`, LRU) |
| `outboundDPoP(OutboundDPoPOptions)` | `null` | Enables outbound DPoP proofs on AS calls |
| `inboundDPoP(InboundDPoPOptions)` | `null` | Enables inbound DPoP proof validation |

## 5. Scope enforcement

Enforce per-tool scope requirements inside tool handlers:

```java
import ai.authplane.sdk.core.VerifiedClaims;
import ai.authplane.sdk.mcp.AuthplaneMcpAdapter;

new SyncToolSpecification(
    Tool.builder("query", schema).description("Execute a query").build(),
    (exchange, request) -> {
        VerifiedClaims claims = AuthplaneMcpAdapter.getClaims(exchange.transportContext());
        claims.requireScope("tools/query");

        return new CallToolResult(List.of(new TextContent("result")), false, null, null);
    }
);
```

`requireScope(...)` throws `InsufficientScopeException`. At the tool-handler layer the MCP server catches this and returns a JSON-RPC error — see [Error handling](#10-error-handling).

### Multiple scopes

```java
claims.requireScope("tools/admin");
claims.requireScope("tools/delete");    // AND logic

if (claims.hasScope("tools/admin")) {
    // branch without throwing
}
```

## 6. Accessing token claims

```java
VerifiedClaims claims = AuthplaneMcpAdapter.getClaims(exchange.transportContext());

String sub      = claims.sub();           // user / service subject
String clientId = claims.clientId();      // OAuth client ID
String iss      = claims.issuer();        // issuer
List<String> aud = claims.audience();     // audience list (always contains the resource URI)
String jti      = claims.jti();

Object tenant   = claims.raw().get("tenant_id");   // custom claim
Map<String, Object> all = claims.raw();
```

`raw()` returns an unmodifiable snapshot of the full JWT payload.

## 7. Protected Resource Metadata

`AuthplaneMcpSetup` registers a `PrmServlet` that serves the RFC 9728 document automatically. The path is derived from the resource URI:

| Resource URL | PRM endpoint |
|---|---|
| `https://mcp.company.com/mcp` | `GET /.well-known/oauth-protected-resource/mcp` |
| `https://mcp.company.com/api/v1` | `GET /.well-known/oauth-protected-resource/api/v1` |

```java
setup.mcpPath();    // e.g. "/mcp"
setup.prmPath();    // e.g. "/.well-known/oauth-protected-resource/mcp"
```

The response includes the authorization server issuer, supported scopes, supported bearer methods (`header`), and the resource identifier.

## 8. Token revocation checking

By default, tokens are validated offline (signature + claims only). Two opt-in modes are available:

### RFC 7662 introspection

```java
AuthplaneMcpSetup setup = AuthplaneMcpSetup.builder()
        .issuer("https://auth.company.com")
        .resource("https://mcp.company.com/mcp")
        .scopes(List.of("tools/query"))
        .authProvider(new ASCredentials("my_resource_server", "secret"))
        .useBuiltinRevocationChecker()
        .build()
        .get();
```

The introspection endpoint is discovered from AS metadata. If the endpoint returns `active=false`, the token is rejected. **Fails open** on transport errors.

### Custom checker

```java
RevocationChecker blocklist = (rawToken, jti) ->
        redisClient.sismember("revoked_tokens", jti);

AuthplaneMcpSetup.builder()
        .issuer("https://auth.company.com")
        .resource("https://mcp.company.com/mcp")
        .scopes(List.of("tools/query"))
        .revocationChecker(blocklist)
        .build()
        .get();
```

Mutually exclusive with `useBuiltinRevocationChecker()`. See the core SDK user guide for fail-closed semantics.

## 9. Token exchange and URL elicitation

`authplane-mcp` ships a helper pair that turns OAuth `consent_required` / `interaction_required` errors from token exchange into MCP URL elicitation responses that clients can act on.

### `UrlElicitationSupport.wrapToolWithUrlElicitation`

Wrap a tool handler that calls token exchange. When the exchange fails with `consent_required` or `interaction_required` and the AS response includes `consent_url`, the wrapper raises MCP JSON-RPC error code `-32042` carrying a URL elicitation payload:

```java
import ai.authplane.sdk.core.TokenExchangeOptions;
import ai.authplane.sdk.mcp.UrlElicitationSupport;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

new SyncToolSpecification(
    Tool.builder("query_downstream", schema).description("Query on behalf of the user").build(),
    UrlElicitationSupport.wrapToolWithUrlElicitation((exchange, request) -> {
        VerifiedClaims claims = AuthplaneMcpAdapter.getClaims(exchange.transportContext());
        claims.requireScope("tools/query");

        String rawToken = /* lifted from the Authorization header */;
        TokenResponse downstream = setup.client()
                .exchange(TokenExchangeOptions.builder(rawToken)
                        .scope(List.of("tools/query"))
                        .resource("https://downstream.company.com/api")
                        .build())
                .get();

        return new CallToolResult(
                List.of(new TextContent(callDownstream(downstream.accessToken()))),
                false, null, null);
    })
);
```

### Why this pairing matters

Feature A (token exchange, in the core SDK) surfaces consent as a typed `ConsentRequiredException` (a subclass of `TokenExchangeException`) carrying `consentUrl`, `serviceId`, and `causeDetail`. Feature B (URL elicitation, in the MCP adapter) translates that exception into the MCP-specific `-32042` response with the consent URL, an elicitation ID, and a human-readable message.

Always wrap any tool handler that triggers token exchange — otherwise the `ConsentRequiredException` bubbles as a generic error and the client never learns about the consent URL.

### Using the helper directly

If you already have a `Throwable` in hand and want to convert it manually:

```java
import io.modelcontextprotocol.spec.McpError;

McpError error = UrlElicitationSupport.toUrlElicitationRequiredError(throwable);
// Returns an McpError when the cause is a ConsentRequiredException carrying a
// non-blank consentUrl. Returns null otherwise (it does NOT rethrow).
if (error != null) {
    throw error;
}
// else: not a consent-with-URL failure — handle the original throwable yourself.
```

`wrapToolWithUrlElicitation` builds on this: it maps the error and throws the resulting `McpError` when non-null, otherwise rethrows the original throwable. The JSON-RPC error code itself is the SDK-native `McpSchema.ErrorCodes.URL_ELICITATION_REQUIRED` (`-32042`).

## 10. Error handling

Two tiers of error handling with different response shapes:

### Transport tier (`validateHeaders`)

Runs before the MCP protocol layer. Failures produce plain HTTP responses via `ServerTransportSecurityException`.

| Condition | HTTP status |
|---|---|
| Missing `Authorization` header | 401 |
| Non-`Bearer` scheme | 401 |
| Invalid / expired / malformed token | 401 |
| Token missing a transport-level scope | 403 |

### Protocol tier (tool handlers)

Exceptions thrown from a tool handler are caught by the MCP SDK and returned as JSON-RPC error responses (HTTP 200 with an error body). Scope failures from `claims.requireScope(...)` appear here as MCP error `-32603` with a descriptive message:

```
Insufficient scope: required 'tools/add', token has [tools/multiply]
```

This is the correct behaviour — by the time a tool handler runs, the token has already been accepted as valid. Scope enforcement at the tool level is an application-layer decision, and MCP represents it as a protocol error.

URL elicitation errors (`UrlElicitationSupport`) use code `-32042`.

### Catching specific exceptions

```java
import ai.authplane.sdk.core.errors.AuthplaneException;
import ai.authplane.sdk.core.errors.InsufficientScopeException;

try {
    VerifiedClaims claims = verifier.verify(token).get().claims();
} catch (InsufficientScopeException e) {
    // 403
} catch (AuthplaneException e) {
    // 401 / 503 — see HttpStatus.of(e)
}
```

See the [core SDK user guide §9](../../core/docs/user-guide.md#9-error-handling) for the full exception hierarchy and the `HttpStatus` / `WwwAuthenticate` helpers.

## 11. Development mode

```java
AuthplaneMcpSetup.builder()
        .issuer("http://localhost:9000")
        .resource("http://localhost:8080/mcp")
        .scopes(List.of("tools/query"))
        .devMode(true)
        .build()
        .get();
```

Allows HTTP, `127.0.0.0/8`, and RFC 1918 ranges. Cloud metadata (`169.254.0.0/16`) and IPv6 link-local (`fe80::/10`) are always blocked.

For fine-grained control, supply a `FetchSettings` — see the [core user guide §6](../../core/docs/user-guide.md#6-configuration-options).

## 12. Advanced: manual setup

When you need more control than the builder provides, wire components individually:

```java
import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.ResourceOptions;
import ai.authplane.sdk.core.prm.ProtectedResourceMetadata;
import ai.authplane.sdk.mcp.AuthplaneMcpAdapter;
import ai.authplane.sdk.mcp.PrmServlet;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;

import java.net.URI;
import java.util.List;

AuthplaneClient client = AuthplaneClient.builder("https://auth.company.com")
        .jwksRefreshSeconds(600)
        .build()
        .get();

ResourceOptions options = ResourceOptions.builder()
        .clockSkewSeconds(60)
        .build();

AuthplaneResource verifier = client.resource(
        "https://mcp.company.com/mcp",
        List.of("tools/query", "tools/write"),
        options);

AuthplaneMcpAdapter adapter = new AuthplaneMcpAdapter(client, verifier);

HttpServletStreamableServerTransportProvider transport =
        HttpServletStreamableServerTransportProvider.builder()
                .mcpEndpoint("/mcp")
                .securityValidator(adapter)
                .contextExtractor(adapter)
                .build();

McpServer.sync(transport)
        .serverInfo(Implementation.builder("My Server", "1.0.0").build())
        .tools(/* ... */)
        .build();

ProtectedResourceMetadata prm = ProtectedResourceMetadata.builder()
        .resource("https://mcp.company.com/mcp")
        .authorizationServer("https://auth.company.com")
        .scopes(List.of("tools/query", "tools/write"))
        .build();

PrmServlet prmServlet = new PrmServlet(prm);
String prmPath = ProtectedResourceMetadata.wellKnownPath(
        URI.create("https://mcp.company.com/mcp"));

servletContext.addServlet("mcp", transport).addMapping("/mcp");
servletContext.addServlet("prm", prmServlet).addMapping(prmPath);
```

## 13. DPoP compatibility and known limitations

> ⚠️ **Warning — DPoP behavior on the SSE GET notification stream:** When a DPoP-bound token (`cnf.jkt` present) is presented on the SSE GET notification-listener path, the DPoP proof binding is **not** validated and the token's revocation state is **not** checked. Only the JWT signature, `exp`, `iss`, and `aud` are verified. The MCP Java SDK invokes only `validateHeaders` on SSE GET (never `extract`), and the deferral mechanism that handles DPoP-bound tokens on POST cannot reach the proof or revocation checks on this path. POST/PUT/DELETE traffic still receives full DPoP and revocation validation via `extract`. Operators needing sender-binding or revocation enforcement on the notification stream must pre-validate at a reverse proxy or front the resource with the Spring Security `AuthplaneAuthenticationProvider` filter (not the Spring MCP transport adapter — same two-hook contract). See "SSE GET caveat" below for the mechanism.

The MCP Java SDK splits transport-level auth into two hooks with different capabilities:

1. **`validateHeaders(Map<String, List<String>>)`** — receives only headers. Can return proper HTTP status codes via `ServerTransportSecurityException` (401/403). **No access to method or URL**, so it cannot construct a `VerificationRequestContext`.
2. **`extract(HttpServletRequest)`** — receives the full request. Has method + URL + DPoP header → can construct `VerificationRequestContext` and run the full DPoP-bound verify. Exceptions bubble as unhandled 500s; there is no mechanism to return a structured HTTP error.

### DPoP-bound tokens (`cnf.jkt` present)

`AuthplaneMcpAdapter` handles this asymmetry internally so DPoP-bound tokens work end-to-end (the TypeScript SDK's FastMCP integration has the same `authenticate`-called-twice hook split and applies the equivalent workaround):

- **`validateHeaders`** runs `resource.verify(token)` in bearer-only mode. For a DPoP-bound token this throws `DPoPProofMissingException` by design — the adapter **swallows that specific exception** and lets the request flow through. All other failures (expired, bad signature, revoked, DPoP unsupported, scope insufficient) still surface as 401/403.
- **`extract`** runs `resource.verify(token, context)` with the full request context. This is the authoritative DPoP validation: proof signature, `htm`/`htu`/`ath` claims, replay store check, binding to `cnf.jkt`. Failures here bubble as the typed `AuthplaneException` (visible as 500 with diagnostic body — see "DPoP failure surface" below).

| Token type | Method | `validateHeaders` | `extract` | Outcome |
|---|---|---|---|---|
| Bearer-only | POST/PUT/DELETE | full verify (401 on failure) | full verify (500 on failure) | DPoP proof not required; token validated twice (see "Duplicate verification") |
| DPoP-bound | POST/PUT/DELETE | swallows `DPoPProofMissingException`, returns | full verify with proof binding | proof validated exactly once, in `extract` |
| Bearer-only | SSE GET (notifications listener) | full verify (401 on failure) | not invoked | token validated once, revocation checked |
| DPoP-bound | SSE GET (notifications listener) | swallows `DPoPProofMissingException`, returns | not invoked | **JWT signature, `exp`, `iss`, `aud` verified; revocation and DPoP proof binding NOT checked** — see "SSE GET caveat" |

### SSE GET caveat

For the SSE GET path the MCP Java SDK calls only `validateHeaders`, never `extract`. A DPoP-bound token presented on a GET request to open the notification stream has its JWT signature, `exp`, `iss`, and `aud` verified (`validator.verify(token)` runs first inside `AuthplaneResource.verify`). It does **not** have the DPoP proof binding checked (no request object → no `VerificationRequestContext`), and it also does **not** have its revocation state checked: in `AuthplaneResource.verify` the order is `validator.verify(token)` → `validateDpop(...)` → `checkRevocation(...)`, and `validateDpop` throws `DPoPProofMissingException` for the no-context case before `checkRevocation` can run; the adapter swallows that exception to defer to `extract`, but on SSE GET `extract` is never invoked. Acceptable for a read-only notification listener (actionable JSON-RPC commands flow through POST and receive full validation via `extract`), but operators that need sender-binding *or* revocation enforcement on the listener too should run the resource behind a reverse proxy that validates the DPoP proof and the token introspection before the request reaches the servlet, or use the `authplane-spring` `AuthplaneAuthenticationProvider` Spring Security filter (not the Spring MCP transport adapter, which has the same split-hook limitation), where verification runs once with full request context.

### Duplicate verification / double introspection

`validateHeaders` and `extract` each call `resource.verify(...)` for bearer-only tokens, so the verifier runs twice per request. When RFC 7662 introspection-based revocation checking is enabled, this triggers **two introspection calls per request** to the authorization server. DPoP-bound tokens incur only one full verify (the validateHeaders pass throws `DPoPProofMissingException` before reaching introspection).

A per-request memo (analogous to the TypeScript SDK's `AsyncLocalStorage`-keyed cache used in its FastMCP integration) would collapse the bearer-only path back to one introspection per request without changing the public contract. It would need either an upstream MCP SDK change to give `validateHeaders` access to the request, or a separately registered servlet `Filter` that sets a request attribute the adapter can read. Tracked as a noted follow-up; not in this version.

### DPoP failure surface

Failures raised by `extract` (invalid proof, method mismatch, URL mismatch, replay detected) become unhandled 500s, not RFC-compliant 401 responses with `WWW-Authenticate`. Tracked upstream: [modelcontextprotocol/java-sdk#887](https://github.com/modelcontextprotocol/java-sdk/issues/887). The Spring Security path in `authplane-spring` does not have this limitation — verification runs once in the filter chain with full request context, so DPoP failures surface as proper 401 + `WWW-Authenticate: DPoP error="invalid_dpop_proof"`.

### Enabling inbound DPoP

```java
AuthplaneMcpSetup setup =
    AuthplaneMcpSetup.builder()
        .issuer("https://auth.example.com")
        .resource("https://mcp.example.com/mcp")
        .scopes(List.of("tools/read"))
        .inboundDPoP(InboundDPoPOptions.defaults(new InMemoryDPoPReplayStore())
                       .withRequired(true))  // optional: reject bearer-only tokens
        .build()
        .get();
```

See `mcp/src/main/java/ai/authplane/sdk/mcp/example/MathServer.java` for a runnable demo (set `AUTHPLANE_INBOUND_DPOP=optional` or `=required` before launching).

## 14. Resource cleanup

No explicit cleanup is required. `AuthplaneResource` uses lazy, demand-driven background refreshes via the configured `Executor` (daemon threads when the common `ForkJoinPool` is used). Call `setup.client().close()` on shutdown to clear the in-memory token cache. Once the setup is no longer referenced, any in-flight refresh completes and the whole object graph becomes garbage-collectable.

## 15. API reference

### `AuthplaneMcpSetup`

See [Core concepts — Components](#components-wired-by-authplanemcpsetup) for the accessor table.

### `AuthplaneMcpAdapter`

Implements `ServerTransportSecurityValidator` and `McpTransportContextExtractor<HttpServletRequest>`.

```java
new AuthplaneMcpAdapter(AuthplaneClient client, AuthplaneResource resource)
```

| Method | Description |
|---|---|
| `validateHeaders(Map<String, List<String>>)` | Validates `Authorization: Bearer <token>`; case-insensitive header lookup. Throws `ServerTransportSecurityException(401 or 403)` |
| `extract(HttpServletRequest)` | Re-verifies the token and returns an `McpTransportContext` containing `VerifiedClaims` at `CLAIMS_KEY`. Throws `AuthplaneException` on failure |
| `static getClaims(McpTransportContext)` | Retrieves the verified claims, or `null` when absent |
| `client()` | Underlying `AuthplaneClient` |
| `resource()` | Underlying `AuthplaneResource` |
| `public static final String CLAIMS_KEY = "authplane.claims"` | Context key used to store claims |

### `PrmServlet`

Jakarta Servlet serving the RFC 9728 PRM document as JSON.

```java
new PrmServlet(ProtectedResourceMetadata prm)
new PrmServlet(Map<String, Object> prmDocument)   // e.g. AuthplaneResource#prmResponse()
```

Response body is pre-serialized at construction time. Ships a single `doGet` handler.

### `UrlElicitationSupport`

| Member | Description |
|---|---|
| `static McpError toUrlElicitationRequiredError(Throwable)` | Converts a `ConsentRequiredException` with a consentUrl into an `McpError` (`-32042`); returns `null` otherwise |
| `static BiFunction<McpSyncServerExchange, CallToolRequest, CallToolResult> wrapToolWithUrlElicitation(BiFunction<...>)` | Wraps a tool handler so consent errors raise `McpError` automatically |

### `AuthplaneMcpException`

Extends `ai.authplane.sdk.core.errors.AuthplaneException`. Thrown by `extract(...)` and `UrlElicitationSupport` to wrap unexpected adapter-layer failures. Maps to HTTP 500 via `HttpStatus.of(...)`.

### Security properties

Enforced via the core SDK:

- **RFC 9068 compliance** — validates all required JWT claims (`iss`, `aud`, `sub`, `client_id`, `exp`, `nbf`, `iat`, `jti`, `typ`)
- **Type header enforcement** — only accepts `typ: "at+jwt"`
- **Asymmetric algorithms only** — HMAC and `none` are rejected at construction
- **SSRF hardening** — DNS pinning, IP blocklists, HTTPS-only, no redirects, response size caps
- **Background JWKS refresh** — refreshes at 80% of TTL
- **Stale cache fallback** — uses cached JWKS if a refresh fails
