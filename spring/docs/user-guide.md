# authplane-spring User Guide

OAuth 2.1 JWT authentication for [Spring Boot](https://spring.io/projects/spring-boot) MCP servers, powered by the [Authplane Java SDK](../../core/README.md). Supports both Spring Security and direct MCP transport-layer integration.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Path A: Spring Security](#path-a-spring-security)
  - [Path B: MCP Transport Hooks](#path-b-mcp-transport-hooks)
- [Choosing an Integration Path](#choosing-an-integration-path)
- [Configuration Reference](#configuration-reference)
- [Scope Enforcement](#scope-enforcement)
- [Accessing Token Claims](#accessing-token-claims)
- [Protected Resource Metadata (PRM)](#protected-resource-metadata-prm)
- [Token Revocation Checking](#token-revocation-checking)
- [Token Exchange (RFC 8693)](#token-exchange-rfc-8693)
- [URL Elicitation (No Equivalent)](#url-elicitation-no-equivalent)
- [Known Limitations (Transport Path)](#known-limitations-transport-path)
- [Development Mode](#development-mode)
- [SSRF Protection](#ssrf-protection)
- [Advanced: Manual Bean Wiring](#advanced-manual-bean-wiring)
- [Resource Cleanup](#resource-cleanup)
- [Error Handling](#error-handling)
- [API Reference](#api-reference)

---

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
  <groupId>ai.authplane.sdk</groupId>
  <artifactId>authplane-spring</artifactId>
  <version>1.0.0-SNAPSHOT</version>
</dependency>
```

Requires Java 21+ and Spring Boot 4.x.

## Quick Start

The adapter offers two independent integration paths. Choose one based on your needs (see [Choosing an Integration Path](#choosing-an-integration-path)).

### Path A: Spring Security

JWT validation via Spring Security's OAuth2 resource server filter chain. Claims are stored in the `SecurityContext`.

```java
import ai.authplane.sdk.spring.security.AuthplaneAuthentication;
import ai.authplane.sdk.spring.security.AuthplaneSecurityConfig;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;
import org.springframework.stereotype.Component;

@SpringBootApplication
@Import(AuthplaneSecurityConfig.class)
public class MyMcpServer {
    public static void main(String[] args) {
        SpringApplication.run(MyMcpServer.class, args);
    }
}

@Component
class MyTools {
    @Tool(description = "Execute a query")
    public String query(String sql) {
        AuthplaneAuthentication.current().requireScope("tools/query");
        return runQuery(sql);
    }
}
```

Add to `application.properties`:

```properties
authplane.issuer=https://auth.company.com
authplane.resource=https://mcp.company.com/mcp
authplane.scopes=tools/query,tools/write
```

### Path B: MCP Transport Hooks

JWT validation at the MCP transport layer without Spring Security. Claims are stored in the `McpTransportContext`.

```java
import ai.authplane.sdk.spring.mcp.AuthplaneMcpServerConfig;
import ai.authplane.sdk.spring.mcp.AuthplaneMcpServerAdapter;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import org.springframework.ai.chat.model.ToolContext;
import org.springframework.ai.mcp.McpToolUtils;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.stereotype.Component;

@SpringBootApplication(exclude = {
    SecurityAutoConfiguration.class,
    OAuth2ResourceServerAutoConfiguration.class,
    ServletWebSecurityAutoConfiguration.class
})
@Import(AuthplaneMcpServerConfig.class)
public class MyMcpServer {
    public static void main(String[] args) {
        SpringApplication.run(MyMcpServer.class, args);
    }
}

@Component
class MyTools {
    @Tool(description = "Execute a query")
    public String query(String sql, ToolContext toolContext) {
        McpSyncServerExchange exchange = McpToolUtils.getMcpExchange(toolContext).orElseThrow();
        AuthplaneMcpServerAdapter.getClaims(exchange.transportContext())
                .requireScope("tools/query");
        return runQuery(sql);
    }
}
```

Add to `application.properties`:

```properties
authplane.issuer=https://auth.company.com
authplane.resource=https://mcp.company.com/mcp
authplane.scopes=tools/query,tools/write
```

## Choosing an Integration Path

| Aspect | Path A: Spring Security | Path B: MCP Transport Hooks |
|--------|------------------------|----------------------------|
| **Config class** | `AuthplaneSecurityConfig` | `AuthplaneMcpServerConfig` |
| **Spring Security** | Yes (filter chain) | No (excluded) |
| **Claims access** | `AuthplaneAuthentication.current()` | `AuthplaneMcpServerAdapter.getClaims(context)` |
| **Scope enforcement** | `auth.requireScope(...)` or `@PreAuthorize` | `claims.requireScope(...)` |
| **401 response** | Structured JSON + `WWW-Authenticate` header | `ServerTransportSecurityException(401)` |
| **403 response** | Spring's `AccessDeniedException` handling | `InsufficientScopeException` |
| **Best for** | Apps that need Spring Security features | Minimal dependencies, framework-agnostic tools |

**Use Path A** when you want the full Spring Security ecosystem: `@PreAuthorize` annotations, `SecurityContext` propagation, structured error responses with `WWW-Authenticate` headers.

**Use Path B** when you want minimal dependencies and don't need Spring Security. The transport hooks validate tokens before they reach the MCP protocol layer.

## Configuration Reference

Both paths use the same `application.properties` keys:

### Required Properties

| Property | Description |
|----------|-------------|
| `authplane.issuer` | Authorization server URL |
| `authplane.resource` | URL of this MCP server (used as JWT audience) |
| `authplane.scopes` | Comma-separated scopes this server supports |

### Optional Properties

| Property | Default | Description |
|----------|---------|-------------|
| `authplane.dev-mode` | `false` | Relaxes SSRF checks for local development |
| `authplane.allowed-algorithms` | `RS256,ES256` | Allowed JWT signature algorithms (asymmetric only) |
| `authplane.clock-skew-seconds` | `30` | Leeway for `exp`/`nbf`/`iat` validation |
| `authplane.jwks-refresh-seconds` | `300` | JWKS cache TTL |
| `authplane.metadata-refresh-seconds` | `3600` | AS metadata cache TTL |
| `authplane.introspection.enabled` | `false` | Enable built-in RFC 7662 token introspection |
| `authplane.timeout-seconds` | `0` (SDK default: 10s) | HTTP request timeout |
| `authplane.circuit-breaker-threshold` | `0` (SDK default: 5) | Failures before the circuit breaker opens |
| `authplane.circuit-breaker-cooldown-seconds` | `0` (SDK default: 30s) | Cooldown before the circuit breaker transitions to half-open |
| `authplane.token-cache-ttl-buffer-seconds` | `0` (SDK default: 30s) | Buffer in seconds before token cache entries expire |

### Optional Beans

For advanced features that can't be expressed as properties, expose these beans:

| Bean type | Qualifier | Description |
|-----------|-----------|-------------|
| `AuthProvider` | — | Authorization Server credentials for introspection / token exchange (commonly `new ASCredentials(clientId, clientSecret)`) |
| `OutboundDPoPOptions` | — | Enables outbound DPoP proof generation for AS requests |
| `InboundDPoPOptions` | — | Enables inbound DPoP proof validation |
| `Executor` | `@Qualifier("authplaneExecutor")` | Custom executor for async operations (default: `ForkJoinPool.commonPool()`) |

## Scope Enforcement

### Path A: Spring Security

Use `AuthplaneAuthentication` to enforce scopes inside `@Tool` methods:

```java
import ai.authplane.sdk.spring.security.AuthplaneAuthentication;

@Tool(description = "Execute a query")
public String query(String sql) {
    AuthplaneAuthentication.current().requireScope("tools/query");
    return runQuery(sql);
}
```

`requireScope()` throws Spring's `AccessDeniedException` (HTTP 403) if the scope is missing.

#### Multiple Scopes

```java
AuthplaneAuthentication auth = AuthplaneAuthentication.current();

// Require ALL scopes
auth.requireAllScopes("tools/admin", "tools/delete");

// Check without throwing
if (auth.hasScope("tools/admin")) {
    // Privileged operation
}

// Check all without throwing
if (auth.hasAllScopes("tools/admin", "tools/delete")) {
    // Both scopes present
}
```

#### Using @PreAuthorize

Since each scope is mapped to a `SCOPE_<scope>` authority, you can use Spring Security's declarative annotations:

```java
import org.springframework.security.access.prepost.PreAuthorize;

@PreAuthorize("hasAuthority('SCOPE_tools/admin')")
@Tool(description = "Admin operation")
public String adminOp() {
    return "admin result";
}
```

### Path B: MCP Transport Hooks

Use `VerifiedClaims.requireScope()` via the transport context:

```java
import ai.authplane.sdk.spring.mcp.AuthplaneMcpServerAdapter;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import org.springframework.ai.chat.model.ToolContext;
import org.springframework.ai.mcp.McpToolUtils;

@Tool(description = "Execute a query")
public String query(String sql, ToolContext toolContext) {
    McpSyncServerExchange exchange = McpToolUtils.getMcpExchange(toolContext).orElseThrow();
    AuthplaneMcpServerAdapter.getClaims(exchange.transportContext())
            .requireScope("tools/query");
    return runQuery(sql);
}
```

`requireScope()` throws `InsufficientScopeException` if the scope is missing, which the MCP server returns as an error result.

## Accessing Token Claims

### Path A: Spring Security

#### Static Helper (Recommended)

```java
import ai.authplane.sdk.spring.security.AuthplaneAuthentication;

@Tool(description = "My tool")
public String myTool(String data) {
    AuthplaneAuthentication auth = AuthplaneAuthentication.current();

    // Standard JWT claims
    String sub      = auth.getSubject();     // Subject (user ID)
    String clientId = auth.getClientId();    // OAuth client ID
    List<String> scopes = auth.getScopes();  // Granted scopes

    // Single claim by key
    Object tenant = auth.getClaim("tenant_id");

    // Full raw claims map
    Map<String, Object> raw = auth.getRawClaims();

    // Full SDK access
    VerifiedClaims claims = auth.getClaims();
    String iss = claims.issuer();
    List<String> aud = claims.audience();
    String jti = claims.jti();

    return "Hello " + sub;
}
```

#### @AuthenticationPrincipal

```java
import org.springframework.security.core.annotation.AuthenticationPrincipal;

@Tool(description = "My tool")
public String myTool(String data,
        @AuthenticationPrincipal AuthplaneAuthentication auth) {
    String sub = auth.getSubject();
    return "Hello " + sub;
}
```

### Path B: MCP Transport Hooks

```java
import ai.authplane.sdk.core.VerifiedClaims;
import ai.authplane.sdk.spring.mcp.AuthplaneMcpServerAdapter;

@Tool(description = "My tool")
public String myTool(String data, ToolContext toolContext) {
    McpSyncServerExchange exchange = McpToolUtils.getMcpExchange(toolContext).orElseThrow();
    VerifiedClaims claims = AuthplaneMcpServerAdapter.getClaims(exchange.transportContext());

    String sub      = claims.sub();
    String clientId = claims.clientId();
    List<String> scopes = claims.scopes();
    Object tenant   = claims.raw().get("tenant_id");

    return "Hello " + sub;
}
```

## Protected Resource Metadata (PRM)

Both paths automatically serve [RFC 9728 Protected Resource Metadata](https://datatracker.ietf.org/doc/rfc9728/) at the well-known URI. This enables MCP clients to discover the authorization server and supported scopes.

The PRM endpoint location depends on the resource URL:

| Resource URL | PRM Endpoint |
|---|---|
| `https://mcp.company.com/mcp` | `GET /.well-known/oauth-protected-resource/mcp` |
| `https://mcp.company.com/api/v1` | `GET /.well-known/oauth-protected-resource/api/v1` |

The response includes:
- Authorization server URL (issuer)
- Supported scopes
- Bearer token methods
- Resource identifier

No additional configuration is needed; PRM is served automatically.

**Path A note**: The config bypasses Spring Security's built-in PRM filter (which produces an incomplete document) and serves the correct RFC 9728 document via a Spring MVC `RouterFunction`.

## Token Revocation Checking

By default, tokens are validated offline (signature + claims only). You can enable revocation checking to catch tokens that have been revoked before they expire.

### No Revocation (Default)

```properties
# No additional configuration needed
authplane.issuer=https://auth.company.com
authplane.resource=https://mcp.company.com/mcp
```

### RFC 7662 Introspection

Enable built-in introspection via a property:

```properties
authplane.issuer=https://auth.company.com
authplane.resource=https://mcp.company.com/mcp
authplane.introspection.enabled=true
```

Authenticated introspection requires client credentials. The SDK reads these from an
`AuthProvider` bean (not from properties):

```java
import ai.authplane.sdk.core.ASCredentials;
import ai.authplane.sdk.core.AuthProvider;
import org.springframework.context.annotation.Bean;

@Bean
public AuthProvider authProvider() {
    return new ASCredentials("my_resource_server", "secret");
}
```

- The introspection endpoint is automatically discovered from AS metadata.
- If the endpoint returns `active=false`, the token is rejected.
- **Fails open**: if the introspection endpoint is unavailable, the token is accepted (offline validation still applies).
- The `AuthProvider` bean enables authenticated introspection (recommended for production).

### Custom Revocation Checker

Expose a `RevocationChecker` bean for custom revocation logic. If both a `RevocationChecker` bean and `authplane.introspection.enabled=true` are set, the bean takes precedence:

```java
import ai.authplane.sdk.core.RevocationChecker;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RevocationConfig {

    @Bean
    public RevocationChecker revocationChecker(RedisClient redis) {
        return (rawToken, jti) ->
            redis.sismember("revoked_tokens", jti);
    }
}
```

## Token Exchange (RFC 8693)

Exchange a user token for a narrowly-scoped downstream token to call other services on behalf of the user.

Configure client credentials by exposing an `AuthProvider` bean:

```java
import ai.authplane.sdk.core.ASCredentials;
import ai.authplane.sdk.core.AuthProvider;
import org.springframework.context.annotation.Bean;

@Bean
public AuthProvider authProvider() {
    return new ASCredentials("https://mcp.company.com/mcp", "secret");
}
```

Then use the `AuthplaneClient` bean to perform token exchange:

```java
import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.TokenExchangeOptions;
import org.springframework.beans.factory.annotation.Autowired;

@Component
class MyTools {

    @Autowired
    private AuthplaneClient client;

    @Tool(description = "Query on behalf of user")
    public String queryOnBehalf(String sql) {
        AuthplaneAuthentication auth = AuthplaneAuthentication.current();
        auth.requireScope("tools/query");

        // Exchange the user's token
        var downstream = client
                .exchange(TokenExchangeOptions.builder(rawToken)
                        .scope(List.of("tools/query"))
                        .resource("https://downstream.company.com/api")
                        .build())
                .get();

        // Use downstream.accessToken() to call another service
        return callDownstream(downstream.accessToken(), sql);
    }
}
```

The token exchange client inherits SSRF settings and credentials from the original configuration.

## URL Elicitation (No Equivalent)

The `authplane-mcp` adapter ships a `UrlElicitationSupport.wrapToolWithUrlElicitation(...)` helper that translates `consent_required` / `interaction_required` token-exchange errors into MCP JSON-RPC URL elicitation responses (error code `-32042`). **There is no Spring-adapter equivalent.**

If your Spring tool handler calls `client.exchange(...)` and needs to surface consent URLs to MCP clients, you must handle the translation yourself:

```java
import ai.authplane.sdk.core.errors.TokenExchangeException;

try {
    TokenResponse downstream = client.exchange(options).get();
    return new CallToolResult(/* ... */);
} catch (ExecutionException e) {
    if (e.getCause() instanceof TokenExchangeException tee
            && ("consent_required".equals(tee.oauthError())
                || "interaction_required".equals(tee.oauthError()))) {
        // Build your own MCP error / return a consent URL to the client.
        // If you are wiring the transport-hooks path (Path B), you can depend on
        // `authplane-mcp` alongside `authplane-spring` and reuse
        // UrlElicitationSupport.toUrlElicitationRequiredError(e) directly.
        throw buildConsentError(tee);
    }
    throw e;
}
```

The `TokenExchangeException` exposes `oauthError()`. When the error is `consent_required` it is raised as the `ConsentRequiredException` subclass, which additionally exposes `consentUrl()`, `serviceId()`, and `causeDetail()` for building the response.

## Known Limitations (Transport Path)

Path A (Spring Security) does not have these limitations — verification happens once in the `SecurityFilterChain`, which has full request context and proper HTTP error mapping. The points below apply only to **Path B (MCP transport hooks)**.

The MCP Java SDK splits transport-level auth into two hooks with different capabilities:

1. **`validateHeaders(Map<String, List<String>>)`** — receives only headers. Can return proper HTTP status codes via `ServerTransportSecurityException` (401/403).
2. **`extract(ServerRequest)`** — receives the full request (method, URL, headers). Exceptions bubble as unhandled 500s; there is no mechanism to return a structured HTTP error.

This produces two observable consequences:

### Duplicate verification / double introspection

`validateHeaders` must call `resource.verify(...)` to produce a proper 401 on invalid tokens, but it lacks method and URL context so it cannot validate DPoP proofs. `extract` calls `resource.verify(...)` again with full context to perform DPoP validation and produce claims. When introspection-based revocation checking is enabled, this triggers **two introspection calls per request** to the authorization server.

### DPoP validation cannot produce a 401

`validateHeaders` cannot validate DPoP proofs because it only receives headers. `extract` has the full request context needed for DPoP, but failures there result in a 500 instead of a 401 with `WWW-Authenticate`. DPoP-related rejections (invalid proof, method mismatch, URL mismatch) therefore cannot return RFC-compliant error responses.

Tracked upstream: [modelcontextprotocol/java-sdk#887](https://github.com/modelcontextprotocol/java-sdk/issues/887).

## Development Mode

For local development, enable `dev-mode` to relax SSRF restrictions and allow HTTP/localhost:

```properties
authplane.issuer=http://localhost:9000
authplane.resource=http://localhost:8080/mcp
authplane.scopes=tools/query,tools/write
authplane.dev-mode=true
```

Development mode allows:
- HTTP (non-TLS) connections
- Localhost addresses (`127.0.0.0/8`)
- Private network addresses (`10.x`, `172.16-31.x`, `192.168.x`)

Cloud metadata addresses (`169.254.x`) are **always blocked**, even in dev mode.

## SSRF Protection

The adapter provides SSRF controls for JWKS and metadata fetching.

For most use cases, `authplane.dev-mode=true` is sufficient for local development. Use `authplane.timeout-seconds` when you need a custom HTTP timeout:

```properties
authplane.timeout-seconds=30
```

For full control, expose a `FetchSettings` bean or use the programmatic builder (see [Advanced: Manual Bean Wiring](#advanced-manual-bean-wiring)).

### Protection Details

| Check | Default | Description |
|-------|---------|-------------|
| HTTPS required | Yes | Blocks HTTP unless explicitly allowed |
| Localhost blocked | Yes | Blocks `127.0.0.0/8` |
| Private networks blocked | Yes | Blocks `10.x`, `172.16-31.x`, `192.168.x` |
| Cloud metadata blocked | **Always** | Blocks `169.254.x` (cannot be disabled) |
| DNS pinning | Yes | Resolves DNS once, validates the IP |
| Redirect blocking | Yes | Prevents open redirect attacks |
| Size limit | 64KB | Maximum JWKS response size |
| Timeout | 10s | HTTP request timeout |

## Advanced: Manual Bean Wiring

For scenarios requiring more control, you can wire up beans individually instead of importing the ready-made configurations.

### Path A: Manual Spring Security Setup

```java
import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.ResourceOptions;
import ai.authplane.sdk.spring.security.AuthplaneAuthenticationConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

@Configuration
public class ManualSecurityConfig {

    @Bean
    public AuthplaneClient authplaneClient() throws Exception {
        return AuthplaneClient.builder("https://auth.company.com")
            .jwksRefreshSeconds(600)
            .build()
            .get();
    }

    @Bean
    public AuthplaneResource authplaneVerifier(AuthplaneClient client) {
        return client.resource(
            "https://mcp.company.com/mcp",
            List.of("tools/query", "tools/write"),
            ResourceOptions.builder().clockSkewSeconds(60).build());
    }

    @Bean
    public SecurityFilterChain security(HttpSecurity http,
            AuthplaneResource verifier) throws Exception {
        // Scope the chain to the resource path and apply the AuthPlane configurer. The configurer
        // wires Spring's BearerTokenAuthenticationFilter (Bearer + DPoP), a request-aware
        // AuthenticationManagerResolver that delegates DPoP validation to the core verifier, and
        // the RFC 6750 / RFC 9728 entry point. Avoid http.oauth2ResourceServer(...) — in Spring
        // Security 7 it force-installs the native DPoP filter with no opt-out.
        return http
            .securityMatcher("/mcp", "/mcp/**")
            .csrf(csrf -> csrf.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .with(new AuthplaneAuthenticationConfigurer(verifier), Customizer.withDefaults())
            .build();
    }
}
```

### Path B: Manual Transport Setup

```java
import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.spring.mcp.AuthplaneMcpServerAdapter;
import org.springframework.ai.mcp.server.webmvc.transport.WebMvcStreamableServerTransportProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class ManualTransportConfig {

    @Bean
    public AuthplaneClient authplaneClient() throws Exception {
        return AuthplaneClient.builder("https://auth.company.com")
            .build()
            .get();
    }

    @Bean
    public AuthplaneResource authplaneVerifier(AuthplaneClient client) {
        return client.resource(
            "https://mcp.company.com/mcp",
            List.of("tools/query", "tools/write"));
    }

    @Bean
    public AuthplaneMcpServerAdapter adapter(AuthplaneResource verifier) {
        return new AuthplaneMcpServerAdapter(verifier);
    }

    @Bean
    public WebMvcStreamableServerTransportProvider transport(AuthplaneMcpServerAdapter adapter) {
        return WebMvcStreamableServerTransportProvider.builder()
            .securityValidator(adapter)
            .contextExtractor(adapter)
            .build();
    }
}
```

## Resource Cleanup

No explicit cleanup is required. The `AuthplaneResource` uses lazy, demand-driven background refreshes via the common `ForkJoinPool` (daemon threads) — there are no timers or scheduled executors to shut down. Once the verifier is no longer referenced, any in-flight refresh completes and no new ones are scheduled, allowing the entire object graph to be garbage collected.

## Error Handling

### Path A: Spring Security

| Exception | HTTP Status | Meaning |
|-----------|-------------|---------|
| Missing/invalid token | 401 | JSON body + `WWW-Authenticate: Bearer resource_metadata="<prm-url>"` |
| `AccessDeniedException` (from `requireScope`) | 403 | Token is valid but missing required scopes |
| All `AuthplaneException` | 401 | Authentication failed (expired, bad signature, etc.) |

The 401 response includes a `WWW-Authenticate` header with the PRM URL, enabling MCP clients to auto-discover the authorization server via RFC 9728.

### Path B: MCP Transport Hooks

| Exception | HTTP Status | Meaning |
|-----------|-------------|---------|
| `InsufficientScopeException` | 403 | Token is valid but missing required scopes |
| All other `AuthplaneException` | 401 | Authentication failed (expired, bad signature, etc.) |
| Missing/malformed header | 401 | No `Authorization: Bearer` header |

### Catching Specific Errors

When using the verifier directly, you can catch specific exceptions:

```java
import ai.authplane.sdk.core.errors.AuthplaneException;
import ai.authplane.sdk.core.errors.InsufficientScopeException;

try {
    VerifiedClaims claims = verifier.verify(token).get().claims();
} catch (InsufficientScopeException e) {
    log.info("Insufficient scope: " + e.getMessage());
    throw e;
} catch (AuthplaneException e) {
    log.warn("Auth failed: " + e.getMessage());
    throw e;
}
```

See the [core SDK user guide §9](../../core/docs/user-guide.md#9-error-handling) for the full exception hierarchy and the `HttpStatus` / `WwwAuthenticate` helpers.

## API Reference

### `AuthplaneSecurityConfig`

Ready-made `@Configuration` for Path A (Spring Security). Import with `@Import(AuthplaneSecurityConfig.class)`.

Wires up:
1. `AuthplaneClient` bean — owns AS connection state (metadata, JWKS, transport)
2. `AuthplaneResource` bean — lightweight JWT verifier scoped to the configured resource
3. `AuthplaneAuthenticationConfigurer` — contributes Spring's `BearerTokenAuthenticationFilter` (accepting `Bearer` and `DPoP` schemes, with DPoP proofs validated by the core verifier) to the resource-scoped chain
4. RFC 9728 PRM endpoint (`RouterFunction`)
5. `WebSecurityCustomizer` (bypasses Spring's built-in PRM filter)
6. `SecurityFilterChain` — scoped to the resource path (not global); returns a structured 401/403 whose `WWW-Authenticate` header points to the PRM document

Accepts optional beans: `OutboundDPoPOptions`, `InboundDPoPOptions`, `@Qualifier("authplaneExecutor") Executor`.

### `AuthplaneMcpServerConfig`

Ready-made `@Configuration` for Path B (MCP transport hooks). Import with `@Import(AuthplaneMcpServerConfig.class)`.

Wires up:
1. `AuthplaneClient` bean — owns AS connection state (metadata, JWKS, transport)
2. `AuthplaneResource` bean — lightweight JWT verifier scoped to the configured resource
3. `AuthplaneMcpServerAdapter` bean
4. `WebMvcStreamableServerTransportProvider` bean (with auth hooks)
5. RFC 9728 PRM endpoint (`RouterFunction`)

Accepts optional beans: `OutboundDPoPOptions`, `InboundDPoPOptions`, `@Qualifier("authplaneExecutor") Executor`.

### `AuthplaneAuthentication`

Spring Security `AbstractOAuth2TokenAuthenticationToken<OAuth2AccessToken>` backed by `VerifiedClaims`.

| Method | Return Type | Description |
|--------|-------------|-------------|
| `current()` (static) | `AuthplaneAuthentication` | Get from current `SecurityContext` |
| `of(VerifiedClaims, String)` (static) | `AuthplaneAuthentication` | Create from verified claims and the raw access token |
| `requireScope(String)` | `void` | Throws `AccessDeniedException` (403) if missing |
| `hasScope(String)` | `boolean` | Check without throwing |
| `requireAllScopes(String...)` | `void` | Require all scopes |
| `hasAllScopes(String...)` | `boolean` | Check all scopes |
| `getSubject()` | `String` | `sub` claim |
| `getClientId()` | `String` | `client_id` claim |
| `getScopes()` | `List<String>` | Parsed scope list |
| `getClaim(String)` | `Object` | Single raw claim value |
| `getRawClaims()` | `Map<String, Object>` | Full JWT claims map |
| `getClaims()` | `VerifiedClaims` | Underlying SDK claims |
| `getToken()` | `OAuth2AccessToken` | Raw access token (inherited from `AbstractOAuth2TokenAuthenticationToken`) |
| `getTokenAttributes()` | `Map<String, Object>` | Token claims as an attribute map (RFC 9068) |
| `getName()` | `String` | Returns `sub` claim |
| `getPrincipal()` | `Object` | Returns `sub` claim |
| `getAuthorities()` | `Collection<GrantedAuthority>` | `SCOPE_<scope>` authorities |

### `AuthplaneAuthenticationProvider`

Spring Security `AuthenticationProvider` that validates Bearer tokens.

| Method | Description |
|--------|-------------|
| `authenticate(Authentication)` | Validates the raw token from an `AuthplanePreAuthToken`, returns `AuthplaneAuthentication` |
| `supports(Class<?>)` | Returns `true` for `AuthplanePreAuthToken` |

`AuthplaneSecurityConfig` and `AuthplaneAuthenticationConfigurer` create and wire the provider internally — instantiate it directly (`new AuthplaneAuthenticationProvider(resource)`) only for fully custom chains.

### `AuthplaneAuthenticationConfigurer`

Spring Security `AbstractHttpConfigurer` that adds Authplane access-token authentication to an `HttpSecurity` chain — apply it with `http.securityMatcher("/mcp").with(new AuthplaneAuthenticationConfigurer(resource), Customizer.withDefaults())`. It wires Spring's `BearerTokenAuthenticationFilter` with a resolver that accepts both the `Bearer` and RFC 9449 `DPoP` schemes, a request-aware `AuthenticationManagerResolver` that builds the `VerificationRequestContext` (method, URL, DPoP proof) so the core verifier stays the single DPoP authority, and an `AuthplaneAuthenticationEntryPoint`. It deliberately avoids `http.oauth2ResourceServer(...)`, which in Spring Security 7 force-installs the native DPoP filter with no opt-out.

### `AuthplaneAuthenticationEntryPoint`

Spring Security `AuthenticationEntryPoint` that renders RFC 6750 / RFC 9728 challenges — a structured 401 whose `WWW-Authenticate` header points at the PRM document — via the shared `FailureResponse`. Created internally by `AuthplaneAuthenticationConfigurer`.

### `AuthplaneMcpServerAdapter`

Spring MVC adapter implementing `ServerTransportSecurityValidator` and `McpTransportContextExtractor<ServerRequest>`.

| Method | Description |
|--------|-------------|
| `validateHeaders(Map<String, List<String>>)` | Validates Bearer token from request headers |
| `extract(ServerRequest)` | Re-verifies token and returns `McpTransportContext` with claims |
| `getClaims(McpTransportContext)` (static) | Retrieves `VerifiedClaims` from the transport context |

### `VerifiedClaims`

Immutable validated token claims (from the core SDK).

| Method | Return Type | Description |
|--------|-------------|-------------|
| `sub()` | `String` | Subject (user ID) |
| `clientId()` | `String` | OAuth client ID |
| `issuer()` | `String` | Issuer (`iss` claim) |
| `audience()` | `List<String>` | Audience list (`aud` claim); always contains the configured resource URI |
| `jti()` | `String` | JWT ID |
| `scopes()` | `List<String>` | Granted scopes |
| `raw()` | `Map<String, Object>` | Full unmodifiable JWT claims map |
| `requireScope(String)` | `void` | Throws `InsufficientScopeException` if scope is missing |
| `hasScope(String)` | `boolean` | Returns `true` if the token carries the scope |
| `hasClaim(String)` | `boolean` | Returns `true` if the claim exists |

### Security Properties

The adapter enforces (via the core SDK):

- **RFC 9068 compliance** — validates all 9 required JWT claims (`iss`, `aud`, `sub`, `client_id`, `exp`, `nbf`, `iat`, `jti`, `typ`)
- **Type header enforcement** — only accepts `typ: "at+jwt"`
- **Asymmetric algorithms only** — HMAC and `none` are rejected
- **SSRF protection** — DNS pinning, IP blocklists, protocol allowlists, redirect blocking
- **Background JWKS refresh** — refreshes at 80% of TTL to avoid request-time latency
- **Stale cache fallback** — uses cached JWKS if a refresh fails, maintaining availability
