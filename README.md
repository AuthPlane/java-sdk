# Authplane Java SDK

[![CI](https://img.shields.io/github/actions/workflow/status/AuthPlane/java-sdk/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/AuthPlane/java-sdk/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/actions/workflow/status/AuthPlane/java-sdk/release.yml?style=flat-square&label=release)](https://github.com/AuthPlane/java-sdk/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](LICENSE)

OAuth 2.1 JWT validation and token operations for Java resource servers, with first-class adapters for Model Context Protocol (MCP) servers and Spring applications.

## Packages

| Package | Maven coordinates | Purpose |
|---|---|---|
| [`authplane-sdk`](core/README.md) | `ai.authplane.sdk:authplane-sdk` | Framework-agnostic JWT validation, AS metadata discovery, token operations, DPoP |
| [`authplane-mcp`](mcp/README.md) | `ai.authplane.sdk:authplane-mcp` | Adapter for the [MCP Java SDK](https://github.com/modelcontextprotocol/java-sdk)'s servlet transport |
| [`authplane-spring`](spring/README.md) | `ai.authplane.sdk:authplane-spring` | Adapter for Spring Security and Spring AI's MCP WebMVC transport |

Requires Java 21+.

## Quickstart — MCP server with auth

Using the [`authplane-mcp`](mcp/README.md) adapter for the [MCP Java SDK](https://github.com/modelcontextprotocol/java-sdk)'s servlet transport:

```java
AuthplaneMcpSetup setup = AuthplaneMcpSetup.builder()
        .issuer("https://auth.company.com")
        .resource("https://mcp.company.com/mcp")
        .scopes(List.of("tools/query"))
        .build()
        .get();

HttpServletStreamableServerTransportProvider transport =
        HttpServletStreamableServerTransportProvider.builder()
                .mcpEndpoint(setup.mcpPath())
                .securityValidator(setup.adapter())
                .contextExtractor(setup.adapter())
                .build();

McpServer.sync(transport)
        .serverInfo(Implementation.builder("My Server", "1.0.0").build())
        .tools(/* ... */)
        .build();

setup.registerServlets(servletContext, transport);
```

That wires RFC 8414 metadata discovery, JWKS caching, RFC 9068 token validation, and RFC 9728 Protected Resource Metadata in one builder. Call `setup.client().close()` on shutdown to clear the token cache. For Spring applications, see [`authplane-spring`](spring/README.md).

## Capabilities

### Standards and RFCs

- OAuth 2.1 (draft-ietf-oauth-v2-1)
- RFC 8414 — Authorization Server Metadata discovery
- RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens
- RFC 7662 — Token Introspection
- RFC 7009 — Token Revocation
- RFC 8693 — Token Exchange
- RFC 8707 — Resource Indicators
- RFC 9449 — DPoP (sender-constrained access tokens)
- RFC 9728 — OAuth 2.0 Protected Resource Metadata
- RFC 6750 — Bearer Token Usage
- RFC 7234 — HTTP caching semantics on discovery responses
- RFC 7519 / 7517 — JWT and JWKS

### Security

- JWT signature, issuer, audience, `exp` / `nbf` / `iat`, and `typ` (`at+jwt`) validation; required claims enforced (`sub`, `client_id`, `exp`, `iat`, `jti`)
- Algorithm-confusion defenses: only `RS256` and `ES256` (asymmetric) are accepted; `none`, `HS256`, `HS384`, `HS512` are always rejected at construction
- AS metadata hardening: discovered `issuer` must match the configured issuer exactly; required endpoints must be present
- SSRF hardening on outbound HTTP: DNS pinning, HTTPS-only by default, cloud-metadata / loopback / private-network / link-local blocking, response size cap, no redirects
- Dev-mode toggle that opens HTTP, loopback, and RFC 1918 private ranges while keeping DNS pinning, the IP blocklist, and cloud-metadata blocking active (defense-in-depth survives a dev-mode build accidentally reaching production)
- JWKS resilience: stale-cache fallback, background refresh at 80% TTL, force-refresh on `kid` miss
- Inbound DPoP proof verification: binding (`cnf.jkt`), replay protection, `htm` / `htu` / `ath` checks
- Outbound DPoP proof generation with per-origin nonce handling
- Circuit breaker around authorization-server calls
- Token caching with TTL buffers and a fallback TTL when `expires_in` is missing

### Framework integrations

- MCP Java SDK servlet transport → [`authplane-mcp`](mcp/README.md)
- Spring Security OAuth2 Resource Server filter chain → [`authplane-spring`](spring/README.md) (Path A)
- Spring AI's MCP WebMVC transport → [`authplane-spring`](spring/README.md) (Path B)

### Observability

- `java.util.logging` structured logs across JWKS refresh, metadata discovery, circuit-breaker transitions, token verification, and DPoP binding outcomes
- Immutable validated claims (`VerifiedClaims`) safe to pass between threads

## Documentation

- `authplane-sdk` — [README](core/README.md) · [User Guide](core/docs/user-guide.md)
- `authplane-mcp` — [README](mcp/README.md) · [User Guide](mcp/docs/user-guide.md)
- `authplane-spring` — [README](spring/README.md) · [User Guide](spring/docs/user-guide.md)
- Release history — [CHANGELOG.md](CHANGELOG.md)
- Security policy — [SECURITY.md](SECURITY.md)
- Contributing — [CONTRIBUTING.md](CONTRIBUTING.md)
- Release policy — [RELEASE_POLICY.md](RELEASE_POLICY.md)

## License

Apache 2.0 — see [LICENSE](LICENSE).
