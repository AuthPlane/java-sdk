# authplane-sdk User Guide

Framework-agnostic OAuth 2.1 JWT validation and token operations for Java resource servers. This is the complete reference for the `ai.authplane.sdk:authplane-sdk` package.

The SDK is built around these RFCs:

- RFC 8414 — Authorization Server Metadata
- RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens
- RFC 7662 — Token Introspection
- RFC 8693 — Token Exchange
- RFC 7009 — Token Revocation
- RFC 9449 — DPoP
- RFC 9728 — Protected Resource Metadata
- RFC 6750 — Bearer Token Usage

## 1. Install

```xml
<dependency>
    <groupId>ai.authplane.sdk</groupId>
    <artifactId>authplane-sdk</artifactId>
    <version>0.3.0</version>
</dependency>
```

Requires Java 21+. The only production dependency is `com.nimbusds:nimbus-jose-jwt`.

### Required JVM property

The SDK's outbound HTTP path uses `java.net.http.HttpClient` with explicit DNS pinning: a URL is resolved to an IP, the request connects to that IP, and the original hostname is sent in the `Host` header so virtual-host routing on the server side keeps working. Java 11+ blocks the `Host` header on stdlib `HttpClient` by default, so consumers must enable it at JVM startup:

```
-Djdk.httpclient.allowRestrictedHeaders=host
```

This applies to every JVM that loads `authplane-sdk` (test, dev, prod). The flag lifts a JDK-internal "prevent careless mistakes" guard, not a security boundary — every other Java HTTP client (Apache HttpClient, OkHttp, async-http-client) lets you set `Host` freely. SDKs in other languages don't need an equivalent; this is specific to `java.net.http.HttpClient`.

## 2. Quickstart

```java
import ai.authplane.sdk.core.AuthplaneClient;
import ai.authplane.sdk.core.AuthplaneResource;
import ai.authplane.sdk.core.VerifiedClaims;

import java.util.List;

try (AuthplaneClient client =
        AuthplaneClient.builder("https://auth.example.com").build().get()) {

    AuthplaneResource verifier =
            client.resource("https://api.example.com", List.of("read:data", "write:data"));

    VerifiedClaims claims = verifier.verify(bearerToken).get().claims();
    claims.requireScope("read:data");

    String subject = claims.sub();
    String clientId = claims.clientId();
}
```

`AuthplaneClient.builder(...).build()` returns a `CompletableFuture<AuthplaneClient>` that completes when AS metadata discovery and the initial JWKS fetch have succeeded. `verify(...)` returns a `CompletableFuture<VerificationResult>`. `.get()` here is illustrative — integrate with your framework's async model in production.

## 3. Core concepts

### `AuthplaneClient`

Central owner of authorization-server connection state: AS metadata cache, JWKS cache, HTTP transport, circuit breaker, token cache, and optional outbound DPoP configuration. Always built via `AuthplaneClient.builder(issuer).build()`. Implements `AutoCloseable`.

A single client can back many resources. Call `close()` on shutdown to clear the token cache.

### `AuthplaneResource`

Lightweight protected-resource verifier, scoped to one resource URI and one scope list. Always created from a client via `client.resource(resourceUri, scopes)` or `client.resource(resourceUri, scopes, options)`. Its only job is JWT verification and PRM generation.

Resources share their parent client's metadata cache, JWKS cache, and transport. You can own multiple `AuthplaneResource` instances backed by the same client.

### Async model

All I/O returns `CompletableFuture`. The default executor is the common `ForkJoinPool`. For production, supply a dedicated executor to `AuthplaneClientBuilder.executor(...)` to avoid starving the shared pool under load.

## 4. Basic usage — verify a Bearer token

```java
AuthplaneClient client = AuthplaneClient.builder("https://auth.example.com").build().get();
AuthplaneResource verifier = client.resource(
        "https://api.example.com",
        List.of("read:data", "write:data"));

VerificationResult result = verifier.verify(bearerToken).get();
VerifiedClaims claims = result.claims();

claims.requireScope("read:data");  // throws InsufficientScopeException (HTTP 403) if missing

String sub      = claims.sub();
String clientId = claims.clientId();
List<String> scopes = claims.scopes();
```

`verify(String)` performs the full RFC 9068 sequence: header decoding, algorithm check, signature verification against the cached JWKS, and claim validation (`iss`, `aud`, `typ=at+jwt`, `exp`, `nbf`, `iat`, plus required `sub`, `client_id`, `jti`). A revocation check runs afterwards if configured.

## 5. Main API reference

### `AuthplaneClient`

| Method | Returns | Description |
|---|---|---|
| `static AuthplaneClientBuilder builder(String issuer)` | `AuthplaneClientBuilder` | Builder using RFC 8414 discovery for the given issuer |
| `AuthplaneResource resource(String resourceUri, List<String> scopes)` | `AuthplaneResource` | Creates a verifier with default `ResourceOptions` |
| `AuthplaneResource resource(String resourceUri, List<String> scopes, ResourceOptions options)` | `AuthplaneResource` | Creates a verifier with custom options |
| `CompletableFuture<TokenResponse> clientCredentials(List<String> scopes, List<String> resources)` | `CompletableFuture<TokenResponse>` | RFC 6749 §4.4 client-credentials grant; RFC 8707 multi-resource |
| `CompletableFuture<TokenResponse> exchange(TokenExchangeOptions options)` | `CompletableFuture<TokenResponse>` | RFC 8693 token exchange |
| `CompletableFuture<IntrospectionResponse> introspect(String token)` | `CompletableFuture<IntrospectionResponse>` | RFC 7662 token introspection |
| `CompletableFuture<Void> revoke(String token)` | `CompletableFuture<Void>` | RFC 7009 token revocation |
| `Map<String, String> dpopHeaders(String method, String absoluteUrl)` | `Map<String, String>` | DPoP header for a downstream request (no `ath`) |
| `Map<String, String> dpopHeaders(String method, String absoluteUrl, String accessToken)` | `Map<String, String>` | DPoP header bound to an access token via `ath` |
| `String issuer()` | `String` | The normalized configured issuer |
| `boolean devMode()` | `boolean` | Whether dev-mode relaxations are active |
| `void close()` | `void` | Clears the token cache; safe to call multiple times |

### `AuthplaneResource`

| Method | Returns | Description |
|---|---|---|
| `CompletableFuture<VerificationResult> verify(String token)` | `CompletableFuture<VerificationResult>` | Verify a JWT access token without request-context DPoP validation |
| `CompletableFuture<VerificationResult> verify(String token, VerificationRequestContext context)` | `CompletableFuture<VerificationResult>` | Verify a JWT and apply inbound DPoP validation when configured |
| `Map<String, Object> prmResponse()` | `Map<String, Object>` | RFC 9728 Protected Resource Metadata document for this resource |
| `String prmPath()` | `String` | URL path at which this resource's RFC 9728 PRM document should be served |
| `String prmUrl()` | `String` | Absolute URL of the resource-hosted RFC 9728 PRM document, always derived from the resource identifier (returned verbatim — not header-escaped) |
| `String resourceMetadataUrl()` | `String` | URL to advertise in the `resource_metadata` challenge parameter: the configured override, else `prmUrl()` (returned verbatim — not header-escaped) |
| `String resourceUri()` | `String` | The scoped resource URI |
| `List<String> scopes()` | `List<String>` | The configured scope list |
| `AuthplaneClient client()` | `AuthplaneClient` | The parent client |

### `VerifiedClaims` (record)

Immutable snapshot of the validated claims. Accessor names match the record components.

| Accessor | Type | Description |
|---|---|---|
| `sub()` | `String` | Subject (end user or service account) |
| `clientId()` | `String` | OAuth client ID (`client_id`) |
| `scopes()` | `List<String>` | Granted scopes (parsed from the space-separated `scope` claim) |
| `issuer()` | `String` | Token issuer (`iss`) |
| `audience()` | `List<String>` | All audiences from the `aud` claim; the configured resource URI is guaranteed to be present |
| `expiresAt()` | `long` | Unix epoch seconds (`exp`) |
| `issuedAt()` | `long` | Unix epoch seconds (`iat`) |
| `notBefore()` | `long` | Unix epoch seconds (`nbf`); `0` when absent |
| `jti()` | `String` | Unique JWT identifier |
| `kid()` | `String` | Key ID used to sign this token |
| `raw()` | `Map<String, Object>` | Unmodifiable snapshot of the full JWT payload |
| `agentId()` | `String` | `agent_id` claim; empty string when absent |
| `agentChain()` | `List<String>` | `agent_chain` claim; empty list when absent |

| Method | Description |
|---|---|
| `boolean hasScope(String scope)` | Case-sensitive, exact scope check |
| `void requireScope(String scope)` | Throws `InsufficientScopeException` (HTTP 403) if absent |
| `boolean hasClaim(String key)` | Check presence of any raw claim |
| `boolean hasClaim(String key, Object value)` | Check a raw claim equals the expected value |
| `Map<String, Object> act()` | `act` (actor) claim, or `null` |
| `Map<String, Object> mayAct()` | **Deprecated** — authserver 0.2.0 no longer issues `may_act`; removed in the next minor. Returns the claim, or `null` |
| `Map<String, Object> cnf()` | `cnf` claim as an immutable map, or `Map.of()` |
| `boolean hasCnf()` | True when the token carries a `cnf` claim |
| `boolean isDpopBound()` | True when `cnf.jkt` is present and non-blank |
| `String dpopThumbprint()` | `cnf.jkt`, or `null` |

### `VerificationResult` (record)

| Accessor / method | Description |
|---|---|
| `claims()` | The verified `VerifiedClaims` |
| `dpopProof()` | Accepted `VerifiedDPoPProof`; `null` for bearer-only verification |
| `hasDpopProof()` | Convenience check |
| `static bearer(VerifiedClaims)` | Constructs a bearer-only result |
| `static dpop(VerifiedClaims, VerifiedDPoPProof)` | Constructs a DPoP result |

### `TokenResponse` (record)

| Accessor | Type | Description |
|---|---|---|
| `accessToken()` | `String` | The exchanged access token |
| `tokenType()` | `String` | Typically `"Bearer"` |
| `expiresIn()` | `Integer` | Lifetime in seconds, or `null` when omitted by the AS |
| `scopes()` | `List<String>` | Granted scopes echoed by the AS, or `null` |
| `issuedTokenType()` | `String` | RFC 8693 issued-token-type URN, or `null` |

RFC 9449 does not place `cnf` on the token response. For a DPoP-bound token the key binding is in the `at+jwt` body (read via `VerifiedClaims.dpopThumbprint()` after verification) or, for opaque tokens, in the introspection response (`IntrospectionResponse.dpopThumbprint()`, RFC 9449 §6.2).

### `IntrospectionResponse` (record)

| Accessor | Type | Description |
|---|---|---|
| `active()` | `boolean` | Whether the token is active (RFC 7662) |
| `raw()` | `Map<String, Object>` | The full introspection response as an immutable map |
| `cnf()` | `Map<String, Object>` | Top-level `cnf` confirmation claim (RFC 9449 §6.2), or `Map.of()` |
| `dpopThumbprint()` | `String` | Convenience: top-level `cnf.jkt`, or `null` when not DPoP-bound |

### `ASCredentials` (record)

```java
new ASCredentials(String clientId, String clientSecret)
```

Credentials of an already-registered OAuth client. Used by the SDK to authenticate to the AS at the token, introspection, and revocation endpoints. Not a dynamic-client-registration payload.

## 6. Configuration options

### `AuthplaneClientBuilder`

Every builder method on `AuthplaneClient.builder(...)`:

| Method | Type | Default | Purpose |
|---|---|---|---|
| `devMode(boolean)` | `boolean` | `false` | Relax SSRF — allow HTTP, localhost, private networks. Overrides `fetchSettings` unless the latter is explicitly set |
| `fetchSettings(FetchSettings)` | `FetchSettings` | — | Full control over SSRF / fetch behaviour; overrides `devMode` |
| `jwksRefreshSeconds(int)` | `int` | `300` | JWKS refresh interval |
| `metadataRefreshSeconds(int)` | `int` | `3600` | AS metadata refresh interval |
| `authProvider(AuthProvider)` | `AuthProvider` | `null` | AS authentication for token / introspection / revocation calls. Pass `new ASCredentials(clientId, clientSecret)` for static HTTP Basic, or a custom provider for credential rotation / non-Basic schemes |
| `outboundDPoP(OutboundDPoPOptions)` | `OutboundDPoPOptions` | `null` | Enables DPoP proofs on AS POSTs and `dpopHeaders(...)` |
| `executor(Executor)` | `Executor` | `ForkJoinPool.commonPool()` | Executor for all async work. **Production deployments should supply a dedicated executor** — the common pool has limited parallelism (CPU cores − 1) and is shared JVM-wide |
| `circuitBreakerThreshold(int)` | `int` | `5` | Consecutive failures before the breaker opens |
| `circuitBreakerCooldownSeconds(int)` | `int` | `30` | Cooldown before the breaker transitions to half-open |
| `tokenCacheConfig(TokenCacheConfig)` | `TokenCacheConfig` | `TokenCacheConfig.defaults()` | Token cache tuning: TTL buffer before expiry (default `30`s), fallback TTL when `expires_in` is absent (default `3600`s), and max entries before LRU eviction (default `10000`) |
| `build()` | — | — | Returns `CompletableFuture<AuthplaneClient>` after validation + discovery + initial JWKS fetch |

`AUTHPLANE_DEV_MODE=true` in the environment flips `devMode` on at build time.

Both refresh intervals are driven by traffic, not by a background timer: the first call past the interval pays for the refetch. For the metadata document that call is a `verify()` — a resource server that only verifies tokens therefore still tracks the AS. When `jwks_uri` changes, the metadata read that discovers it rebinds JWKS fetching to the new URI before the token in hand is verified, and if that rebind fails (the new endpoint is briefly down) the next key lookup retries it. A metadata endpoint that is unreachable never fails verification: the last known good document keeps being served, and a failed refresh is not retried on the network for another 30 seconds.

### `ResourceOptions`

Per-resource configuration. Supply to `client.resource(resourceUri, scopes, options)`.

| Builder method | Default | Purpose |
|---|---|---|
| `allowedAlgorithms(List<String>)` | `["RS256", "ES256"]` | JWT signing algorithms; only `RS256` and `ES256` (asymmetric) are supported, `none` and HMAC (HS256/384/512) are always rejected |
| `clockSkewSeconds(int)` | `30` | Leeway applied to `exp`, `nbf`, `iat` |
| `inboundDPoP(InboundDPoPOptions)` | `null` | Enables inbound DPoP proof validation |
| `resourceMetadataUrl(String)` | derived | Advertises this URL in the `resource_metadata` challenge parameter instead of the derived, resource-hosted one; must be an absolute `http(s)` URL naming a host, with no fragment, no userinfo, and a valid RFC 3986 query |
| `useBuiltinRevocationChecker()` | disabled | Enables RFC 7662 introspection-based revocation checking; mutually exclusive with `revocationChecker(...)` |
| `revocationChecker(RevocationChecker)` | `null` | Plug in a custom checker (e.g. Redis blocklist); mutually exclusive with `useBuiltinRevocationChecker()` |
| `failClosed()` | fail-open | Reject tokens if the revocation check throws |

`ResourceOptions.defaults()` returns the options above with all defaults.

### `FetchSettings` (record)

```java
new FetchSettings(
    boolean ssrfProtection,      // DNS pinning, IP blocklists
    boolean allowHttp,           // plain http://
    boolean allowLocalhost,      // 127.0.0.0/8, ::1
    boolean allowPrivateNetworks,// RFC 1918
    int timeoutSeconds           // connect + request timeout
)
```

| Factory | Shape |
|---|---|
| `FetchSettings.production()` | `(true, false, false, false, 10)` |
| `FetchSettings.devMode()` | `(true, true, true, true, 10)` |
| `FetchSettings.fromDevMode(boolean)` | `production()` or `devMode()` |

Cloud-metadata ranges (`169.254.0.0/16`) and IPv6 link-local (`fe80::/10`) are always blocked regardless of settings.

## 7. Intermediate features

### Scope enforcement

```java
if (!claims.hasScope("tools/admin")) {
    // branch without throwing
}

claims.requireScope("tools/admin");      // throws InsufficientScopeException (HTTP 403)
claims.requireScope("tools/delete");     // AND logic: call each
```

### Built-in revocation via RFC 7662 introspection

```java
ResourceOptions options = ResourceOptions.builder()
        .useBuiltinRevocationChecker()
        .build();

AuthplaneResource verifier = client.resource(resourceUri, scopes, options);
```

Uses the client's metadata cache to discover the introspection endpoint, the client's AS credentials for HTTP Basic auth, and the client's SSRF-safe transport. **Fails open** by default on transport or endpoint errors. Add `.failClosed()` to reject tokens when the checker throws.

**Who may introspect (authserver ≥ 0.1.2).** The client behind `ASCredentials` must be confidential (a public client cannot introspect at all) and must be either the client the token was issued to or a runtime-client of the Resource named in `aud`. Anyone else gets `{"active": false}`, so a resource server introspecting with the wrong credentials rejects every token as revoked. Register the resource server on its Resource with:

```bash
authserver admin resource runtime-client add --client-id <rs-client-id> --slug <resource-slug>
```

The checker logs a warning at construction when the client has no `AuthProvider`, and once when introspection answers `active: false` for a token that already passed local JWT verification.

### Custom revocation checker

```java
RevocationChecker blocklist = (rawToken, jti) ->
        redisClient.sismember("revoked_tokens", jti);

ResourceOptions options = ResourceOptions.builder()
        .revocationChecker(blocklist)
        .build();
```

The checker is called only after cryptographic validation succeeds. Returning `true` rejects the token. Thrown exceptions are either logged (fail-open, default) or converted into `TokenRevokedException` (fail-closed).

### Direct introspection and revocation

```java
IntrospectionResponse resp = client.introspect(accessToken).get();
boolean active = resp.active();
Map<String, Object> full = resp.raw();

client.revoke(accessToken).get();
```

Both calls authenticate to the AS using the configured `ASCredentials` and route through the circuit breaker.

## 8. Advanced features

### Token operations

#### Client credentials

```java
TokenResponse token = client.clientCredentials(
        List.of("read:data"),                   // scopes; empty list → omit `scope` param
        List.of("https://api.example.com")      // resources (RFC 8707); empty list → omit
).get();
```

Caches by the requested scope/resource combination.

#### Token exchange (RFC 8693)

```java
TokenResponse exchanged = client.exchange(
        TokenExchangeOptions.builder(incomingAccessToken)
                .scope(List.of("read:data"))
                .resource("https://api.example.com")
                .build()
).get();
```

`TokenExchangeOptions.Builder` methods:

| Method | Purpose |
|---|---|
| `subjectTokenType(String)` | Override the default `urn:ietf:params:oauth:token-type:access_token` |
| `scope(List<String>)` | Scopes for the exchanged token |
| `resource(String)` / `resources(List<String>)` | Resource indicators (RFC 8707) |
| `audience(String)` / `audiences(List<String>)` | Audience claim for the exchanged token |
| `actorToken(String)` | Actor token for delegation (RFC 8693 §2.1) |
| `actorTokenType(String)` | Actor token type URN |

##### Exchange errors

All three are subtypes of `TokenExchangeException`, and none of them trips the circuit breaker — the AS answered correctly:

- `ConsentRequiredException` (`consent_required` / `interaction_required`): the user has not granted the downstream service; surface `consentUrl()` and retry after consent.
- `AccessDeniedException` (`access_denied`, HTTP 403): on a cross-client exchange, the operator has not allowlisted the exchanging client on the target Resource. Re-prompting the user will not fix it — the Resource policy must change (next section).
- `InvalidTargetException` (`invalid_target`, HTTP 400, RFC 8707 §2.2): the `resource` string does not match a granted resource exactly — a trailing slash or a different scheme is enough. Send the resource identifier byte for byte as it was granted.

##### Operator step: allowlist the exchanging client

For each MCP server that exchanges for a downstream resource it does not itself act as, allowlist its client ID on that Resource:

```http
PATCH /admin/resources/{id}
{"policy": {"exchange": {"allowed_client_ids": ["<exchanging-client-id>"]}}}
```

A client exchanging a token issued to itself, fronted exchanges, and Broker resources need nothing.

#### Token cache behaviour

A shared in-memory cache backs both `clientCredentials` and `exchange`.

- **Client-credentials cache key** — normalized scope + resource set.
- **Token-exchange cache key** — the full effective input set: `subject_token`, `subject_token_type`, `actor_token`, `actor_token_type`, normalized scopes, normalized resources, normalized audiences. Different subject tokens are never treated as equivalent.
- **TTL** — if the AS reports `expires_in`, the cache uses that value; otherwise it falls back to `TokenCacheConfig.defaultTtlSeconds()`. In both cases `TokenCacheConfig.ttlBufferSeconds()` is subtracted so the SDK stops using cached tokens slightly before they expire. The cache is bounded to `TokenCacheConfig.maxEntries()` with least-recently-used eviction.

### Outbound DPoP

Configure outbound DPoP on the client when your AS calls or downstream API calls must carry proofs:

```java
import ai.authplane.sdk.core.dpop.DPoPAlgorithm;
import ai.authplane.sdk.core.dpop.DPoPKeyMaterial;
import ai.authplane.sdk.core.dpop.DPoPProvider;
import ai.authplane.sdk.core.dpop.OutboundDPoPOptions;
import com.nimbusds.jose.jwk.JWK;

DPoPKeyMaterial keyMaterial = DPoPKeyMaterial.fromJwk(privateJwk, DPoPAlgorithm.ES256);
DPoPProvider provider = new DPoPProvider(keyMaterial);

try (AuthplaneClient client = AuthplaneClient.builder("https://auth.example.com")
        .authProvider(new ASCredentials("my-rs", "s3cret"))
        .outboundDPoP(new OutboundDPoPOptions(provider))
        .build()
        .get()) {

    TokenResponse token = client.clientCredentials(List.of("read:data"), List.of()).get();

    Map<String, String> headers = client.dpopHeaders(
            "GET",
            "https://api.example.com/data",
            token.accessToken());
}
```

`DPoPKeyMaterial` factories:

| Factory | Input |
|---|---|
| `DPoPKeyMaterial.fromJwk(JWK privateJwk, DPoPAlgorithm algorithm)` | Nimbus `JWK` private key |
| `DPoPKeyMaterial.fromPem(String pem, DPoPAlgorithm algorithm)` | PEM-encoded private key |
| `DPoPKeyMaterial.fromPublicAndPrivateJwks(Map, Map, DPoPAlgorithm)` | Explicit public + private JWK maps |

`DPoPAlgorithm` values: `RS256`, `ES256`.

### Inbound DPoP

DPoP enablement and policy are configured **per resource**, matching RFC 9728 § 2 (OAuth Protected Resource Metadata) which scopes `dpop_bound_access_tokens_required` and `dpop_signing_alg_values_supported` as per-resource metadata. Different protected resources behind the same authorization server can have different DPoP requirements. Per-request, only the proof JWT plus the `htm` / `htu` / `ath` claims (RFC 9449 § 7) are supplied.

Enable inbound DPoP validation on the verifier:

```java
import ai.authplane.sdk.core.dpop.InboundDPoPOptions;
import ai.authplane.sdk.core.dpop.InMemoryDPoPReplayStore;
import ai.authplane.sdk.core.dpop.VerificationRequestContext;

ResourceOptions options = ResourceOptions.builder()
        .inboundDPoP(InboundDPoPOptions.defaults(new InMemoryDPoPReplayStore()))
        .build();

AuthplaneResource verifier = client.resource(
        "https://api.example.com", List.of("read:data"), options);

VerificationRequestContext ctx = new VerificationRequestContext(
        "GET",
        "https://api.example.com/data",
        List.of(requestDpopProof));   // raw DPoP header values; List.of() when none

VerificationResult result = verifier.verify(accessToken, ctx).get();
if (result.hasDpopProof()) {
    // result.dpopProof().keyThumbprint(), .jti(), .htm(), .htu(), .iat(), .exp(), .raw()
}
```

`InboundDPoPOptions.defaults(replayStore)` sets a 300-second max proof age, 30-second clock skew, and algorithms `{RS256, ES256}`. Construct the record directly for custom values:

```java
new InboundDPoPOptions(replayStore, maxProofAgeSeconds, clockSkewSeconds, allowedProofAlgorithms)
```

Only the asymmetric algorithms `RS256` and `ES256` are accepted for `allowedProofAlgorithms`; an empty set or any other algorithm (`none`, `HS256`, …) is rejected at construction. Pass `null` to accept the defaults.

The `DPoPReplayStore` interface has a single implementation provided — `InMemoryDPoPReplayStore` — suitable for single-process deployments. Supply your own implementation (for example backed by Redis) for multi-node deployments.

#### DPoP enforcement modes

The verifier enforces one of three modes, selected by whether `inboundDPoP` is configured and its `required` flag. The mode drives both what the PRM advertises and how `verify(...)` treats each token shape:

| Mode | Configuration | PRM `dpop_bound_access_tokens_required` | Bearer-only token | DPoP-bound token | Bearer token + proof |
|---|---|---|---|---|---|
| **Required** | `inboundDPoP` set, `required = true` | `true` | reject (`DPoPBindingMismatchException`) | validate end-to-end | reject |
| **Supported** | `inboundDPoP` set, `required = false` (default) | `false` | accept | validate end-to-end | reject (`DPoPBindingMismatchException`) |
| **Not configured** | `inboundDPoP` is `null` | _absent_ | accept | reject (`DPoPNotSupportedException`) | reject (`DPoPNotSupportedException`) |

Passing any `InboundDPoPOptions` instance — even a default-constructed one — is the on/off switch for advertising DPoP in the PRM. To require DPoP-bound tokens, pass `options.withRequired(true)`:

```java
ResourceOptions options = ResourceOptions.builder()
        .inboundDPoP(InboundDPoPOptions.defaults(new InMemoryDPoPReplayStore()).withRequired(true))
        .build();
```

"Not configured" fails closed (RFC 9449 § 6): a resource that has not opted into DPoP rejects any DPoP signal rather than silently dropping sender-binding. Because such a resource does not support DPoP, the `WWW-Authenticate` challenge for `DPoPNotSupportedException` uses the `Bearer` scheme.

### Protected Resource Metadata (RFC 9728)

```java
Map<String, Object> prm = verifier.prmResponse();
// Serialize as JSON and serve at ProtectedResourceMetadata.wellKnownPath(URI.create(resourceUri)).
```

Well-known path derivation:

| Resource URI | Path |
|---|---|
| `https://api.example.com` | `/.well-known/oauth-protected-resource` |
| `https://api.example.com/mcp` | `/.well-known/oauth-protected-resource/mcp` |
| `https://api.example.com/v2/mcp` | `/.well-known/oauth-protected-resource/v2/mcp` |

#### Where the PRM document lives

The document can be hosted in either of two places, and the resource decides which one its challenges point at:

| Topology | Who serves the document | What the challenge advertises |
|---|---|---|
| Resource-hosted (default) | This server, at `prmPath()` | `prmUrl()` — the derived `<resource origin>/.well-known/oauth-protected-resource[/path]` |
| AS-hosted | The authorization server, which publishes one document per registered resource (authserver 0.2.0 and later serves `<issuer>/.well-known/oauth-protected-resource/{ref}`, `ref` being the RFC 9728 §3.1 path suffix of the resource URI, or its slug) | The URL configured via `ResourceOptions.builder().resourceMetadataUrl(...)` |

Use the second when the resource server cannot serve well-known paths — a platform that owns them, or a gateway that routes only the resource path. Nothing else changes: the SDK still derives `prmPath()`/`prmUrl()`, and `resourceMetadataUrl()` is what adapters put in the challenge.

Whichever you pick, RFC 9728 §3.3 binds the document to the identifier: the `resource` member the client reads must equal, byte for byte, the identifier it derived the metadata request from. The resource URI registered at the authorization server, the `resourceUri` configured here, and the URL clients actually call therefore all have to be the same string — a trailing slash, a different host, or an extra path segment makes it a different resource and the client discards the document.

```java
ResourceOptions options = ResourceOptions.builder()
        .resourceMetadataUrl("https://auth.example.com/.well-known/oauth-protected-resource/mcp")
        .build();
AuthplaneResource resource = client.resource("https://mcp.example.com/mcp", scopes, options);

resource.resourceMetadataUrl();  // the AS-hosted URL above — what challenges advertise
resource.prmUrl();               // still the derived https://mcp.example.com/.well-known/...
```

`ProtectedResourceMetadata.wellKnownUrl(String resourceUri)` returns the full URL. If the resource identifier carries a query component, the returned URL carries it verbatim (`https://api.example.com/mcp?tenant=a` → `https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a`) while routing stays path-keyed — the derivation table above is unaffected. The framework adapters (`authplane-mcp`, `authplane-spring`) register the servlet/router automatically — this is only needed when writing your own adapter.

### Dev mode

```java
AuthplaneClient client = AuthplaneClient.builder(issuer)
        .devMode(true)
        .build()
        .get();
```

Allows `http://`, `localhost`, and RFC 1918 ranges. Cloud metadata endpoints (`169.254.0.0/16`) and IPv6 link-local (`fe80::/10`) remain blocked. Set `AUTHPLANE_DEV_MODE=true` in the environment for the same effect.

## 9. Error handling

All SDK exceptions extend `AuthplaneException` (unchecked).

### Exception hierarchy

| Exception | HTTP status | Cause |
|---|---|---|
| `InsufficientScopeException` | 403 | Token is valid but lacks the required scope |
| `TokenMissingException` | 401 | Token is null or blank |
| `TokenExpiredException` | 401 | `exp` claim is in the past (beyond clock skew) |
| `InvalidClaimsException` | 401 | `iss` / `aud` / `typ` mismatch, invalid `nbf` / `iat`, disallowed algorithm |
| `InvalidSignatureException` | 401 | Signature verification failed or `kid` not found |
| `TokenRevokedException` | 401 | Revocation checker rejected the token |
| `DPoPException` (and subclasses) | 401 | DPoP proof missing, invalid, replayed, or binding mismatch |
| `JwksFetchException` | 503 | JWKS endpoint unreachable and no cached keys available |
| `MetadataFetchException` | 503 | Metadata endpoint unreachable or missing `jwks_uri` |
| `TokenExchangeException` | 500 | AS token / exchange / introspection / revocation call failed |
| `ConsentRequiredException` | 500 | Token exchange needs user consent (subtype of `TokenExchangeException`); carries an optional `consentUrl` to drive the consent flow |
| `AccessDeniedException` | 500 | AS returned `access_denied` (subtype of `TokenExchangeException`): the exchanging client is not allowlisted on the target Resource |
| `InvalidTargetException` | 500 | AS returned `invalid_target` (subtype of `TokenExchangeException`): `resource` does not match a granted resource exactly |

DPoP subclasses (all extend `DPoPException`):

| Exception | Cause |
|---|---|
| `DPoPProofMissingException` | Proof required but not supplied |
| `InvalidDPoPProofException` | Proof is malformed or fails validation |
| `DPoPBindingMismatchException` | Proof key doesn't match token `cnf.jkt` |
| `DPoPReplayDetectedException` | Proof `jti` was already used |
| `DPoPNotSupportedException` | A DPoP signal arrived at a resource that has not opted into DPoP (RFC 9449 §6); challenge uses the `Bearer` scheme |
| `MultipleDpopProofsException` | Request carried more than one `DPoP` header field (RFC 9449 §4.3 #1) |

### Mapping exceptions to HTTP responses

```java
import ai.authplane.sdk.core.errors.AuthplaneException;
import ai.authplane.sdk.core.errors.HttpStatus;
import ai.authplane.sdk.core.errors.WwwAuthenticate;

try {
    VerifiedClaims claims = verifier.verify(token).get().claims();
    claims.requireScope("write:data");
} catch (ExecutionException e) {
    if (e.getCause() instanceof AuthplaneException ae) {
        response.setStatus(HttpStatus.of(ae));
        response.setHeader("WWW-Authenticate", WwwAuthenticate.of(ae));
    }
}
```

`HttpStatus.of(AuthplaneException)` returns `401`, `403`, `500`, or `503` per the table above. `WwwAuthenticate.of(AuthplaneException)` produces an RFC 6750 header value using the `DPoP` scheme for DPoP errors and `Bearer` for everything else; `WwwAuthenticate.of(error, realm)` adds a realm; `WwwAuthenticate.of(error, ChallengeOptions)` additionally emits the `resource_metadata` (RFC 9728 §5.3) and `scope` (RFC 6750 §3) parameters. All parameter values are escaped for header safety.

**`error_description` is fixed, not the exception message.** The challenge and the JSON body are both served to a caller who by definition has not authenticated, so the description is chosen by the `error` code:

| `error` | `error_description` |
|---|---|
| `invalid_token` | `The access token is missing or not valid for this resource` |
| `insufficient_scope` | `The access token does not carry the scope this operation requires` |
| `invalid_dpop_proof` | `The DPoP proof is missing or not valid for this request` |
| anything else | `The request could not be authenticated` |

The SDK's own messages name the failing detail — the unknown `kid`, the claim that did not validate, the `typ` that was rejected — and an audience mismatch would hand the caller the exact `aud` the resource expects, which is the value they would need in order to request a token for it. RFC 6750 §3 does not require `error_description` to be diagnostic; the `error` code already carries what a conforming client acts on. The message stays on the exception, so log it server-side.

`WwwAuthenticate.of(error, options, true)` and `FailureResponse.of(error, options, true)` restore the message for local debugging — on both halves together, since an escape hatch that opened only one would let you believe the message was suppressed while it still shipped. They disclose SDK internals to unauthenticated callers; do not enable them in production.

### Fail-open vs fail-closed revocation

Default is fail-open: exceptions from the revocation checker are logged and the token is accepted. Opt in to fail-closed so checker failures become `TokenRevokedException`:

```java
ResourceOptions options = ResourceOptions.builder()
        .useBuiltinRevocationChecker()
        .failClosed()
        .build();
```

## 10. Lifecycle

`AuthplaneClient` implements `AutoCloseable`. Background JWKS and metadata refreshes use the configured `Executor` (the common `ForkJoinPool` by default — daemon threads). There are no scheduled timers or HTTP connection pools to shut down explicitly. Call `close()` on shutdown to clear the in-memory token cache. Once the client is no longer referenced, any in-flight refresh completes and the object graph becomes garbage-collectable.

`AuthplaneResource` holds no lifecycle state of its own — it reads through the parent client's caches. It does not need cleanup.
