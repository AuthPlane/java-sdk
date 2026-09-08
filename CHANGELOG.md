# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `JwksCache` and `MetadataCache` gained public constructors taking a `java.time.Clock`, so the
  refresh intervals can be driven from an injected time source rather than the wall clock. Additive;
  the existing constructors are unchanged and delegate with `Clock.systemUTC()`.
- `DocumentCache.forceRefreshIgnoringFailureBackoff()` — public, and the only way to force a
  fetch while a failed refresh is backing off. It exists for a caller that is asking a question
  and wants the attempt made rather than the cached answer, and is prepared to wait for a
  timeout: an administrative refresh, or a test. It is named rather than a boolean on
  `forceRefresh` so no request path reaches it by flipping an argument, and no request path
  should.

### Fixed

- A server cache directive that is not in the future no longer makes the document permanently
  expired. `Cache-Control: no-store` and `no-cache` parse to an expiry of `0`, `max-age=0` to the
  current second, and a stale `Expires:` to a past one; the effective TTL was computed by
  subtracting the cache timestamp from that, so any of them produced a *negative* TTL — about
  -1.7e9 for `no-store`. A negative TTL is expired on every read, so every read took the
  synchronous re-fetch branch on the caller's thread, and the failure backoff could not help
  because it only arms when a fetch throws: an endpoint answering `no-store` successfully cleared
  the backoff and re-armed the expiry on the same call. Such an expiry is now treated as no
  preference and the configured interval governs. This was latent while nothing on a verification
  path read the metadata cache; the change above puts it there, before signature verification, so
  an unauthenticated caller would otherwise have set the fetch rate against the authorization
  server.

- Authorization server metadata is now re-read under ordinary verification traffic, so
  `metadataRefreshSeconds` takes effect on a resource server that only verifies tokens. Such a
  server never calls the token, introspection or revocation endpoints, so nothing on its request
  path touched the metadata document after start-up: the SDK kept the copy fetched at build time
  indefinitely and never followed a rotated `jwks_uri`. Verification now reads through the metadata
  cache before each key lookup; once the configured interval has elapsed the document is re-fetched
  and a rotated `jwks_uri` rebinds JWKS fetching before the lookup runs.
- A metadata document is validated when it is fetched rather than when it is read, so a refresh
  returning an invalid document (wrong issuer, non-HTTPS endpoint, missing `jwks_uri`) no longer
  displaces the good one and cannot repoint key retrieval. The last valid document keeps being
  served. `jwks_uri` is now part of that validation rather than being checked at read time. RFC 8414
  §2 marks it OPTIONAL — REQUIRED is OpenID Connect Discovery, a different document — but this SDK
  requires it regardless: every verification path builds a JWT validator, and introspection is
  layered on top of that rather than offered instead of it. It is also the field the refresh
  mechanism itself runs on — a document without it left nothing to reconcile the JWKS binding
  against, so a later rotation would not be followed even after the authorization server fixed its
  document. A document lacking it already failed at `AuthplaneClient` build time; what changes is
  that a *refresh* returning one is now rejected and backed off like any other failed refresh,
  instead of being published and then raising on every read.
- A failed `jwks_uri` rebind is retried instead of stranding key retrieval on the withdrawn URI.
  The rebind used to be driven by the metadata document *changing*, and the document is published to
  the cache before anything acts on the change — so one transient failure at the new endpoint left
  JWKS fetching pinned to a URI the authorization server had already withdrawn, with nothing left to
  re-trigger it: every later refresh returned that same document, so the change never fired again. A
  single 503 at the wrong moment meant every token failed to verify until the process restarted. The
  binding is now reconciled against the document on each key lookup, so a rebind that fails simply
  retries on the next one.
- A failed document refresh no longer costs a network round trip on every subsequent lookup. The
  cache timestamp advances only on success, so against an unreachable endpoint the document stayed
  permanently expired and each read took the synchronous re-fetch branch — a full HTTP timeout per
  verification once metadata moved onto the verification path, serialized behind the cache's fetch
  lock. A failed refresh now backs off for up to 30 seconds (never longer than the configured
  refresh interval), and a read that finds a refresh already in flight serves the document it holds
  rather than waiting for it. The same backoff governs a failed `jwks_uri` rebind: the binding is
  reconciled against the metadata document on every key lookup, so a rotated `jwks_uri` that is
  down would otherwise cost a JWKS fetch per verification — the rebind builds a fresh cache per
  attempt, which has no backoff of its own to inherit. Tokens whose keys are already cached keep
  verifying throughout, and the rebind is still retried until it succeeds, on the backoff instead
  of on every lookup. The backoff also governs the forced refresh a `kid` miss triggers, which is
  the path a rotation puts every token on once the keys in hand are the new ones: without it each
  such verification paid a full fetch against a failing endpoint, and an unauthenticated caller
  presenting unknown `kid` values set that rate.
- `elideSecrets` no longer ships the userinfo of a scheme-relative identifier whose path or query
  contains a later `://`, such as `//svc:pw@api.example.com/mcp?next=https://x`, in a message that
  claims to have elided it — the authority is now located by testing the leading `//` first.

### Changed

- `CacheHeaderParser.parseExpiresAt` returns `null` for `Cache-Control: no-store` and `no-cache`
  instead of `0`. Those directives say the response should not be reused, which for a document
  this SDK has to keep serving is not an expiry it can honour — so the honest answer is "no usable
  preference", and the caller falls back to its configured interval. The `0` was read as an
  absolute expiry at the epoch, which is what made the document permanently stale; once the cache
  started discarding a non-future expiry the sentinel became indistinguishable from `null` while
  the javadoc still claimed it meant "immediately expired". Both sibling SDKs already model this as
  absent rather than as zero. A caller reading the return value directly should treat `null` as
  "use your own interval"; nothing else in this SDK distinguished the two values.

- `DocumentCache.forceRefresh()` now respects the failure backoff instead of fetching
  unconditionally, and returns the currently held document when a refresh is backing off or
  already in flight. This is a public method, inherited by the public `JwksCache` and
  `MetadataCache`, so an embedder calling it during a backoff window now gets a cached document
  back — and the return type cannot say which happened. It changed because the SDK's own
  request path reaches it: `JwksCache.getKeyByKid(kid, true)` is called on every `kid` the
  cached document does not hold, which is the state a rotation to an unreachable `jwks_uri`
  leaves behind, and fetching unconditionally there cost a full HTTP timeout per verification.
  Use `forceRefreshIgnoringFailureBackoff()` if you need the old unconditional behaviour.

- A resource identifier carrying userinfo (`https://svc:pw@api.example.com/mcp`) is now rejected at
  construction by the new `ProtectedResourceMetadata.requireNoUserinfo(String)` gate, called from
  `AuthplaneClient.resource(...)`, the `AuthplaneResource` constructor and
  `ProtectedResourceMetadata.Builder#build()`, because the identifier is published verbatim to
  unauthenticated callers (RFC 9110 §4.2.4, RFC 3986 §3.2.1); a host with a port and an opaque
  identifier such as `urn:example:api` are unaffected.

  **Migration:** If `authplane.resource` (or the `resourceUri` passed to
  `AuthplaneClient.resource(...)`) carries userinfo, remove it — otherwise the resource, and a
  Spring context that builds one, now fails at startup. Present the credential in the
  `Authorization` header instead.

- A resource identifier without a scheme is now rejected at construction —
  `AuthplaneClient.resource(...)`, the `AuthplaneResource` constructor, and
  `ProtectedResourceMetadata.Builder#build()` all call the new
  `ProtectedResourceMetadata.requireScheme(String)` gate. As shipped in 0.1.0 the SDK refused such an identifier at
  derivation, which covered the PRM URL but not the other sink that splices the scheme: the DPoP
  `htu` binding target read `null://api.example.com/mcp`, so every DPoP-bound request against a
  scheme-relative identifier failed. Rejecting at construction closes both. The derivation-time gate
  stays as a backstop and now names the requirement the identifier actually fails (no scheme, no
  authority, or opaque) instead of listing all of them. RFC 8707 §2 requires an absolute URI, which
  RFC 3986 §4.3 defines as always carrying a scheme, so an identifier that names a resource by
  scheme is not turned away. Note the gate is scheme-only: an opaque identifier such as
  `urn:example:api` still constructs here and fails later if a PRM URL is derived from it.
  Whether construction is the right place to refuse an identifier with no host is a separate
  question, not settled by this change, and tracked in #31.

  **Migration:** A scheme-relative or relative resource identifier now fails at startup instead of
  at the first 401. Prefix the intended scheme. `wellKnownUrl` enforces the same four gates (in a
  different order, so the component named in the message can differ from a constructor's) as the
  constructors, so a caller reaching it directly with a string no constructor saw is refused there
  too rather than splicing a malformed identifier into a challenge.

- The derived Protected Resource Metadata URL now preserves the resource identifier's query
  component. RFC 9728 §3 forms the well-known URI by inserting the well-known string "between the
  host component and the path and/or query components, if any", and §3.1 removes the terminating
  slash following the host when a path or query is present:
  `https://api.example.com/mcp?tenant=a` →
  `https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a`, and both
  `https://api.example.com?x=1` and `https://api.example.com/?x=1` →
  `https://api.example.com/.well-known/oauth-protected-resource?x=1`. A query component is legal
  in a resource indicator — RFC 8707 §2 states the SHOULD NOT and its exception in the same
  sentence, and RFC 9728 §1.2 carries it forward. The raw (percent-encoded) query is preserved
  verbatim, as the raw authority already was in 0.1.0. An empty query (a bare trailing `?`) is
  treated as absent and derives the query-less URL. An identifier without a query derives exactly
  the same URL as in 0.1.0.

  A query component is also now validated at construction, against the RFC 3986 §3.4 grammar
  (`query = *( pchar / "/" / "?" )`), by the same four boundaries that reject a fragment. The query
  is spliced verbatim into the `resource_metadata` parameter of the `WWW-Authenticate` challenge,
  and `WwwAuthenticate.escapeQuotedString` strips only control characters, `\` and `"` — so a raw
  non-ASCII octet shipped into a header field that RFC 9110 §5.5 confines to US-ASCII, and a
  character `java.net.URI` rejects (a space, `"`, `\`, `|`, `^`, `{`, `}`, `<`, `>`, a malformed
  percent-escape) passed construction and then threw out of the 401 response path — a 500 in place
  of the challenge. Nothing is escaped on the operator's behalf: rewriting the query would change
  the resource's identity. Neither the authority nor the path is gated — both were always part of
  the derived URL and are unchanged here — and closing them is tracked in #29.

  The DPoP `htu` derived by `AuthplaneResource.normalizeRequestUrl` now reads the raw authority
  too. Previously a percent-encoded userinfo was decoded into it, so the server computed
  `https://u@b@host` where the client proved `https://u%40b@host` and the proof never matched. The
  matching correction to the PRM URL shipped in 0.1.0; this is the same defect on the DPoP path.

  **Migration:** If your resource identifier contains a query component, the PRM document URL
  advertised in `WWW-Authenticate: … resource_metadata=` now includes that query. Update any
  hard-coded expectation of the old query-less URL. Your existing PRM route continues to serve the
  document — routing is unchanged. Serving distinct documents per query value is not supported.
  If that query falls outside the RFC 3986 §3.4 grammar, the resource — and a Spring context that
  builds one — now fails at startup rather than at the first 401. The realistic case is unescaped
  brackets, `?filter[a]=b`, which `java.net.URI`, browsers and servlet containers all accept;
  percent-encode the offending octets (`?filter%5Ba%5D=b`) to keep the identifier.

- A resource identifier carrying a URI fragment is now rejected at construction
  (`AuthplaneClient.resource(...)`, the `AuthplaneResource` constructor and
  `ProtectedResourceMetadata.builder()`), with `IllegalArgumentException`. RFC 8707 §2 states the
  resource URI "MUST NOT include a fragment component", and RFC 9728 §1.2 defines the resource
  identifier as a URL with no fragment. Previously the fragment was dropped when deriving the
  `.well-known` URL but published verbatim in the document's `resource` field, so the served
  document named an identifier its own URL disagreed with — which RFC 9728 §3.3 requires a
  conformant client to discard, with no error raised on the server. Deriving a PRM path or URL
  from a fragment-bearing identifier is refused as well, and refused before the identifier is
  checked for derivability, so an identifier that is both fragment-bearing and non-derivable is
  reported for the fragment — which is also what keeps the fragment out of the message.

  The `resource` form parameter that `ClientCredentialsGrant` and `TokenExchange` send to the
  authorization server is *not* gated: that parameter carries whatever string the caller passes to
  the grant, not the configured resource identifier, and it is the RFC 8707 §2 indicator in its
  primary role. Closing it is tracked in #30.

  **Migration:** If `authplane.resource` (or the `resourceUri` passed to
  `AuthplaneClient.resource(...)`) contains a `#`, remove the fragment — otherwise the resource,
  and a Spring context that builds one, now fails at startup. Only an unescaped `#` is a fragment
  delimiter; a percent-encoded `%23` inside the path is unaffected. Resource identifiers without a
  fragment are unchanged, as is the handling of opaque identifiers such as `urn:example:api`.

## [0.1.0] - 2026-09-07

- Initial release.
