# Conformance Tests

RFC conformance tests for `Authplane Java SDK`. Each test method maps to a case in the shared
[Authplane Conformance Catalog](https://github.com/AuthPlane/conformance),
enabling cross-SDK comparison.

Broader guides and links to other language SDKs: [AuthPlane on GitHub](https://github.com/AuthPlane).

## Prerequisites

The harness finds `oauth-sdk-conformance-catalog.yaml` automatically in this order:

1. `CONFORMANCE_CATALOG_PATH` (absolute path to the file), when set
2. `../conformance/` (clone the catalog repo under this directory name)
3. `../conformance/` (same repo, default clone folder name)
4. `./conformance/` or `./conformance/` under the SDK root (nested checkout, e.g. CI)

Clone the catalog next to the SDK (recommended for local work):

```bash
# From the parent directory of java-sdk/
git clone git@github.com:AuthPlane/conformance.git conformance
# Check out the same ref CI pins, so local runs match CI:
git -C conformance checkout "$(cat java-sdk/.conformance-catalog-ref)"
```

CI pins the catalog to the SHA in `java-sdk/.conformance-catalog-ref` — a single
source of truth read by `ci.yml` and `release.yml`. Bump that file (together with
the SDK-side coverage for any new cases) to adopt a newer catalog; the weekly
`conformance-catalog-drift.yml` job fails when the latest catalog drifts ahead of
the pinned ref. It runs only on a schedule, so it never blocks PR CI.

Expected layout:

```
parent/
├── java-sdk/       ← this repo (contains core/, mcp/, spring/)
└── conformance/    ← catalog repo
    └── oauth-sdk-conformance-catalog.yaml
```

Alternatively, point the harness at any path using the `CONFORMANCE_CATALOG_PATH` environment variable:

```bash
export CONFORMANCE_CATALOG_PATH=/path/to/oauth-sdk-conformance-catalog.yaml
mvn test
```

## Running

Conformance tests are compiled and executed as part of the normal test suite — no separate profile or command needed:

```bash
# From java-sdk/core/
mvn test
```

After the run, two reports are written to the project root:

| File | Format | Use |
|------|--------|-----|
| `conformance-report.md` | Markdown | Human review, PR diffs |
| `conformance-report.json` | JSON | Tooling, dashboards |

Run a single RFC class:

```bash
mvn test -Dtest=Rfc9068ConformanceTest
```

Run a single test method:

```bash
mvn test -Dtest=Rfc9068ConformanceTest#rfc9068_valid_at_jwt_must_verify
```

## Test classes

| Class | RFC | Topic |
|-------|-----|-------|
| `Rfc6749ConformanceTest` | RFC 6749 | Client credentials, HTTP Basic auth, token response |
| `Rfc7009ConformanceTest` | RFC 7009 | Token revocation |
| `Rfc7662ConformanceTest` | RFC 7662 | Token introspection |
| `Rfc8414ConformanceTest` | RFC 8414 | Authorization server metadata discovery |
| `Rfc8693ConformanceTest` | RFC 8693 | Token exchange |
| `Rfc8707ConformanceTest` | RFC 8707 | Resource indicators |
| `Rfc8725ConformanceTest` | RFC 8725 | JWT best practices |
| `Rfc9068ConformanceTest` | RFC 9068 | JWT access token profile |
| `Rfc9110ConformanceTest` | RFC 9110 | HTTP semantics (case-insensitive headers) |
| `Rfc9449ConformanceTest` | RFC 9449 | DPoP proof-of-possession |
| `Rfc9728ConformanceTest` | RFC 9728 | Protected resource metadata |
| `AuthplaneConformanceTest` | — | Authplane-specific fields (`agentId`, `agentChain`, `nbf`) on `VerifiedClaims` |

## Annotations

### `@ConformanceCase`

Maps a test method to a catalog case ID:

```java
@Test
@ConformanceCase("rfc9068-valid-at-jwt-must-verify")
void rfc9068_valid_at_jwt_must_verify() { ... }
```

A test without `@ConformanceCase` still runs and is counted in the suite, but appears as an uncatalogued test in the report.

### `@ConformanceCoverage`

Optional — documents partial coverage when a single test cannot fully exercise a catalog case:

```java
@Test
@ConformanceCase("rfc9449-dpop-proof-nonce-retry")
@ConformanceCoverage(
    level = ConformanceCoverageLevel.PARTIAL,
    gaps = {"server-provided nonce not exercised end-to-end"},
    note = "Integration test required for full coverage"
)
void rfc9449_dpop_proof_nonce_retry() { ... }
```

## Adding a new conformance test

1. Find the case ID in `oauth-sdk-conformance-catalog.yaml`.
2. Add a test method to the appropriate `RfcXxxxConformanceTest` class (or create a new class if the RFC has no class yet).
3. Annotate with `@ConformanceCase("the-case-id")`.
4. Add `@ConformanceCoverage(level = PARTIAL, gaps = {...})` if the test does not fully cover the case.
5. Run `mvn test` and verify the case moves from `not_run` to `passed` in `conformance-report.md`.

New RFC classes must be annotated with `@ConformanceSuite` and `@ExtendWith(ConformanceExtension.class)`:

```java
@ConformanceSuite
@ExtendWith(ConformanceExtension.class)
class RfcXxxxConformanceTest {
    ...
}
```

## Known gaps

There are **no `not_run` cases** — every catalog case has a test implementation, and all
implemented cases are `passed` in `conformance-report.md`.

Two cases carry **partial** coverage rather than full:

| Case ID | RFC | Coverage | Reason |
|---------|-----|----------|--------|
| `rfc9449-dpop-inbound-nonce-must-be-validated-when-required` | RFC 9449 §8 | partial (`@Disabled`) | Server-issued inbound nonce enforcement is not yet implemented. RFC 9449 §8 allows but does not require resource servers to enforce nonces. Documented via `@ConformanceCoverage` on the test. |
| `rfc9449-dpop-proof-jwk-must-not-include-private-key-material` | RFC 9449 §4.2 | partial (passed) | The proof is rejected as `invalid_dpop_proof`, but the Java SDK does not surface a stable private-key-material diagnostic independent of Nimbus's parsing error. Documented via `@ConformanceCoverage` on the test. |

## Definition of done for a conformance case

- Status is `passed` in `conformance-report.md`
- Coverage level is `full`, or `partial` with all gaps documented in `@ConformanceCoverage`
- No uncatalogued tests (every test method has a `@ConformanceCase` mapping)
