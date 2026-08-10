# Contributing to the Authplane Java SDK

Thanks for your interest in contributing. This repository is a Maven multi-module project publishing three artifacts to Maven Central:

| Maven coordinate | Directory |
|---|---|
| `ai.authplane.sdk:authplane-parent` (aggregator BOM) | `./` |
| `ai.authplane.sdk:authplane-sdk` | `core/` |
| `ai.authplane.sdk:authplane-mcp` | `mcp/` |
| `ai.authplane.sdk:authplane-spring` | `spring/` |

Adapters (`authplane-mcp`, `authplane-spring`) depend on `authplane-sdk`. A single tagged release publishes all three artifacts at the same version.

## Reporting Issues

- **Bugs:** open a [bug report](https://github.com/AuthPlane/java-sdk/issues/new?template=bug-report.md). Include artifact, version, JDK version, and a minimal reproduction.
- **MCP compatibility:** use the [MCP Compatibility Report](https://github.com/AuthPlane/java-sdk/issues/new?template=mcp-compatibility.md) template.
- **Feature requests:** open a [feature request](https://github.com/AuthPlane/java-sdk/issues/new?template=feature-request.md). Describe the problem, then the proposed solution.
- **Security vulnerabilities:** do **not** open a public issue. See [SECURITY.md](SECURITY.md).

## Development Setup

### Prerequisites

- JDK 21 (Temurin or equivalent)
- Maven 3.9+
- `git`

### Clone and build

```bash
git clone https://github.com/AuthPlane/java-sdk.git
cd java-sdk
mvn -B verify
```

One Maven reactor pass covers all three modules.

### Conformance catalog

The RFC conformance tests load the shared [Authplane Conformance Catalog](https://github.com/AuthPlane/conformance), which lives in its own repo (not vendored here). `mvn -B verify` fails with `Conformance catalog not found` until it can locate the catalog. Provide it one of two ways:

```bash
# Option A — clone the catalog as a sibling of java-sdk/ (resolved automatically):
#   parent/
#   ├── java-sdk/      ← this repo
#   └── conformance/   ← catalog repo
git clone https://github.com/AuthPlane/conformance.git ../conformance
# Check out the same ref CI pins, so local runs match CI:
git -C ../conformance checkout "$(cat .conformance-catalog-ref)"

# Option B — clone it anywhere and point CONFORMANCE_CATALOG_PATH at the file:
export CONFORMANCE_CATALOG_PATH=/path/to/conformance/oauth-sdk-conformance-catalog.yaml
```

CI pins the catalog to the SHA in [`.conformance-catalog-ref`](.conformance-catalog-ref) (a single source of truth read by `ci.yml` and `release.yml`); a weekly `conformance-catalog-drift.yml` job fails when the latest catalog adds cases the SDK does not yet cover (it runs only on a schedule, so it never blocks PRs). Bumping the pinned ref must accompany the matching SDK-side coverage. See [`core/src/conformance/README.md`](core/src/conformance/README.md) for details.

## Local Verification

**Full verify (compile + tests + checkstyle):**

```bash
mvn -B verify -Dbuildhelper.addtestsource.skip=true -Dmaven.javadoc.failOnError=false
```

**Source and Javadoc jars (confirm what Central will receive):**

```bash
mvn -B source:jar javadoc:jar -Dmaven.javadoc.failOnError=false
```

**Vulnerability scan (OWASP dependency-check):**

```bash
mvn -B org.owasp:dependency-check-maven:check
```

First run downloads the CVE database and is slow (~5–10 minutes); subsequent runs are faster.

**Run a single module's tests:**

```bash
mvn -B -pl core   -am test
mvn -B -pl mcp    -am test
mvn -B -pl spring -am test
```

## Pull Request Guidelines

- Branch off `main`. Release branches (`release/v*`, `hotfix/v*`) are managed by the release flow — see [RELEASE_POLICY.md](RELEASE_POLICY.md) and [RELEASE_GUIDE.md](RELEASE_GUIDE.md).
- PR titles follow [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `ci:`, `deps:`, `refactor:`, `test:`, `chore:`.
- Link the related GitHub issue (or other tracking reference) in the PR description.
- Fill out the PR template (summary, testing, checklist).
- Keep PRs focused.

## Changelog

User-facing changes go in [`CHANGELOG.md`](CHANGELOG.md) under the `[Unreleased]` heading. Follow the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format. Release tooling moves entries from `[Unreleased]` to the release version on tag.

## GitHub Actions — SHA-pinning

All workflow actions must be SHA-pinned with a version comment:

```yaml
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

When editing or adding a workflow, run [`pinact`](https://github.com/suzuki-shunsuke/pinact) to pin any new `uses:` lines before committing:

```bash
pinact run
```

Dependabot opens weekly PRs to bump the SHAs (see [`.github/dependabot.yml`](.github/dependabot.yml)).

## Release Process

Releases follow a single-branch flow: `main` is the only long-lived branch, short-lived `release/v*` (or `hotfix/v*`) branches stabilize each release and are deleted post-tag. The detailed procedure lives in [RELEASE_POLICY.md](RELEASE_POLICY.md) and [RELEASE_GUIDE.md](RELEASE_GUIDE.md). As a contributor you don't need to trigger releases — maintainers handle them. Publishing happens to Maven Central via the Sonatype Central Portal; the publish workflow (`publish-maven.yml`) fires on `v*.*.*` tag push and signs artifacts with the org GPG key.

## Code of Conduct

Be kind. Disagree on substance, not people. Projects that aren't kind don't last.
