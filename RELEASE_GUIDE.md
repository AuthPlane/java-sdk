# Release Guide

How to ship a new version of `ai.authplane.sdk:{authplane-sdk,authplane-mcp,authplane-spring}`. All three artifacts release together at the same version. See [`RELEASE_POLICY.md`](RELEASE_POLICY.md) for the policy this guide implements.

## Prerequisites

- You are a maintainer on `AuthPlane/java-sdk` with rights to dispatch the `cut-release` and `release` workflows.
- **Maven Central credentials** (`CENTRAL_USERNAME`, `CENTRAL_PASSWORD`) and **GPG signing material** (`GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`) are provisioned as repo secrets, scoped to the `maven-central` GitHub Environment with deployment limited to `v*.*.*` tag refs. (One-time setup; see *Troubleshooting → Maven Central credentials missing or rotated* if anything needs refreshing.)
- **Settings → Actions → General → Workflow permissions → "Allow GitHub Actions to create and approve pull requests"** is enabled on the repo. (Once-per-repo; required for the next-dev bump PR.)
- `CHANGELOG.md` on `main` has a populated `## [Unreleased]` section.

## Happy path: current-line release

For a normal forward-progress release off `main`.

### 1. Cut the release branch

Dispatch **Actions → Cut release branch** from `main`. Inputs:

- `releaseVersion`: target version, e.g. `1.3.0` (no `v` prefix, no `-SNAPSHOT` suffix).
- Leave `hotfixBase` empty.
- `nextDevVersion`: optional override; defaults to next patch `-SNAPSHOT` (e.g. releasing `1.3.0` → `main` bumps to `1.3.1-SNAPSHOT`).

The workflow:

- Branches off `main` as `release/v<X.Y.Z>` with the reactor POMs (parent + `core`, `mcp`, `spring`) at `<X.Y.Z>-SNAPSHOT`, and the `authplane.sdk.version` property in `mcp/demo` and `spring/demo` aligned to the same SNAPSHOT.
- Pushes a separate chore branch and opens a PR titled `chore: bump main to <next>-SNAPSHOT`. Attempts auto-merge.

### 2. Merge the next-dev bump PR

If auto-merge succeeded, nothing to do. Otherwise merge it manually. After merge, `main` reports `<next>-SNAPSHOT` across all reactor POMs and the demo POM properties.

### 3. Stabilize the release branch

On `release/v<X.Y.Z>`:

- Move content from `## [Unreleased]` in `CHANGELOG.md` into a new `## [<X.Y.Z>]` section.
- Land any last-minute fixes (checkstyle, doc updates, etc.).

> Why `-SNAPSHOT` during stabilization: a developer who runs `mvn install` from a release branch gets a clearly-snapshot artifact in their local Maven cache — Maven treats it as mutable and will re-fetch. If the branch carried the final `X.Y.Z` already, that artifact would be indistinguishable from the eventual Central-published version, and last-minute fixes wouldn't refresh anyone's local cache. `release.yml` strips the suffix and writes `X.Y.Z` in the same commit it tags.

### 4. (Optional) Dry-run the release workflow

Dispatch **Actions → Release** with `release/v<X.Y.Z>` selected and `dryRun: true`. Runs `mvn verify source:jar javadoc:jar` against the carried SNAPSHOT, strips `-SNAPSHOT`, commits, tags locally — but does **not** push the tag, create the Release, or trigger `publish-maven.yml`.

### 5. Dispatch the release workflow

Dispatch **Actions → Release** with `release/v<X.Y.Z>` selected and `dryRun: false`. The workflow:

- Reruns `mvn verify source:jar javadoc:jar` against the carried SNAPSHOT.
- Strips `-SNAPSHOT` from the reactor POMs and the demo `authplane.sdk.version` property, commits as `release: <X.Y.Z>`.
- Creates the annotated tag `v<X.Y.Z>`.
- **Atomic-pushes** the branch and tag.
- Creates the GitHub Release with notes extracted from `CHANGELOG.md`.
- Deletes `release/v<X.Y.Z>` on the remote.

The tag push triggers `publish-maven.yml`:

- Verifies the POM version matches the tag.
- Runs `mvn -P release verify` (signs the three artifacts with GPG, builds sources + javadoc jars).
- Runs `mvn -P release -DskipTests deploy` to upload via the Sonatype Central Portal plugin (`autoPublish=true`, `waitUntil=published`).

The `publish-maven.yml` job runs in the `maven-central` GitHub Environment, restricted to `v*.*.*` tag refs. This binds the Central credentials + GPG key to tags only — a maintainer dispatching `release.yml` from a branch can never accidentally deploy to Central. If the environment is additionally configured with **required reviewers**, a maintainer must approve the run before the deploy steps execute; keep that enabled regardless of the auth mechanism in use.

### 6. Confirm

- The three artifacts appear under <https://central.sonatype.com/search?q=g%3Aai.authplane.sdk+v%3A%3CX.Y.Z%3E> (allow a few minutes for index propagation).
- The GitHub Release page renders with `_Released commit: <sha>_` plus the CHANGELOG notes.
- Tag `v<X.Y.Z>` points at the release commit (`git ls-remote --tags origin 'v<X.Y.Z>^{}'`).

A consumer can now add:

```xml
<dependency>
  <groupId>ai.authplane.sdk</groupId>
  <artifactId>authplane-sdk</artifactId>
  <version><X.Y.Z></version>
</dependency>
```

## Happy path: older-line hotfix

For patches to an older minor line — e.g. shipping `0.5.2` after `1.0.0` is already out.

### 1. Cut the hotfix branch

Dispatch **Actions → Cut release branch** from `main`. Inputs:

- `releaseVersion`: target patch, e.g. `0.5.2`.
- `hotfixBase`: the existing tag to branch from, e.g. `v0.5.1`. Must be on the same minor line as `releaseVersion` and strictly older than `main`'s latest tag.
- `nextDevVersion`: ignored for hotfixes.

The workflow branches off the tag as `hotfix/v<X.Y.Z>`, sets the reactor + demo POMs to `<X.Y.Z>-SNAPSHOT`, and pushes. No next-dev bump PR — older lines do not advance the default branch.

### 2. Stabilize the hotfix branch

- Add a `## [<X.Y.Z>]` section to `CHANGELOG.md` on the hotfix branch (the workflow does not require `## [Unreleased]` for hotfix cuts because they branch off old tags).
- Land the fix (cherry-pick from `main` or commit directly).

### 3. Dispatch the release workflow

Same as steps 4–6 of the current-line flow, but with `hotfix/v<X.Y.Z>` selected. `release.yml` refuses if `(major, minor)` of the branch is not strictly older than `main`'s latest tag — current-line patches must use `release/v*`.

### 4. Backport if needed

After publish, if any commits on the hotfix branch should also reach `main`, dispatch **Actions → Backport fixes** with `fromBranch=v<X.Y.Z>` — the tag, because the hotfix branch is deleted by `release.yml` on success.

---

## Local verification (no publish)

To test the release profile builds, signs, and packages cleanly without uploading anything to Central:

```bash
mvn -B -P release verify
```

This requires a GPG key on your local machine. It produces signed JARs in each module's `target/` directory but does not deploy them.

## Troubleshooting

### Maven Central rejects the upload mid-deploy

Once Central accepts an upload, the GAV (`groupId:artifactId:version`) is permanently claimed. If `publish-maven.yml` failed *before* `mvn deploy` started uploading, just re-run the workflow. If it failed mid-deploy:

1. Sign in at <https://central.sonatype.com> → **Deployments** and find the staging deployment for this run.
2. If it shows **Failed** or **Validating** indefinitely, **Drop** it from the UI.
3. Delete the tag: `git push origin --delete v<X.Y.Z>`.
4. Delete the GitHub Release (the workflow already created it): `gh release delete v<X.Y.Z> --yes`.
5. Bump the patch (e.g. `<X.Y.Z+1>`) and re-cut the release. **Do not** try to re-publish the same version — even if Central dropped the staging deployment, the namespace coordination may still consider it claimed.

If the staging deployment shows **Published**, the version is live; finishing any half-completed steps (GitHub Release, branch delete) is the recovery path, not a re-publish.

### Next-dev bump PR fails to open

If **Cut release branch** logs `GitHub Actions is not permitted to create or approve pull requests` at the *Open PR with default-branch bump* step, the repo setting is missing. Enable:

**Settings → Actions → General → Workflow permissions → "Allow GitHub Actions to create and approve pull requests"**

The chore branch with the version bump was already pushed by the previous step. Open the PR by hand against `main` from that branch, then continue from step 3 of the happy path.

### Source branch delete failed

`release.yml` deletes `release/v*` / `hotfix/v*` on success. If the branch ruleset doesn't allow the bot to delete, the workflow logs a warning but does not fail. Run:

```bash
git push origin --delete release/v<X.Y.Z>
```

### Tag push blocked by branch/tag ruleset

If a ruleset prevents `release.yml` from pushing `v<X.Y.Z>` (the bot can't create tags matching `v*`), fall back to a fully manual release from a maintainer's machine.

```bash
# Fresh clone keeps the release commit identity local to this release.
git clone git@github.com:AuthPlane/java-sdk.git /tmp/java-sdk-release-v<X.Y.Z>
cd /tmp/java-sdk-release-v<X.Y.Z>
git checkout release/v<X.Y.Z>

# Maintainer identity — use YOUR AuthPlane identity, not a personal one.
git config user.name "<your-github-username>"
git config user.email "<your-authplane-email>"

# Strip -SNAPSHOT to the final release version (reactor + demo POMs).
mvn -B -ntp versions:set -DnewVersion=<X.Y.Z> -DprocessAllModules -DgenerateBackupPoms=false
for demo in mcp/demo spring/demo; do
  (cd "$demo" && mvn -B -ntp versions:set-property \
    -Dproperty=authplane.sdk.version -DnewVersion=<X.Y.Z> -DgenerateBackupPoms=false)
done

git add -A
git commit -m "release: <X.Y.Z>"
git tag -a v<X.Y.Z> -m "Release v<X.Y.Z>"
git push --atomic origin release/v<X.Y.Z> v<X.Y.Z>
```

`publish-maven.yml` triggers on the tag push and deploys as usual.

After publish completes:

```bash
sha="$(git rev-parse HEAD)"
{ echo "_Released commit: \`$sha\`_"; echo;
  awk '/^## \[<X.Y.Z>\]/{f=1;next} /^## \[/{f=0} f' CHANGELOG.md;
} > /tmp/notes-<X.Y.Z>.md

gh release create v<X.Y.Z> --title v<X.Y.Z> --notes-file /tmp/notes-<X.Y.Z>.md
git push origin --delete release/v<X.Y.Z>
rm -rf /tmp/java-sdk-release-v<X.Y.Z>
```

Then merge (or open by hand) the next-dev bump PR if it's still outstanding. Confirm via step 6 of the happy path.

### `release.yml` fails on POM-version mismatch

The release branch was hand-edited and the POM version stem no longer matches the branch name. On the branch:

```bash
mvn -B versions:set -DnewVersion=<X.Y.Z>-SNAPSHOT -DprocessAllModules -DgenerateBackupPoms=false
git add -A && git commit -m "chore: realign POM version to <X.Y.Z>-SNAPSHOT"
git push
```

Re-dispatch `release.yml`.

### `release.yml` fails on CHANGELOG check

Add `## [<X.Y.Z>] — YYYY-MM-DD` heading to `CHANGELOG.md` on the release branch and re-dispatch.

### GPG signing failed during `publish-maven.yml`

`gpg: signing failed: No secret key` — the `GPG_PRIVATE_KEY` secret is missing the BEGIN/END armor lines, the passphrase is wrong, or the key was rotated. Re-export with `gpg --armor --export-secret-keys YOUR_KEY_ID` and update both `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE`. The tag is still valid — re-run `publish-maven.yml` once the secrets are fixed.

### Central rejects the signature

`Invalid signature for...` — the public key isn't on a keyserver, or the email on the key wasn't verified at `keys.openpgp.org`. Re-publish the key:

```bash
gpg --keyserver keys.openpgp.org --send-keys YOUR_KEY_ID
gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID
```

Verify the email via the link `keys.openpgp.org` sends, then re-run `publish-maven.yml`.

### Maven Central credentials missing or rotated

`Failed to deploy artifacts: ... 401 Unauthorized` — regenerate the user token at <https://central.sonatype.com> → avatar → **View Account** → **Generate User Token**, then update `CENTRAL_USERNAME` and `CENTRAL_PASSWORD` in repo secrets. The token is long-lived but tied to the account that created it — rotate when that account changes.
