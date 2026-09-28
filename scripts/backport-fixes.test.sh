#!/usr/bin/env bash
set -euo pipefail

# Tests for backport-fixes.sh --from/--to ref resolution.
#
# The script had no test, and the failure it hid is not one a reader would
# guess: resolution used to run a fetch per candidate refspec with
# `2>/dev/null || true` and then look at what landed locally, so "the fetch
# failed" and "origin has no such ref" arrived as the same answer. Any other
# fetch failure — an unreachable remote, a refused auth, a ref that cannot be
# written locally — was reported as a missing ref, sending the operator after a
# ref that is present and current.
#
# Each case builds a throwaway origin + clone in a temp dir, so nothing here
# touches the real repository or the network.
#
# Run: scripts/backport-fixes.test.sh

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/backport-fixes.sh"
failures=0

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n     %s\n' "$1" "$2"; failures=$((failures + 1)); }

# Builds: origin with `main`, a v1.0.0 tag, and one commit after the tag that is
# only reachable from the tag's branch — the shape of a fix landed on a release
# branch at step 3 of the release flow.
make_fixture() {
  local root="$1"
  # -b main explicitly: the default branch name comes from init.defaultBranch,
  # which differs between a developer machine and a CI runner. Without it the
  # fixture builds `master` somewhere and every checkout of `main` fails.
  git init -q -b main "$root/origin"
  git -C "$root/origin" config user.email t@example.com
  git -C "$root/origin" config user.name "Test"
  echo base > "$root/origin/f.txt"
  git -C "$root/origin" add -A
  git -C "$root/origin" commit -qm "base"

  # Clone before the tag exists. A clone made afterwards fetches every tag,
  # which leaves refs/tags/v1.0.0 populated locally and hides whether the
  # script's own fetch materialises it. The real scenario is a maintainer who
  # last fetched before the release.
  git clone -q "$root/origin" "$root/clone"

  git -C "$root/origin" checkout -q -b release/v1.0.0
  echo fix > "$root/origin/f.txt"
  git -C "$root/origin" commit -qam "fix: something landed on the release branch"
  # Annotated, matching release.yml's `git tag -a`. A lightweight tag resolves
  # the same way here, but the fixture should produce what the flow it models
  # produces.
  git -C "$root/origin" tag -a v1.0.0 -m "v1.0.0"
  git -C "$root/origin" checkout -q main
  git -C "$root/clone" config user.email t@example.com
  git -C "$root/clone" config user.name "Test"
}

# --- a branch as --from keeps working -----------------------------------------
t_branch() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>&1)"; then
    if git -C "$root/clone" log --oneline main..HEAD | grep -q "landed on the release branch"; then
      pass "a branch as --from cherry-picks its commits"
    else
      fail "a branch as --from cherry-picks its commits" "branch created but the commit is missing"
    fi
  else
    fail "a branch as --from cherry-picks its commits" "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- a tag as --from ----------------------------------------------------------
# After a release, release.yml has deleted release/vX.Y.Z, so the tag is the
# only ref naming those commits — the form the release guide and
# backport-fixes.yml both tell you to pass, and therefore the form least likely
# to be exercised before it is needed.
t_tag() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from v1.0.0 --to main 2>&1)"; then
    if git -C "$root/clone" log --oneline main..HEAD | grep -q "landed on the release branch"; then
      pass "a tag as --from cherry-picks its commits"
    else
      fail "a tag as --from cherry-picks its commits" "branch created but the commit is missing"
    fi
  else
    fail "a tag as --from cherry-picks its commits" "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- an unknown ref fails, and leaves nothing behind ---------------------------
# It fails at the resolver, which is what the assertion below pins: `git
# ls-remote --exit-code` exits 2 for a name the remote does not have, both arms
# of fetch_source_ref return non-zero, and the script prints its own message.
# What matters is the contract: non-zero, and no branch created.
t_unknown() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from does-not-exist --to main 2>&1)"; then
    fail "an unknown --from fails at the resolver, creating no branch" "script exited zero"
  elif [[ -n "$(git -C "$root/clone" branch --list 'backport/*')" ]]; then
    fail "an unknown --from fails at the resolver, creating no branch" \
      "it created a backport branch anyway"
  elif ! grep -q "not found on origin as a branch or a tag" <<<"$out"; then
    fail "an unknown --from fails at the resolver, creating no branch" \
      "reached the fetch, not the resolver: ${out##*$'\n'}"
  else
    pass "an unknown --from fails at the resolver, creating no branch"
  fi
}

# --- a glob is not a ref name --------------------------------------------------
# `git ls-remote` matches its argument as a glob and `*` is legal in a refspec,
# so an unvalidated `--from 'release/*'` answered "the ref is there", fetched
# wildcard-expanded, and handed `git cherry` a pattern instead of a commit. The
# `|| true` on that turned `fatal: unknown commit` into an empty candidate list
# and the run reported "Nothing to backport." at exit 0 — a tooling failure
# delivered as a fact about the refs, the class this suite exists for.
#
# Asserts the absence of the script's own wrong claim rather than the presence
# of any particular message, plus the two side effects that make it worse than
# a bad exit code: no backport branch, and no write to the local ref store. The
# second one is the reason this is caught in argument validation and not after
# the fetch — a rejected argument must not leave the repository changed.
t_glob_from() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from 'release/*' --to main 2>&1)"; then
    fail "a glob as --from is rejected, fetching nothing" "script exited zero"
  elif grep -q "Nothing to backport" <<<"$out"; then
    fail "a glob as --from is rejected, fetching nothing" \
      "the failure was reported as an empty backport"
  elif [[ -n "$(git -C "$root/clone" branch --list 'backport/*')" ]]; then
    fail "a glob as --from is rejected, fetching nothing" "it created a backport branch anyway"
  elif git -C "$root/clone" show-ref --verify --quiet refs/remotes/origin/release/v1.0.0; then
    fail "a glob as --from is rejected, fetching nothing" \
      "the wildcard refspec still wrote refs/remotes/origin/release/v1.0.0"
  else
    pass "a glob as --from is rejected, fetching nothing"
  fi
}

# Same defect on the other argument: `--to 'mai*'` fetched refs/heads/mai* into
# refs/remotes/origin/mai*, then compared against a ref of that name that does
# not exist, and again ended at "Nothing to backport." with exit 0.
t_glob_to() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to 'mai*' 2>&1)"; then
    fail "a glob as --to is rejected, fetching nothing" "script exited zero"
  elif grep -q "Nothing to backport" <<<"$out"; then
    fail "a glob as --to is rejected, fetching nothing" \
      "the failure was reported as an empty backport"
  elif git -C "$root/clone" show-ref --verify --quiet refs/remotes/origin/release/v1.0.0; then
    fail "a glob as --to is rejected, fetching nothing" \
      "--from was fetched before --to was validated"
  else
    pass "a glob as --to is rejected, fetching nothing"
  fi
}

# --- --to is branch-only ------------------------------------------------------
# A tag resolves and `git checkout -b` would even work, but backport-fixes.yml
# opens a PR with `--base "$TO"`, which needs a branch on the remote. Rejecting
# it here beats failing after the cherry-picks have run, and the message has to
# name the reason — "not found on remote" for a tag the remote demonstrably has
# is the same category of misdirection this suite exists for.
t_to_rejects_a_tag() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from main --to v1.0.0 2>&1)"; then
    fail "--to rejects a tag" "script exited zero"
  elif grep -q "must be a branch" <<<"$out"; then
    pass "--to rejects a tag, naming the reason"
  else
    fail "--to rejects a tag" "unexpected message: ${out##*$'\n'}"
  fi
}

# --- a force-pushed source branch still backports ------------------------------
# What the `+` on the refspecs is for. Without it the fetch is a non-fast-forward
# rejection, and the resolver would report that as "not found on origin".
# Amending a release commit during release prep is routine.
t_force_pushed_source() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # Seed the remote-tracking ref at the pre-amend commit: the state of a
  # maintainer who last fetched before the force-push. Without this the clone
  # has no origin/release/v1.0.0 at all and any fetch is trivially a
  # fast-forward, which is how a missing `+` would go unnoticed.
  git -C "$root/clone" fetch -q origin \
    '+refs/heads/release/v1.0.0:refs/remotes/origin/release/v1.0.0'

  git -C "$root/origin" checkout -q release/v1.0.0
  echo amended > "$root/origin/f.txt"
  git -C "$root/origin" commit -q --amend -am "fix: something landed on the release branch (amended)"
  git -C "$root/origin" checkout -q main

  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>&1)"; then
    if git -C "$root/clone" log --oneline main..HEAD | grep -q "(amended)"; then
      pass "a force-pushed source branch backports the rewritten commit"
    else
      fail "a force-pushed source branch backports the rewritten commit" \
        "it backported the pre-amend commit"
    fi
  else
    fail "a force-pushed source branch backports the rewritten commit" \
      "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- a branch wins when a branch and a tag share the name ----------------------
# The arm order in fetch_source_ref decides this and --help now states it, so it
# needs a case: a repo that tags v1.0.0 and later cuts a branch of the same name
# would otherwise silently change which commits get backported.
t_branch_beats_tag() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # A branch literally named v1.0.0, carrying a commit the tag does not.
  git -C "$root/origin" checkout -q -b v1.0.0 main
  echo from-branch > "$root/origin/f.txt"
  git -C "$root/origin" commit -qam "fix: reached through the branch"
  git -C "$root/origin" checkout -q main

  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from v1.0.0 --to main 2>&1)"; then
    if git -C "$root/clone" log --oneline main..HEAD | grep -q "reached through the branch"; then
      pass "a branch wins over a tag of the same name"
    else
      fail "a branch wins over a tag of the same name" "it resolved the tag instead"
    fi
  else
    fail "a branch wins over a tag of the same name" "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- a re-cut tag backports the new commit -------------------------------------
# What the `+` on the *tag* refspec is for. t_force_pushed_source covers the
# branch arm only; without this case the tag arm's `+` can be deleted and the
# suite still passes. Re-cutting a tag — deleting it on origin and re-pushing it
# at a new commit — is what happens when a release is pulled and redone, and it
# is the one time the local tag and origin's disagree.
#
# Without the `+` the fetch is rejected (`would clobber existing tag`) and
# `|| exit 1` aborts, so this fails on the exit code rather than on a wrong
# backport.
t_recut_tag() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # The maintainer fetched at release time, so the clone holds v1.0.0 at the
  # original commit. Without this the local tag is simply absent, any fetch of
  # it is trivially new, and a missing `+` would go unnoticed — the same trap
  # t_force_pushed_source seeds around on the branch arm.
  git -C "$root/clone" fetch -q origin '+refs/tags/v1.0.0:refs/tags/v1.0.0'

  git -C "$root/origin" checkout -q release/v1.0.0
  echo recut > "$root/origin/f.txt"
  git -C "$root/origin" commit -qam "fix: shipped in the re-cut release"
  git -C "$root/origin" tag -d v1.0.0 >/dev/null
  git -C "$root/origin" tag -a v1.0.0 -m "v1.0.0"
  git -C "$root/origin" checkout -q main

  local out subjects
  if out="$(cd "$root/clone" && "$SCRIPT" --from v1.0.0 --to main 2>&1)"; then
    # Not `git log | grep -q`: this is the first case whose log is more than one
    # line with the match on the first of them, so grep -q exits before git has
    # finished writing, git takes SIGPIPE, and `set -o pipefail` reports the
    # pipeline as failed. Collect first, match second.
    subjects="$(git -C "$root/clone" log --format=%s main..HEAD)"
    if grep -q "re-cut release" <<<"$subjects"; then
      pass "a re-cut tag backports the commit it now names"
    else
      fail "a re-cut tag backports the commit it now names" \
        "it backported the superseded tag's commits"
    fi
  else
    fail "a re-cut tag backports the commit it now names" \
      "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- the fetches stay verbose --------------------------------------------------
# A source-level assertion, deliberately. `-q` suppresses the per-ref status
# table, which is where `! [rejected]` is written — and with the `+` in place
# nothing can produce a rejection, so no fixture reaches the case while the
# script is otherwise correct. Measured on a stale local tag against a re-cut
# origin tag, with the `+` removed:
#
#   without -q:  ! [rejected]  v1.0.0 -> v1.0.0  (would clobber existing tag)  rc 1
#   with    -q:  (nothing on either stream)                                    rc 1
#
# `|| exit 1` then ends the run with no explanation at all, which is what the
# comment above the resolver says must not happen. The lock-error cases below do
# not catch it either: their `error:` lines come from the ref backend rather than
# the status table and survive -q.
t_fetches_stay_verbose() {
  local offenders
  offenders="$(grep -n 'git fetch' "$SCRIPT" | grep -E -- '(-q|--quiet)' || true)"
  if [[ -n "$offenders" ]]; then
    fail "the fetches run without -q" "${offenders//$'\n'/; }"
  else
    pass "the fetches run without -q"
  fi
}

# --- a failed fetch is not a missing ref ---------------------------------------
# The case the resolver was rewritten for. origin has release/v1.0.0 and will
# happily say so, but the fetch cannot write refs/remotes/origin/release/v1.0.0
# because refs/remotes/origin/release already exists as a ref — the state of a
# clone that once tracked a branch called `release`. git fails the fetch with a
# lock error naming the conflict.
#
# The old resolver ran that fetch under `2>/dev/null || true`, found nothing
# under refs/remotes and nothing under refs/tags, and printed "not found on
# origin (tried both branches and tags)" about a branch origin has.
#
# It asserts the absence of the script's own message rather than the presence of
# git's, because the wording of the lock error is git's to change and a test
# pinning it would fail on a git upgrade for unrelated reasons. But absence
# alone would also sign off on a script that failed in silence, and "an
# actionable message" is the whole point — so it also asserts that *something*
# reached stderr, keyed on git's `error:` / `fatal:` prefix. That prefix is a
# convention across every git command, not a wording: git changing it would
# break far more than this suite.
t_failed_fetch_is_not_a_missing_ref() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  local base
  base="$(git -C "$root/clone" rev-parse main)"
  git -C "$root/clone" update-ref refs/remotes/origin/release "$base"

  local out rc=0
  out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>"$root/stderr")" || rc=$?
  local err; err="$(cat "$root/stderr")"
  if [[ "$rc" -eq 0 ]]; then
    fail "a failed fetch is not reported as a missing ref" "script exited zero"
  elif grep -q "not found on origin" <<<"$out$err"; then
    fail "a failed fetch is not reported as a missing ref" \
         "the fetch failure was reported as a missing ref"
  elif ! grep -qE '^(error|fatal):' <<<"$err"; then
    fail "a failed fetch is not reported as a missing ref" \
         "it failed without writing an explanation to stderr"
  elif [[ -n "$(git -C "$root/clone" branch --list 'backport/*')" ]]; then
    fail "a failed fetch is not reported as a missing ref" "it created a backport branch anyway"
  else
    pass "a failed fetch is not reported as a missing ref"
  fi
}

# --- an unreachable remote is not a missing ref --------------------------------
# `git ls-remote --exit-code` answers 2 for "asked, and the remote has no such
# ref" and 128 for "could not ask" — unreachable, or refused. The 128 arm is the
# one that separates them, and without a case a regression in it is invisible:
# the suite passes while a network failure is reported as a missing ref.
#
# Same assertion shape as above, and for the same reasons: `fatal: Could not read
# from remote repository.` is git's wording to change, so what is pinned is that
# the script adds no claim about the ref on top of it — and that git's own
# explanation did reach the operator.
t_unreachable_remote() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  git -C "$root/clone" remote set-url origin /nonexistent

  local out rc=0
  out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>"$root/stderr")" || rc=$?
  local err; err="$(cat "$root/stderr")"
  if [[ "$rc" -eq 0 ]]; then
    fail "an unreachable remote is not reported as a missing ref" "script exited zero"
  elif grep -q "not found on origin" <<<"$out$err"; then
    fail "an unreachable remote is not reported as a missing ref" \
         "the network failure was reported as a missing ref"
  elif ! grep -qE '^(error|fatal):' <<<"$err"; then
    fail "an unreachable remote is not reported as a missing ref" \
         "it failed without writing an explanation to stderr"
  elif [[ -n "$(git -C "$root/clone" branch --list 'backport/*')" ]]; then
    fail "an unreachable remote is not reported as a missing ref" "it created a backport branch anyway"
  else
    pass "an unreachable remote is not reported as a missing ref"
  fi
}

echo "backport-fixes.sh — --from/--to ref resolution"
t_branch
t_tag
t_unknown
t_glob_from
t_glob_to
t_to_rejects_a_tag
t_force_pushed_source
t_branch_beats_tag
t_recut_tag
t_fetches_stay_verbose
t_failed_fetch_is_not_a_missing_ref
t_unreachable_remote

if [[ "$failures" -gt 0 ]]; then
  echo "$failures failing"
  exit 1
fi
echo "all passing"
