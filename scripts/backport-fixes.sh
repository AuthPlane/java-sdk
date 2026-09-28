#!/usr/bin/env bash
set -euo pipefail

# Cherry-pick commits from a release/hotfix branch (or a release tag) to a
# local backport branch off the target. Does NOT push, create PRs, or
# touch remotes beyond `git fetch`.
#
# Conflicts use git's native cherry-pick state machine — resolve, then
# `git cherry-pick --continue` (or --skip / --abort). Re-running this
# script is not needed after a conflict; git's sequencer handles it.
#
# Uses `git cherry` for patch-ID-based matching, so commits already
# cherry-picked to the target (under different SHAs) are correctly
# detected and excluded.

usage() {
  cat <<'EOF'
Usage:
  backport-fixes.sh --from <ref> --to <branch> [--branch <name>] [--no-filter]

Options:
  --from <ref>       Source ref on origin: a branch (e.g. release/v0.6.0,
                     hotfix/v0.5.1) or a tag (e.g. v0.6.0). Do not include
                     'origin/'. Required. Use the tag after the release
                     workflow has deleted the source branch. A branch wins
                     if a branch and a tag share the name. One ref name,
                     not a pattern — globs like 'release/*' are rejected.
  --to <branch>      Target branch on origin. Required. Branch only:
                     backport-fixes.yml opens a PR with --base, which
                     needs a branch that exists on the remote.
  --branch <name>    Name for the local backport branch (default:
                     `backport/vX.Y.Z` derived from --from when it
                     matches release/vX.Y.Z, hotfix/vX.Y.Z, or vX.Y.Z;
                     otherwise `backport/<flattened-from>`).
  --no-filter        Include commits whose subject starts with
                     'release:' or 'release-prep:' (automated version
                     bumps). Default behavior excludes them to keep the
                     target branch's own version string intact.
  -h, --help         Show this help.

Behavior:
  1. Asks origin what <from> and <to> name (git ls-remote), then fetches
     those two refs — not the whole remote.
  2. Lists commits on the resolved source ref — origin/<from> for a
     branch, refs/tags/<from> for a tag — that aren't already on
     origin/<to>, and commits that are already there (skipped).
  3. Creates the backport branch off origin/<to>.
  4. Runs `git cherry-pick -x` with the candidates, oldest-first.
  5. On conflict: stops. Resolve, then `git cherry-pick --continue`.

  By default, commits with subjects matching ^(release|release-prep):
  are excluded from the candidate list — in this repo these are always
  automated version-file edits that would conflict with the target's
  own version string. Pass --no-filter to include them.

If the backport branch already exists locally, the script fails — delete
it (`git branch -D <name>`) or pass `--branch <other-name>` to override.

No push. No PR. The branch stays local; you decide what to do next.

Examples:
  backport-fixes.sh --from release/v0.6.0 --to main
  backport-fixes.sh --from v0.6.0        --to main   # branch deleted post-release
EOF
}

FROM=""
TO=""
BRANCH_OVERRIDE=""
NO_FILTER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from)      FROM="${2-}"; shift 2 ;;
    --to)        TO="${2-}"; shift 2 ;;
    --branch)    BRANCH_OVERRIDE="${2-}"; shift 2 ;;
    --no-filter) NO_FILTER=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$FROM" ]]; then
  echo "error: --from is required" >&2
  usage >&2
  exit 2
fi
if [[ -z "$TO" ]]; then
  echo "error: --to is required" >&2
  usage >&2
  exit 2
fi
if [[ "$FROM" == origin/* || "$TO" == origin/* ]]; then
  echo "error: refs must not include 'origin/'" >&2
  exit 2
fi
if [[ "$FROM" == "$TO" ]]; then
  echo "error: --from and --to must differ" >&2
  exit 2
fi

# Each of --from / --to names exactly one ref, and nothing downstream enforces
# it. `git ls-remote` matches its argument as a glob and `*` is legal in a
# refspec, so `--from 'release/*'` answers "the ref is there", fetches
# wildcard-expanded — writing refs/remotes/origin/release/v1.0.0 — and leaves
# the source ref naming a pattern. `git cherry` then dies with `fatal: unknown
# commit`, the `|| true` on it swallows that, and the run ends "Nothing to
# backport." at exit 0: a tooling failure handed to the operator as a fact
# about the refs.
#
# `git check-ref-format` is git's own rule set for a ref name. It rejects the
# glob metacharacters and also `~`, `^`, `:`, `..` and friends — none of which
# name a single ref either. Checked here, before the first ls-remote, so a
# rejected argument cannot leave the local ref store changed. The rules are the
# same under refs/heads and refs/tags, so one check covers both arms.
require_single_ref_name() {
  local flag="$1" name="$2"
  if ! git check-ref-format "refs/heads/$name" 2>/dev/null; then
    echo "error: $flag '$name' is not the name of a single ref" >&2
    echo "       No globs ('*', '?', '['), no '~', '^', ':' or '..'." >&2
    exit 2
  fi
}
require_single_ref_name --from "$FROM"
require_single_ref_name --to "$TO"

# Must be in a git repo
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "error: not inside a git repository" >&2
  exit 1
fi

# Detect in-progress cherry-pick first — gives a more actionable error
# than the generic dirty-tree check, which also trips during a conflict.
if [[ -f "$(git rev-parse --git-dir)/CHERRY_PICK_HEAD" ]]; then
  echo "error: a cherry-pick is already in progress. Finish or abort it first:" >&2
  echo "       git cherry-pick --continue | --skip | --abort" >&2
  exit 1
fi

# Require clean working tree — cherry-picks onto a dirty tree are unsafe.
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "error: working tree has uncommitted changes. Commit or stash first." >&2
  exit 1
fi

echo "Resolving --from / --to against origin..."

# Ask origin what a name is before fetching it, instead of attempting a fetch
# and reading its failure as absence. `git ls-remote --exit-code` answers 0 (the
# ref is there), 2 (the remote answered and has no such ref) or 128 (the remote
# was unreachable, or refused us). Only 2 means "not found"; reporting 128 as a
# missing ref sends the operator after a ref that is perfectly fine.
#
# Both refspecs below keep their leading `+`. Without the force, a source branch
# that was force-pushed — routine during release prep, e.g. an amended release
# commit — stops fast-forwarding and the fetch is rejected.
#
# The fetches run without -q on purpose: -q suppresses the per-ref status table,
# which is where `! [rejected]` is written, so a fetch that fails after
# ls-remote said the ref was there would exit with no explanation at all.
remote_ref_exists() {
  local rc=0
  git ls-remote --exit-code origin "$1" >/dev/null || rc=$?
  case "$rc" in
    0) return 0 ;;
    2) return 1 ;;
    # git has already described the failure on stderr; adding a guess about the
    # ref on top of it would only mislead.
    *) exit 1 ;;
  esac
}

# These assign to from_ref / from_pretty rather than echoing their result.
# Called as `$(...)`, the body would run in a subshell, where the `exit 1` above
# exits only that subshell and the caller carries on with an empty ref.
from_ref=""
from_pretty=""

# --from accepts a branch or a tag: after a release the source branch is gone,
# and the tag is the only ref naming those commits. Branches go to
# refs/remotes/origin/<from>, tags to refs/tags/<from>. A branch wins if a
# branch and a tag share the name.
fetch_source_ref() {
  local name="$1"
  if remote_ref_exists "refs/heads/$name"; then
    git fetch origin --no-tags "+refs/heads/$name:refs/remotes/origin/$name" || exit 1
    from_ref="refs/remotes/origin/$name"
    from_pretty="origin/$name"
  elif remote_ref_exists "refs/tags/$name"; then
    # A re-cut tag (deleted on origin and re-pushed at a new commit) lands here.
    # `+` overwrites the stale local tag. Without it the fetch does not quietly
    # keep the old tag — it is rejected outright, `! [rejected] v1.0.0 -> v1.0.0
    # (would clobber existing tag)`, and `|| exit 1` aborts the run. Loud, but
    # for a tag origin has moved on purpose. t_recut_tag pins this arm.
    git fetch origin --no-tags "+refs/tags/$name:refs/tags/$name" || exit 1
    from_ref="refs/tags/$name"
    from_pretty="$name (tag)"
  else
    return 1
  fi
}

# --to is branch-only, deliberately. A tag would resolve and `git checkout -b`
# would even work, but backport-fixes.yml opens a PR with `--base "$TO"`, which
# needs a branch that exists on the remote.
fetch_target_ref() {
  local name="$1"
  if remote_ref_exists "refs/heads/$name"; then
    git fetch origin --no-tags "+refs/heads/$name:refs/remotes/origin/$name" || exit 1
  else
    return 1
  fi
}

if ! fetch_source_ref "$FROM"; then
  echo "error: $FROM not found on origin as a branch or a tag" >&2
  exit 1
fi

if ! fetch_target_ref "$TO"; then
  echo "error: $TO not found on origin as a branch (--to must be a branch)" >&2
  exit 1
fi

# ls-remote said both refs were there and both fetches reported success, so both
# must now name a commit locally. Anything else — a tag object pointing at a
# blob, a ref that landed as something other than a commit — reaches `git
# cherry` below, which fails, and the `|| true` on it turns the failure into an
# empty candidate list and "Nothing to backport." at exit 0. Stop here instead:
# the run has already established these two refs resolve, so a ref that does not
# is a fault, not an answer.
for resolved in "$from_ref" "refs/remotes/origin/$TO"; do
  if ! git rev-parse --verify --quiet "$resolved^{commit}" >/dev/null; then
    echo "error: $resolved does not name a commit after fetching from origin" >&2
    exit 1
  fi
done

# `git cherry -v <upstream> <head>` prints one line per commit:
#   + <sha> <subject>   -> not on upstream (candidate for backport)
#   - <sha> <subject>   -> already on upstream via patch-ID match
cherry_out="$(git cherry -v "refs/remotes/origin/$TO" "$from_ref" || true)"

all_candidates="$(echo "$cherry_out" | awk '$1 == "+" { sub(/^\+ /, ""); print }')"
already_pretty="$(echo  "$cherry_out" | awk '$1 == "-" { sub(/^- /, "");  print }')"

if [[ -n "$NO_FILTER" ]]; then
  candidates_pretty="$all_candidates"
  filtered_pretty=""
else
  filtered_pretty="$(echo "$all_candidates" | grep -E '^[0-9a-f]+ (release|release-prep):' || true)"
  candidates_pretty="$(echo "$all_candidates" | grep -Ev '^[0-9a-f]+ (release|release-prep):' || true)"
fi

shas="$(echo "$candidates_pretty" | awk 'NF { print $1 }')"

n_candidates=0
[[ -n "$candidates_pretty" ]] && n_candidates=$(echo "$candidates_pretty" | wc -l | tr -d ' ')
n_already=0
[[ -n "$already_pretty" ]] && n_already=$(echo "$already_pretty" | wc -l | tr -d ' ')
n_filtered=0
[[ -n "$filtered_pretty" ]] && n_filtered=$(echo "$filtered_pretty" | wc -l | tr -d ' ')

echo
echo "=== Commits on $from_pretty not yet on origin/$TO ($n_candidates) ==="
if [[ "$n_candidates" -gt 0 ]]; then
  echo "$candidates_pretty"
else
  echo "(none)"
fi

if [[ "$n_already" -gt 0 ]]; then
  echo
  echo "=== Already on origin/$TO, excluded ($n_already) ==="
  echo "$already_pretty"
fi

if [[ "$n_filtered" -gt 0 ]]; then
  echo
  echo "=== Skipped (version-bump commits; pass --no-filter to include) ($n_filtered) ==="
  echo "$filtered_pretty"
fi

if [[ "$n_candidates" -eq 0 ]]; then
  echo
  echo "Nothing to backport."
  exit 0
fi

if [[ -n "$BRANCH_OVERRIDE" ]]; then
  branch="$BRANCH_OVERRIDE"
elif [[ "$FROM" =~ ^(release|hotfix)/v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
  branch="backport/v${BASH_REMATCH[2]}"
elif [[ "$FROM" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
  branch="backport/v${BASH_REMATCH[1]}"
else
  flat="$(echo "$FROM" | sed -E 's|/|-|g; s/[^a-zA-Z0-9._-]+/-/g')"
  branch="backport/${flat}"
fi

if git show-ref --verify --quiet "refs/heads/$branch"; then
  echo "error: local branch '$branch' already exists." >&2
  echo "       Delete it (git branch -D $branch) or pass --branch <other-name>." >&2
  exit 1
fi

echo
echo "Creating branch $branch off origin/$TO..."
git checkout -b "$branch" "origin/$TO"

echo
echo "Cherry-picking $n_candidates commit(s) with -x, oldest first..."
echo "If git stops on a conflict:"
echo "  - Resolve, 'git add <files>', then 'git cherry-pick --continue'."
echo "  - To drop the conflicting commit: 'git cherry-pick --skip'."
echo "  - To bail out entirely:           'git cherry-pick --abort'."
echo

# shellcheck disable=SC2086 # intentional word-split: $shas is a hex-only list
exec git cherry-pick -x $shas
