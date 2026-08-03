#!/usr/bin/env bash
# Cross-branch wire-conformance diff for solana-bn254-batch-syscall.
#
# For each named branch, checks out a temporary worktree and runs the crate's
# wire-fingerprint conformance test, which drives the four public batch fns
# through a fixed input battery and prints a keccak256 hash over every output
# byte and error discriminant. Identical fingerprints prove the branches are
# byte-identical on the wire (same outputs, same errors, same precedence)
# over the whole battery; any divergence prints per branch and exits nonzero.
#
# Usage: scripts/bn254-branch-diff.sh <branch> [<branch>...]
#
# CARGO_TARGET_DIR is passed through, so pointing it at a shared directory
# lets the branches reuse each other's dependency builds.

set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <branch> [<branch>...]" >&2
    exit 2
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

branches=("$@")
fingerprints=()

worktree=""
cleanup() {
    if [ -n "$worktree" ]; then
        git worktree remove --force "$worktree" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

for branch in "${branches[@]}"; do
    worktree="$(mktemp -d "${TMPDIR:-/tmp}/bn254-diff.XXXXXX")"
    # mktemp created the directory; worktree add wants to create it itself
    rmdir "$worktree"
    echo "==> $branch" >&2
    git worktree add --detach "$worktree" "$branch" >&2

    # --nocapture so the printed fingerprint reaches the log even on pass
    log="$worktree/fingerprint.log"
    if ! (cd "$worktree" && cargo test -p solana-bn254-batch-syscall \
        --features agave-unstable-api --test fingerprint \
        -- --nocapture) >"$log" 2>&1; then
        cat "$log" >&2
        echo "error: fingerprint test failed on $branch (its own GOLDEN mismatch?)" >&2
        exit 1
    fi

    fp="$(grep -o 'wire fingerprint: [0-9a-f]*' "$log" | head -1 | awk '{print $3}')"
    if [ -z "$fp" ]; then
        cat "$log" >&2
        echo "error: no fingerprint in test output on $branch" >&2
        exit 1
    fi
    fingerprints+=("$fp")

    git worktree remove --force "$worktree" >&2
    worktree=""
done

echo
printf '%-40s %s\n' "branch" "fingerprint"
status=0
for i in "${!branches[@]}"; do
    printf '%-40s %s\n' "${branches[$i]}" "${fingerprints[$i]}"
    if [ "${fingerprints[$i]}" != "${fingerprints[0]}" ]; then
        status=1
    fi
done

if [ "$status" -ne 0 ]; then
    echo
    echo "FAIL: fingerprints differ; the branches are not wire-identical" >&2
else
    echo
    echo "OK: all ${#branches[@]} branches share one wire fingerprint"
fi
exit "$status"
