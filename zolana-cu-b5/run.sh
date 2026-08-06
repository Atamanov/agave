#!/usr/bin/env bash
# Measure the confidential rail under each syscall configuration.
#
# The zolana worktree is read-only here. CARGO_TARGET_DIR stays outside it, and
# the prover runs against a directory of symlinks so a missing key can never be
# downloaded into someone else's tree.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scratch="${SCRATCH:-/tmp/zolana-cu-b5}"
recursion_tree="${RECURSION_TREE:-$here/../../zolana/.worktrees/groth16-recursion}"
port=3403

mkdir -p "$scratch"

# LiteSVM turns register tracing on when this is set, and bakes it into the
# program at load time, so it must be exported before the harness boots.
export SBF_TRACE_DIR="$scratch/sbf-trace"
mkdir -p "$SBF_TRACE_DIR"

if ! curl -s -m 2 "http://127.0.0.1:$port/health" >/dev/null; then
  rm -rf "$scratch/prover-keys" && mkdir -p "$scratch/prover-keys"
  for key in "$recursion_tree"/prover/server/proving-keys/*; do
    ln -s "$(readlink -f "$key")" "$scratch/prover-keys/$(basename "$key")"
  done
  nohup "$recursion_tree/target/prover-server" start \
    --keys-dir "$scratch/prover-keys" \
    --prover-address "127.0.0.1:$port" \
    --metrics-address "127.0.0.1:$((port + 7000))" \
    --auto-download=false >"$scratch/prover.log" 2>&1 &
  until curl -s -m 2 "http://127.0.0.1:$port/health" >/dev/null; do sleep 2; done
fi

mkdir -p "$here/artifacts"

# The line-by-line probe behind RECONCILIATION.md. It shadows sol_invoke_signed_c
# and sol_get_sysvar with delegating observers, so a CPI and a sysvar read are
# priced at the site the runtime charges them instead of staying in a residual.
if [[ -n "${PROBE:-}" ]]; then
  ZOLANA_PROVER_URL="http://127.0.0.1:$port" \
    MODE=b5 PROBE=1 BATCH_LEGS="${LEGS:-2}" \
    CARGO_TARGET_DIR="$scratch/target" \
    cargo run --release --manifest-path "$here/Cargo.toml" \
    | tail -n +3 | tee "$here/artifacts/probe-b5-${LEGS:-2}.txt"
  exit 0
fi

for legs in ${LEGS:-2 3}; do
  for mode in ${MODES:-raw stock b5}; do
    ZOLANA_PROVER_URL="http://127.0.0.1:$port" \
      MODE="$mode" BATCH_LEGS="$legs" \
      CARGO_TARGET_DIR="$scratch/target" \
      cargo run --release --manifest-path "$here/Cargo.toml" \
      | tee "$here/artifacts/$mode-$legs.txt"
  done
done
