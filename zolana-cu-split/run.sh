#!/usr/bin/env bash
# Reproduce the syscall-vs-sBPF split for both real zolana programs.
#
# Both zolana worktrees are read-only here. CARGO_TARGET_DIR must stay outside
# them, and the prover runs against a directory of symlinks so a missing key
# can never be downloaded into someone else's tree.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scratch="${SCRATCH:-/tmp/zolana-cu-split}"
registry_tree="${REGISTRY_TREE:-$here/../../zolana/.worktrees/vk-registry}"
recursion_tree="${RECURSION_TREE:-$here/../../zolana/.worktrees/groth16-recursion}"

mkdir -p "$scratch"

# LiteSVM turns register tracing on when this is set, and bakes it into the
# program at load time, so it must be exported before the harness boots.
export SBF_TRACE_DIR="$scratch/sbf-trace"
mkdir -p "$SBF_TRACE_DIR"

start_prover() {
  local tree=$1 port=$2
  if curl -s -m 2 "http://127.0.0.1:$port/health" >/dev/null; then return; fi
  rm -rf "$scratch/prover-keys" && mkdir -p "$scratch/prover-keys"
  for key in "$tree"/prover/server/proving-keys/*; do
    ln -s "$(readlink -f "$key")" "$scratch/prover-keys/$(basename "$key")"
  done
  nohup "$tree/target/prover-server" start \
    --keys-dir "$scratch/prover-keys" \
    --prover-address "127.0.0.1:$port" \
    --metrics-address "127.0.0.1:$((port + 7000))" \
    --auto-download=false >"$scratch/prover.log" 2>&1 &
  until curl -s -m 2 "http://127.0.0.1:$port/health" >/dev/null; do sleep 2; done
}

case "${1:-both}" in
registry | both)
  start_prover "$registry_tree" 3401
  ZOLANA_PROVER_URL=http://127.0.0.1:3401 \
    CARGO_TARGET_DIR="$scratch/target-registry" \
    cargo run --release --manifest-path "$here/registry/Cargo.toml" \
    | tee "$here/artifacts/registry-run.txt"
  ;;&
aggregate | both)
  start_prover "$recursion_tree" 3402
  ZOLANA_PROVER_URL=http://127.0.0.1:3402 \
    BATCH_LEGS="${BATCH_LEGS:-2}" \
    CARGO_TARGET_DIR="$scratch/target-aggregate" \
    cargo run --release --manifest-path "$here/aggregate/Cargo.toml" \
    | tee "$here/artifacts/aggregate-run.txt"
  ;;
esac
