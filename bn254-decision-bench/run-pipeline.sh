#!/usr/bin/env bash
# Produces both decision tables from committed inputs. Runs on any host: the
# charge schedule is a tariff, and the residual is guest-side sBPF CU, which
# LiteSVM counts deterministically.
#
# The tariff capture is not part of this. It needs an x86 host that passes
# scripts/verify-capture-host.sh, and its output is committed under
# research/bn254-decision-table-v2-20260804/capture-zen5-20260805.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
RESEARCH=research/bn254-decision-table-v2-20260804
PROGS=${PROGS:-$ROOT/target/decision-guests}
export PROGS

mkdir -p "$PROGS"
for guest in groth16 groth-recursion plonk-direct plonk-recursion; do
    echo "building $guest"
    cargo-build-sbf --manifest-path "bn254-decision-bench/sbf/$guest/Cargo.toml" \
        --sbf-out-dir "$PROGS"
done

cargo build -p solana-bn254-decision-collector
bash bn254-decision-bench/collect-residuals.sh

cargo run -q -p solana-bn254-decision-bench --example render_core_table > "$RESEARCH/TRANSACTION-TABLE.md"
cargo run -q -p solana-bn254-decision-bench --example render_ops_table > "$RESEARCH/OPERATIONS-TABLE.md"
cargo test -q -p solana-bn254-decision-bench
cargo test -q -p solana-syscalls --test bn254_charge_schedule

if grep -q '^|.*+?' "$RESEARCH/TRANSACTION-TABLE.md"; then
    echo "WARNING: unmeasured cells remain in TRANSACTION-TABLE.md" >&2
fi
echo "wrote $RESEARCH/TRANSACTION-TABLE.md and $RESEARCH/OPERATIONS-TABLE.md"
