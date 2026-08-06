#!/usr/bin/env bash
# Produces the decision tables from committed inputs. Runs on any host: the
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
# The collector decides what every cell reports, so it must be newer than every
# source that can change a count. A stale one already published a full 30-cell
# contract from a binary built before the feature under test existed.
COLLECTOR=${CARGO_TARGET_DIR:-$ROOT/target}/debug/solana-bn254-decision-collector
newer=$(find bn254-decision-collector/src bn254-decision-litesvm/src bn254-decision-bench/src \
    -name '*.rs' -newer "$COLLECTOR" -print -quit)
if [ -n "$newer" ]; then
    echo "FAIL: $COLLECTOR is older than $newer" >&2
    exit 1
fi
bash bn254-decision-bench/collect-residuals.sh

# A null cell means a collector run failed. Rendering it produces a core-only
# table that looks finished, so stop before writing anything.
if grep -q ': *null' "$RESEARCH/residuals.json"; then
    echo "FAIL: residuals.json carries a null cell; a collector run failed" >&2
    grep -n ': *null' "$RESEARCH/residuals.json" >&2
    exit 1
fi
cells=$(grep -c '": *[0-9]' "$RESEARCH/residuals.json")
if [ "$cells" -ne 30 ]; then
    echo "FAIL: residuals.json has $cells measured cells, expected 30" >&2
    exit 1
fi

# Render to a scratch dir and diff BEFORE overwriting. Writing first and testing
# after makes the golden test compare the renderer against its own fresh output,
# which cannot fail.
GENERATED=(TRANSACTION-TABLE.md OPERATIONS-TABLE.md STRUCTURE-TABLE.md expected-counts.v1.json)
EXAMPLES=(render_core_table render_ops_table render_structure_table render_expected_counts)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for i in "${!GENERATED[@]}"; do
    cargo run -q -p solana-bn254-decision-bench --example "${EXAMPLES[$i]}" \
        > "$tmp/${GENERATED[$i]}"
    if [ ! -s "$tmp/${GENERATED[$i]}" ]; then
        echo "FAIL: ${EXAMPLES[$i]} produced nothing" >&2
        exit 1
    fi
done

for f in "${GENERATED[@]}"; do
    if [ -f "$RESEARCH/$f" ] && ! diff -q "$RESEARCH/$f" "$tmp/$f" >/dev/null; then
        echo "NOTE: $f changed" >&2
        diff -u "$RESEARCH/$f" "$tmp/$f" >&2 || true
    fi
    cp "$tmp/$f" "$RESEARCH/$f"
done

# Every generated file must now equal what the renderer emits. This is the
# check the old write-then-test order could not make.
for i in "${!GENERATED[@]}"; do
    cargo run -q -p solana-bn254-decision-bench --example "${EXAMPLES[$i]}" \
        | diff -q - "$RESEARCH/${GENERATED[$i]}" >/dev/null || {
        echo "FAIL: ${GENERATED[$i]} does not reproduce from ${EXAMPLES[$i]}" >&2
        exit 1
    }
done

if grep -q '^|.*+?' "$RESEARCH/TRANSACTION-TABLE.md"; then
    echo "FAIL: unmeasured cells remain in TRANSACTION-TABLE.md" >&2
    exit 1
fi

# A syscall column that is mostly guest sBPF is not measuring its syscall. This
# is a smell detector, not a physical law, so it reports every run and only
# aborts under BN254_STRUCTURE_STRICT.
if grep -q '^## Structural breaches' "$RESEARCH/STRUCTURE-TABLE.md"; then
    echo "STRUCTURAL BREACH: a syscall column is dominated by guest sBPF" >&2
    sed -n '/^## Structural breaches/,$p' "$RESEARCH/STRUCTURE-TABLE.md" >&2
    if [ "${BN254_STRUCTURE_STRICT:-0}" = 1 ]; then exit 1; fi
fi

cargo test -q -p solana-bn254-decision-bench
cargo test -q -p solana-syscalls --test bn254_charge_schedule
printf 'wrote %s in %s\n' "${GENERATED[*]}" "$RESEARCH"
