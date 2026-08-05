#!/usr/bin/env bash
# Measures the guest-side sBPF residual for all 30 decision-table cells.
# One ExecutionRequest per cell into the collector, one ResidualCell out.
# Writes research/bn254-decision-table-v2-20260804/residuals.json.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
RESEARCH=research/bn254-decision-table-v2-20260804
PROGS=${PROGS:-/tmp/progs2}
OUT=$RESEARCH/residuals.json

ALGO() { # row is_groth16 column -> algorithm_id
    case "$3" in
    current) $2 && echo groth16-current-independent-v1 || echo plonk-current-independent-v1 ;;
    batch_b5) $2 && echo groth16-batch-b5-v1 || echo plonk-batch-b5-v1 ;;
    registry_b5) $2 && echo groth16-batch-registry-b5-v1 || echo plonk-batch-registry-b5-v1 ;;
    recursion_b5) $2 && echo groth16-recursion-b5-v1 || echo plonk-recursion-b5-v1 ;;
    current_fp12) $2 && echo groth16-current-fp12-v1 || echo plonk-current-fp12-v1 ;;
    batch_fp12_b5) $2 && echo groth16-batch-fp12-b5-v1 || echo plonk-batch-fp12-b5-v1 ;;
    esac
}
PRICING() {
    case "$1" in
    current) echo stock_current ;;
    current_fp12) echo current_fp12 ;;
    batch_fp12_b5) echo batch_fp12_b5 ;;
    *) echo b5 ;;
    esac
}
BACKEND() {
    case "$1" in
    current) echo agave-current ;;
    current_fp12) echo current-fp12 ;;
    batch_fp12_b5) echo helius-b5-fp12 ;;
    *) echo helius-b5 ;;
    esac
}

REV=$(git rev-parse HEAD)
echo '{' > "$OUT"
first=1
for row in groth16_n5_same_vk groth16_n2_distinct_vk groth16_n3_distinct_vk \
           plonk_n2_distinct_vk_shared_srs plonk_n3_distinct_vk_shared_srs; do
    case "$row" in groth16_*) g=true ;; *) g=false ;; esac
    for col in current batch_b5 registry_b5 recursion_b5 current_fp12 batch_fp12_b5; do
        python3 - "$row" "$col" "$(ALGO "$row" $g "$col")" "$(BACKEND "$col")" "$(PRICING "$col")" \
            > /tmp/cell-req.json <<'PY'
import json, sys
row, col, algo, backend, pricing = sys.argv[1:6]
fm = json.load(open("research/bn254-decision-table-v2-20260804/fixture-manifest.real-20260805.json"))
fixture = next(r for r in fm["rows"] if r["row_id"] == row)
print(json.dumps({
    "schema": "helius.bn254-decision-table-v3.execution-request.v1",
    "campaign_id": "local-residual-20260805",
    "row_id": row, "column_id": col, "algorithm_id": algo,
    "backend_id": backend, "pricing_id": pricing,
    "fixture_set_id": fm["fixture_set_id"],
    "fixture_manifest_path":
        "research/bn254-decision-table-v2-20260804/fixture-manifest.real-20260805.json",
    "fixture": fixture, "tariff_sha256": "0" * 64,
}))
PY
        cell=$(./target/debug/solana-bn254-decision-collector \
            --workspace-root . --program-dir "$PROGS" \
            --plonk-fixture-dir "$RESEARCH/fixtures-v3/plonk-zolana-shapes" \
            --runtime-revision "$REV" < /tmp/cell-req.json 2>/dev/null)
        if [ -n "$cell" ]; then
            cu=$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['non_core_transaction_cu'])" "$cell")
            status=ok
        else
            cu=null
            status=FAILED
        fi
        [ $first -eq 0 ] && echo ',' >> "$OUT"
        printf '  "%s/%s": %s' "$row" "$col" "$cu" >> "$OUT"
        first=0
        printf '%-34s %-16s %10s  %s\n' "$row" "$col" "$cu" "$status"
    done
done
printf '\n}\n' >> "$OUT"
echo "wrote $OUT"
