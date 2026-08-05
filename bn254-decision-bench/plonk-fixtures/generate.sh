#!/usr/bin/env bash
# Generates PLONK fixtures whose shapes match zolana's transact rails: one
# public signal per proof, circuit size driven by (nIn, nOut). Distinct
# verifying keys over one shared SRS, which is the case the decision table
# prices.
#
# The earlier fixture set used circomlib multiplier circuits with 1, 2 and 3
# public inputs, so a row priced 3 or 6 public inputs. Every real zolana
# verifying key declares nr_pubinputs = 1.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
CIRCOMLIB=${CIRCOMLIB:?path to the circomlib circuits directory}
PTAU=${PTAU:?path to a powers-of-tau file for the plonk setup}
OUT=$HERE/zolana-shapes
SHAPES=${SHAPES:-"1_1 2_2 2_3"}

test -f "$PTAU" || { echo "missing powers of tau: $PTAU" >&2; exit 1; }
rm -rf "$OUT"; mkdir -p "$OUT"
cd "$HERE/circuits"

for shape in $SHAPES; do
    nin=${shape%_*}
    nout=${shape#*_}
    dir=$OUT/transact_$shape
    mkdir -p "$dir"

    circom "transact_$shape.circom" --r1cs --wasm -o . -l "$CIRCOMLIB" >/dev/null

    # One SRS across every shape: the table's PLONK rows are distinct keys
    # sharing a setup, so the fixtures must share it too.
    snarkjs plonk setup "transact_$shape.r1cs" "$PTAU" "$dir/circuit.zkey" >/dev/null
    snarkjs zkey export verificationkey "$dir/circuit.zkey" "$dir/verification_key.json" >/dev/null

    # Deterministic witness values so a regeneration reproduces identical
    # bytes. They carry no meaning beyond exercising the hash chain.
    python3 - "$nin" "$nout" > "$dir/input.json" <<'PY'
import json, sys
nin, nout = int(sys.argv[1]), int(sys.argv[2])
val = lambda tag, i: str(1 + (i + 1) * (7919 if tag == "nul" else 6271 if tag == "root"
                                        else 5417 if tag == "own" else 4231))
print(json.dumps({
    "nullifiers": [val("nul", i) for i in range(nin)],
    "utxoRoots": [val("root", i) for i in range(nin)],
    "outputOwners": [val("own", j) for j in range(nout)],
    "outputAmounts": [val("amt", j) for j in range(nout)],
}))
PY

    node "transact_${shape}_js/generate_witness.js" \
        "transact_${shape}_js/transact_$shape.wasm" "$dir/input.json" "$dir/witness.wtns" >/dev/null
    snarkjs plonk prove "$dir/circuit.zkey" "$dir/witness.wtns" \
        "$dir/proof.json" "$dir/public.json" >/dev/null
    snarkjs plonk verify "$dir/verification_key.json" "$dir/public.json" "$dir/proof.json" >/dev/null

    n_public=$(python3 -c "import json;print(len(json.load(open('$dir/public.json'))))")
    constraints=$(snarkjs r1cs info "transact_$shape.r1cs" 2>/dev/null |
        grep "# of Constraints" | grep -oE '[0-9]+$')
    printf '  transact_%-4s nIn=%s nOut=%s constraints=%-5s public=%s verified\n' \
        "$shape" "$nin" "$nout" "$constraints" "$n_public"

    rm -f "$dir/witness.wtns" "$dir/circuit.zkey"
done

echo "fixtures in $OUT"
