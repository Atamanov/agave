# PLONK fixtures shaped like zolana transact

Three circuits mirroring the zolana transact statement: one public signal, a
Poseidon hash chain over per-input nullifiers and roots plus per-output owners
and amounts. Shape `(nIn, nOut)` drives circuit size exactly as it drives the
Groth16 rails.

| fixture | nIn | nOut | r1cs constraints | public signals |
|---|---:|---:|---:|---:|
| `transact_1_1` | 1 | 1 | 519 | 1 |
| `transact_2_2` | 2 | 2 | 1041 | 1 |
| `transact_2_3` | 2 | 3 | 1302 | 1 |

Distinct verifying keys over one shared SRS, which is the case the decision
table's PLONK rows price. Every proof verifies under `snarkjs plonk verify`.

## Why these replace the multiplier fixtures

The previous set used circomlib multipliers with 1, 2 and 3 public inputs, so a
two-proof row priced 3 public inputs and a three-proof row priced 6. Every
zolana verifying key declares `nr_pubinputs: 1`. Public-input count drives the
verifier's Lagrange evaluation and its MSM width, so the old rows measured a
shape zolana never submits.

Poseidon is the right in-circuit cost: it is what the shielded pool hashes
with, and it dominates the constraint count here as it does on the real rails.

## Regenerate

```bash
bash bn254-decision-bench/plonk-fixtures/generate.sh
```

Deterministic: witness values are fixed per shape, so a regeneration reproduces
identical inputs. `PTAU` and `CIRCOMLIB` are overridable. The ceremony must
reach 2^14 — Poseidon expands to ~5.5k PLONK constraints at the 1_1 shape, well
above the r1cs count.

Proving keys are not kept. They are large, derivable, and nothing verifies
against them.
