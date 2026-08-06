# BN254 decision table, where the compute units go

Syscall CU is the charge a validator meters. sBPF is everything the
guest program spends preparing it. A syscall column whose share is low
is measuring its own wrapper.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 388930 / 3229 = 99.1% | 36578 / 8750 = 80.6% | 33152 / 9332 = 78.0% | 40821 / 10325 = 79.8% | 247140 / 18186 = 93.1% | 45038 / 9637 = 82.3% |
| 2 real Zolana Groth16 proofs — distinct VKs | 155572 / 1492 = 99.0% | 35472 / 6967 = 83.5% | 28620 / 7838 = 78.5% | 39723 / 9137 = 81.2% | 98856 / 9131 = 91.5% | 45510 / 7961 = 85.1% |
| 3 real Zolana Groth16 proofs — distinct VKs | 233358 / 2071 = 99.1% | 63088 / 9727 = 86.6% | 52810 / 10964 = 82.8% | 40089 / 9471 = 80.8% | 148284 / 13292 = 91.7% | 51689 / 11194 = 82.1% |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 263596 / 247021 = 51.6% | 36108 / 8063 = 81.7% | 30470 / 8598 = 77.9% | 40089 / 9471 = 80.8% | 237460 / 247261 = 48.9% | 36108 / 8125 = 81.6% |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 395394 / 370787 = 51.6% | 46013 / 10933 = 80.8% | 40375 / 11521 = 77.7% | 41187 / 10656 = 79.4% | 356190 / 371135 = 48.9% | 46013 / 10995 = 80.7% |

Each cell is `syscall CU / sBPF CU = syscall share`.

A syscall-bearing column below 25.0% is reported as a structural breach.

No breach.
