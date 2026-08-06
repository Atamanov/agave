# BN254 decision table, transaction CU

Syscall core from the committed runtime schedule, plus the measured
guest-side sBPF residual. Core is a tariff and is identical on every host.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 392159 | 45328 | 42484 | 51146 | 265326 | 54675 |
| 2 real Zolana Groth16 proofs — distinct VKs | 157064 | 42439 | 36458 | 48860 | 107987 | 53471 |
| 3 real Zolana Groth16 proofs — distinct VKs | 235429 | 72815 | 63774 | 49560 | 161576 | 62883 |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 510617 | 44171 | 39068 | 49560 | 484721 | 44233 |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 766181 | 56946 | 51896 | 51843 | 727325 | 57008 |

30 of 30 cells carry a measured residual.
The batch columns price the AVX-512 IFMA kernel. A validator without avx512ifma cannot reach these charges, so adopting them raises the hardware floor above docs/src/operations/requirements.md.
