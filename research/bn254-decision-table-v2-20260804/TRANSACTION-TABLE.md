# BN254 decision table, transaction CU

Syscall core from the committed runtime schedule, plus the measured
guest-side sBPF residual. Core is a tariff and is identical on every host.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 392159 | 45347 | 42510 | 46329 | 265326 | 51371 |
| 2 real Zolana Groth16 proofs — distinct VKs | 157064 | 42458 | 36475 | 44043 | 107987 | 48692 |
| 3 real Zolana Groth16 proofs — distinct VKs | 235429 | 71906 | 62870 | 44743 | 161576 | 62947 |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 510617 | 44171 | 39068 | 44743 | 484721 | 44233 |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 766181 | 56946 | 51896 | 47026 | 727325 | 57008 |

30 of 30 cells carry a measured residual.
The batch columns price the AVX-512 IFMA kernel. A validator without avx512ifma cannot reach these charges, so adopting them raises the hardware floor above docs/src/operations/requirements.md.
