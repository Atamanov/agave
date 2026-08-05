# BN254 decision table, transaction CU

Syscall core from the committed runtime schedule, plus the measured
guest-side sBPF residual. Core is a tariff and is identical on every host.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 392829 | 105330 | 103448 | 191297 | 277378 | 118432 |
| 2 real Zolana Groth16 proofs — distinct VKs | 157571 | 73430 | 68975 | 166877 | 114483 | 82580 |
| 3 real Zolana Groth16 proofs — distinct VKs | 236061 | 119320 | 112288 | 175067 | 171006 | 106872 |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 518681 | 295649 | 290303 | 175068 | 492793 | 295712 |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 774385 | 431304 | 425985 | 199339 | 735540 | 431367 |

30 of 30 cells carry a measured residual.
The batch columns price the AVX-512 IFMA kernel. A validator without avx512ifma cannot reach these charges, so adopting them raises the hardware floor above docs/src/operations/requirements.md.
