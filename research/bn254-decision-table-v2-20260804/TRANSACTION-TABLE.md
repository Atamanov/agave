# BN254 decision table, transaction CU

Syscall core from the committed runtime schedule, plus the measured
guest-side sBPF residual. Core is a tariff and is identical on every host.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 392829 | 105330 | 103448 | 115975 | 277378 | 118432 |
| 2 real Zolana Groth16 proofs — distinct VKs | 157571 | 73430 | 68975 | 91679 | 114483 | 82580 |
| 3 real Zolana Groth16 proofs — distinct VKs | 236061 | 119320 | 112288 | 99751 | 171006 | 106872 |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 518642 | 56948 | 51602 | 99758 | 492754 | 57011 |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 774324 | 71998 | 66679 | 124085 | 735479 | 72061 |

30 of 30 cells carry a measured residual.
The batch columns price the AVX-512 IFMA kernel. A validator without avx512ifma cannot reach these charges, so adopting them raises the hardware floor above docs/src/operations/requirements.md.
