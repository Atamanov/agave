# BN254 decision table, transaction CU

Syscall core from the committed runtime schedule, plus the measured
guest-side sBPF residual. Core is a tariff and is identical on every host.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 392829 | 95123 | 93241 | 101658 | 267163 | 108225 |
| 2 real Zolana Groth16 proofs — distinct VKs | 157571 | 69348 | 64893 | 83499 | 110398 | 78498 |
| 3 real Zolana Groth16 proofs — distinct VKs | 236061 | 113191 | 106159 | 89515 | 164871 | 100743 |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 518642 | 56948 | 51602 | 89508 | 492754 | 57011 |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 774324 | 71998 | 66679 | 107654 | 735479 | 72061 |

30 of 30 cells carry a measured residual.
The batch columns price the AVX-512 IFMA kernel. A validator without avx512ifma cannot reach these charges, so adopting them raises the hardware floor above docs/src/operations/requirements.md.
