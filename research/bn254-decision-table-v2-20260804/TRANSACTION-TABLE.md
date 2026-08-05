# BN254 decision table, transaction CU

Syscall core from the committed runtime schedule, plus the measured
guest-side sBPF residual. Core is a tariff and is identical on every host.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 392829 | 48635 | 46753 | 52051 | 267163 | 107678 |
| 2 real Zolana Groth16 proofs — distinct VKs | 157571 | 44710 | 40255 | 49741 | 110398 | 78498 |
| 3 real Zolana Groth16 proofs — distinct VKs | 236061 | 76247 | 69215 | 50449 | 164871 | 100743 |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 518642 | 56948 | 51602 | 50437 | 492754 | 57011 |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 774324 | 71998 | 66679 | 52757 | 735479 | 72061 |

30 of 30 cells carry a measured residual.
The batch columns price the AVX-512 IFMA kernel. A validator without avx512ifma cannot reach these charges, so adopting them raises the hardware floor above docs/src/operations/requirements.md.
