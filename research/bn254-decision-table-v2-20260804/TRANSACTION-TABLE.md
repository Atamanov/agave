# BN254 decision table, transaction CU

Syscall core from the committed runtime schedule, plus the measured
guest-side sBPF residual. Core is a tariff and is identical on every host.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 469869 | 123047 | 120210 | 63473 | 343026 | 129071 |
| 2 real Zolana Groth16 proofs — distinct VKs | 188157 | 73544 | 67561 | 61187 | 139073 | 79778 |
| 3 real Zolana Groth16 proofs — distinct VKs | 282061 | 118530 | 109494 | 61887 | 208200 | 109571 |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 524041 | 57595 | 52492 | 61887 | 498145 | 57657 |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 786317 | 77082 | 72032 | 64170 | 747461 | 77144 |

30 of 30 cells carry a measured residual.
The batch columns price the AVX-512 IFMA kernel. A validator without avx512ifma cannot reach these charges, so adopting them raises the hardware floor above docs/src/operations/requirements.md.
