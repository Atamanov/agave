# BN254 decision table, transaction CU

Syscall core from the committed runtime schedule, plus the measured
guest-side sBPF residual. Core is a tariff and is identical on every host.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 371959 | 105330 | 104935 | 191297 | 338220 | 119919 |
| 2 real Zolana Groth16 proofs — distinct VKs | 149223 | 73430 | 70458 | 166877 | 139708 | 84063 |
| 3 real Zolana Groth16 proofs — distinct VKs | 223539 | 119320 | 116776 | 175067 | 211107 | 111360 |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 382325 | 324917 | 322568 | 175068 | 382573 | 324980 |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 569840 | 475195 | 472873 | 199339 | 570199 | 475258 |

30 of 30 cells carry a measured residual.
The batch columns price the AVX-512 IFMA kernel. A validator without avx512ifma cannot reach these charges, so adopting them raises the hardware floor above docs/src/operations/requirements.md.
