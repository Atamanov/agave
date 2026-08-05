# BN254 decision table, transaction CU

Syscall core from the committed runtime schedule, plus the measured
guest-side sBPF residual. Core is a tariff and is identical on every host.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 392829 | 48461 | 45698 | 52001 | 267147 | 56875 |
| 2 real Zolana Groth16 proofs — distinct VKs | 157571 | 44649 | 38793 | 49685 | 110382 | 62288 |
| 3 real Zolana Groth16 proofs — distinct VKs | 236061 | 76162 | 67209 | 50395 | 164855 | 75749 |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 514154 | 52460 | 47084 | 50395 | 488266 | 52523 |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 771339 | 69013 | 63664 | 52709 | 732494 | 69076 |

30 of 30 cells carry a measured residual.
The batch columns price the AVX-512 IFMA kernel. A validator without avx512ifma cannot reach these charges, so adopting them raises the hardware floor above docs/src/operations/requirements.md.
