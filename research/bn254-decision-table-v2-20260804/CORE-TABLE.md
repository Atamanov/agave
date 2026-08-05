# BN254 decision table, syscall core

Charged CU from the committed runtime schedule. Host-independent.
Excludes the guest-side sBPF residual, so each cell is a lower bound.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 368060 | 32515 | 27679 | 36679 | 306495 | 40736 |
| 2 real Zolana Groth16 proofs — distinct VKs | 147224 | 31627 | 21955 | 35791 | 122598 | 124146 |
| 3 real Zolana Groth16 proofs — distinct VKs | 220836 | 51703 | 37195 | 36087 | 183897 | 146111 |
| 2 PLONK canonical committed test exceptions — distinct VKs, shared SRS | 97972 | 25779 | 22555 | 36087 | 97972 | 25779 |
| 3 PLONK canonical committed test exceptions — distinct VKs, shared SRS | 146958 | 31699 | 28475 | 36975 | 146958 | 31699 |

GT multiexp is provisional at 50000 + 20000t and inflates the fold-all column on multi-key rows.
