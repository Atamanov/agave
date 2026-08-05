# BN254 decision table, transaction CU

Syscall core from the committed runtime schedule, plus the measured
guest-side sBPF residual. Core is a tariff and is identical on every host.

A cell shown as `N +?` has no residual measurement and is core only, so it
is a lower bound. See CAPTURE-HOST-REQUIREMENTS.md for why.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 376384 | 101289 | 99484 | 187177 | 338220 | 115651 |
| 2 real Zolana Groth16 proofs — distinct VKs | 150993 | 69593 | 63801 | 162961 | 139708 | 162711 |
| 3 real Zolana Groth16 proofs — distinct VKs | 226194 | 107947 | 101173 | 171083 | 211107 | 205800 |
| 2 PLONK canonical committed test exceptions — distinct VKs, shared SRS | 97972 +? | 25779 +? | 22555 +? | 171084 | 97972 +? | 25779 +? |
| 3 PLONK canonical committed test exceptions — distinct VKs, shared SRS | 146958 +? | 31699 +? | 28475 +? | 195151 | 146958 +? | 31699 +? |

20 of 30 cells carry a measured residual.
GT multiexp is provisional at 50000 + 20000t and inflates the fold-all column on multi-key rows.
