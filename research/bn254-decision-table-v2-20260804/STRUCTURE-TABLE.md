# BN254 decision table, where the compute units go

Syscall CU is the charge a validator meters. sBPF is everything the
guest program spends preparing it. A syscall column whose share is low
is measuring its own wrapper.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 388930 / 3899 = 99.0% | 36556 / 68774 = 34.7% | 33130 / 70318 = 32.0% | 40803 / 75172 = 35.1% | 247140 / 30238 = 89.0% | 45004 / 73428 = 37.9% |
| 2 real Zolana Groth16 proofs — distinct VKs | 155572 / 1999 = 98.7% | 35464 / 37966 = 48.2% | 28612 / 40363 = 41.4% | 39711 / 51968 = 43.3% | 98856 / 15627 = 86.3% | 45498 / 37082 = 55.0% |
| 3 real Zolana Groth16 proofs — distinct VKs | 233358 / 2703 = 98.8% | 63076 / 56244 = 52.8% | 52798 / 59490 = 47.0% | 40075 / 59676 = 40.1% | 148284 / 22722 = 86.7% | 51671 / 55201 = 48.3% |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 263596 / 255046 = 50.8% | 36108 / 20840 = 63.4% | 30470 / 21132 = 59.0% | 40075 / 59683 = 40.1% | 237460 / 255294 = 48.1% | 36108 / 20903 = 63.3% |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 395394 / 378930 = 51.0% | 46013 / 25985 = 63.9% | 40375 / 26304 = 60.5% | 41167 / 82918 = 33.1% | 356190 / 379289 = 48.4% | 46013 / 26048 = 63.8% |

Each cell is `syscall CU / sBPF CU = syscall share`.

A syscall-bearing column below 25.0% is reported as a structural breach.

No breach.
