# BN254 decision table, where the compute units go

Syscall CU is the charge a validator meters. sBPF is everything the
guest program spends preparing it. A syscall column whose share is low
is measuring its own wrapper.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 388930 / 3899 = 99.0% | 36578 / 12057 = 75.2% | 33152 / 13601 = 70.9% | 40821 / 11230 = 78.4% | 247140 / 20023 = 92.5% | 45004 / 62674 = 41.7% |
| 2 real Zolana Groth16 proofs — distinct VKs | 155572 / 1999 = 98.7% | 35472 / 9238 = 79.3% | 28620 / 11635 = 71.0% | 39723 / 10018 = 79.8% | 98856 / 11542 = 89.5% | 45498 / 33000 = 57.9% |
| 3 real Zolana Groth16 proofs — distinct VKs | 233358 / 2703 = 98.8% | 63088 / 13159 = 82.7% | 52810 / 16405 = 76.2% | 40089 / 10360 = 79.4% | 148284 / 16587 = 89.9% | 51671 / 49072 = 51.2% |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 263596 / 255046 = 50.8% | 36108 / 20840 = 63.4% | 30470 / 21132 = 59.0% | 40089 / 10348 = 79.4% | 237460 / 255294 = 48.1% | 36108 / 20903 = 63.3% |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 395394 / 378930 = 51.0% | 46013 / 25985 = 63.9% | 40375 / 26304 = 60.5% | 41187 / 11570 = 78.0% | 356190 / 379289 = 48.4% | 46013 / 26048 = 63.8% |

Each cell is `syscall CU / sBPF CU = syscall share`.

A syscall-bearing column below 25.0% is reported as a structural breach.

No breach.
