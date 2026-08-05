# BN254 decision table, where the compute units go

Syscall CU is the charge a validator meters. sBPF is everything the
guest program spends preparing it. A syscall column whose share is low
is measuring its own wrapper.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 388930 / 3899 = 99.0% | 36578 / 11883 = 75.4% | 33152 / 12546 = 72.5% | 40821 / 11180 = 78.5% | 247140 / 20007 = 92.5% | 45038 / 11837 = 79.1% |
| 2 real Zolana Groth16 proofs — distinct VKs | 155572 / 1999 = 98.7% | 35472 / 9177 = 79.4% | 28620 / 10173 = 73.7% | 39723 / 9962 = 79.9% | 98856 / 11526 = 89.5% | 45510 / 16778 = 73.0% |
| 3 real Zolana Groth16 proofs — distinct VKs | 233358 / 2703 = 98.8% | 63088 / 13074 = 82.8% | 52810 / 14399 = 78.5% | 40089 / 10306 = 79.5% | 148284 / 16571 = 89.9% | 51689 / 24060 = 68.2% |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 263596 / 250558 = 51.2% | 36108 / 16352 = 68.8% | 30470 / 16614 = 64.7% | 40089 / 10306 = 79.5% | 237460 / 250806 = 48.6% | 36108 / 16415 = 68.7% |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 395394 / 375945 = 51.2% | 46013 / 23000 = 66.6% | 40375 / 23289 = 63.4% | 41187 / 11522 = 78.1% | 356190 / 376304 = 48.6% | 46013 / 23063 = 66.6% |

Each cell is `syscall CU / sBPF CU = syscall share`.

A syscall-bearing column below 25.0% is reported as a structural breach.

No breach.
