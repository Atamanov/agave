# BN254 decision table, where the compute units go

Syscall CU is the charge a validator meters. sBPF is everything the
guest program spends preparing it. A syscall column whose share is low
is measuring its own wrapper.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 388930 / 3229 = 99.1% | 38437 / 6891 = 84.7% | 35011 / 7473 = 82.4% | 42590 / 8556 = 83.2% | 247533 / 17793 = 93.2% | 47161 / 7514 = 86.2% |
| 2 real Zolana Groth16 proofs — distinct VKs | 155572 / 1492 = 99.0% | 36945 / 5494 = 87.0% | 30093 / 6365 = 82.5% | 41348 / 7512 = 84.6% | 99642 / 8345 = 92.2% | 46983 / 6488 = 87.8% |
| 3 real Zolana Groth16 proofs — distinct VKs | 233358 / 2071 = 99.1% | 65235 / 7580 = 89.5% | 54957 / 8817 = 86.1% | 41762 / 7798 = 84.2% | 149463 / 12113 = 92.5% | 53836 / 9047 = 85.6% |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 267259 / 243358 = 52.3% | 37279 / 6892 = 84.3% | 31641 / 7427 = 80.9% | 41762 / 7798 = 84.2% | 241123 / 243598 = 49.7% | 37279 / 6954 = 84.2% |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 400826 / 365355 = 52.3% | 47707 / 9239 = 83.7% | 42069 / 9827 = 81.0% | 43004 / 8839 = 82.9% | 361622 / 365703 = 49.7% | 47707 / 9301 = 83.6% |

Each cell is `syscall CU / sBPF CU = syscall share`.

A syscall-bearing column below 25.0% is reported as a structural breach.

No breach.
