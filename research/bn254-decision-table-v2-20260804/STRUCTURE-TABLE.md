# BN254 decision table, where the compute units go

Syscall CU is the charge a validator meters. sBPF is everything the
guest program spends preparing it. A syscall column whose share is low
is measuring its own wrapper.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 368060 / 3899 = 98.9% | 36556 / 68774 = 34.7% | 33130 / 71805 = 31.5% | 40799 / 150498 = 21.3% | 306495 / 31725 = 90.6% | 45004 / 74915 = 37.5% |
| 2 real Zolana Groth16 proofs — distinct VKs | 147224 / 1999 = 98.6% | 35464 / 37966 = 48.2% | 28612 / 41846 = 40.6% | 39707 / 127170 = 23.7% | 122598 / 17110 = 87.7% | 45498 / 38565 = 54.1% |
| 3 real Zolana Groth16 proofs — distinct VKs | 220836 / 2703 = 98.7% | 63076 / 56244 = 52.8% | 52798 / 63978 = 45.2% | 40071 / 134996 = 22.8% | 183897 / 27210 = 87.1% | 51671 / 59689 = 46.3% |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 97972 / 284353 = 25.6% | 30531 / 294386 = 9.3% | 24893 / 297675 = 7.7% | 40071 / 134997 = 22.8% | 97972 / 284601 = 25.6% | 30531 / 294449 = 9.3% |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 146958 / 422882 = 25.7% | 37811 / 437384 = 7.9% | 32173 / 440700 = 6.8% | 41163 / 158176 = 20.6% | 146958 / 423241 = 25.7% | 37811 / 437447 = 7.9% |

Each cell is `syscall CU / sBPF CU = syscall share`.

A syscall-bearing column below 25.0% is reported as a structural breach.

## Structural breaches

- **2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS / Batching syscalls (B5)** spends only 9.3% of its budget in the syscall it is named after.
- **2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS / Batching + VK registry (B5)** spends only 7.7% of its budget in the syscall it is named after.
- **2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS / Batching + Fp12 (B5)** spends only 9.3% of its budget in the syscall it is named after.
- **3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS / Batching syscalls (B5)** spends only 7.9% of its budget in the syscall it is named after.
- **3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS / Batching + VK registry (B5)** spends only 6.8% of its budget in the syscall it is named after.
- **3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS / Batching + Fp12 (B5)** spends only 7.9% of its budget in the syscall it is named after.
