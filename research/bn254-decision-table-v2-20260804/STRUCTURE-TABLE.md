# BN254 decision table, where the compute units go

Syscall CU is the charge a validator meters. sBPF is everything the
guest program spends preparing it. A syscall column whose share is low
is measuring its own wrapper.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 388930 / 3899 = 99.0% | 36556 / 68774 = 34.7% | 33130 / 70318 = 32.0% | 40799 / 150498 = 21.3% | 327365 / 30238 = 91.5% | 45004 / 73428 = 37.9% |
| 2 real Zolana Groth16 proofs — distinct VKs | 155572 / 1999 = 98.7% | 35464 / 37966 = 48.2% | 28612 / 40363 = 41.4% | 39707 / 127170 = 23.7% | 130946 / 15627 = 89.3% | 45498 / 37082 = 55.0% |
| 3 real Zolana Groth16 proofs — distinct VKs | 233358 / 2703 = 98.8% | 63076 / 56244 = 52.8% | 52798 / 59490 = 47.0% | 40071 / 134996 = 22.8% | 196419 / 22722 = 89.6% | 51671 / 55201 = 48.3% |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 263596 / 284356 = 48.1% | 30531 / 294389 = 9.3% | 24893 / 294681 = 7.7% | 40071 / 134997 = 22.8% | 263596 / 284604 = 48.0% | 30531 / 294452 = 9.3% |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 395394 / 422885 = 48.3% | 37811 / 437387 = 7.9% | 32173 / 437706 = 6.8% | 41163 / 158176 = 20.6% | 395394 / 423244 = 48.2% | 37811 / 437450 = 7.9% |

Each cell is `syscall CU / sBPF CU = syscall share`.

A syscall-bearing column below 25.0% is reported as a structural breach.

## Structural breaches

- **2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS / Batching syscalls (B5)** spends only 9.3% of its budget in the syscall it is named after.
- **2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS / Batching + VK registry (B5)** spends only 7.7% of its budget in the syscall it is named after.
- **2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS / Batching + Fp12 (B5)** spends only 9.3% of its budget in the syscall it is named after.
- **3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS / Batching syscalls (B5)** spends only 7.9% of its budget in the syscall it is named after.
- **3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS / Batching + VK registry (B5)** spends only 6.8% of its budget in the syscall it is named after.
- **3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS / Batching + Fp12 (B5)** spends only 7.9% of its budget in the syscall it is named after.
