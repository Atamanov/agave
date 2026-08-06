# BN254 decision table, where the compute units go

Syscall CU is the charge a validator meters. sBPF is everything the
guest program spends preparing it. A syscall column whose share is low
is measuring its own wrapper.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---:|---:|---:|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | 462460 / 7409 = 98.4% | 111967 / 11080 = 90.9% | 108541 / 11669 = 90.2% | 53247 / 10226 = 83.8% | 321063 / 21963 = 93.5% | 117161 / 11910 = 90.7% |
| 2 real Zolana Groth16 proofs — distinct VKs | 184984 / 3173 = 98.3% | 66357 / 7187 = 90.2% | 59505 / 8056 = 88.0% | 52005 / 9182 = 84.9% | 129054 / 10019 = 92.7% | 71350 / 8428 = 89.4% |
| 3 real Zolana Groth16 proofs — distinct VKs | 277476 / 4585 = 98.3% | 108398 / 10132 = 91.4% | 98120 / 11374 = 89.6% | 52419 / 9468 = 84.7% | 193581 / 14619 = 92.9% | 97954 / 11617 = 89.3% |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 276223 / 247818 = 52.7% | 46243 / 11352 = 80.2% | 40605 / 11887 = 77.3% | 52419 / 9468 = 84.7% | 250087 / 248058 = 50.2% | 46243 / 11414 = 80.2% |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 414272 / 372045 = 52.6% | 61153 / 15929 = 79.3% | 55515 / 16517 = 77.0% | 53661 / 10509 = 83.6% | 375068 / 372393 = 50.1% | 61153 / 15991 = 79.2% |

Each cell is `syscall CU / sBPF CU = syscall share`.

A syscall-bearing column below 25.0% is reported as a structural breach.

## What the hash syscalls contribute

`sol_keccak256` and `sol_sha256` are metered syscall charges, so they
belong in the numerator. They are also the one family that moved from
the residual without any program changing, so the share is given both
ways. The second number is what the cell reads if the hash charge is
returned to the guest side.

| Scenario | Column | Hash CU | Share | Share with hash as sBPF |
|---|---|---:|---:|---:|
| 5 real Zolana Groth16 proofs — same VK | Batching syscalls (B5) | 1859 | 90.9% | 89.4% |
| 5 real Zolana Groth16 proofs — same VK | Batching + VK registry (B5) | 1859 | 90.2% | 88.7% |
| 5 real Zolana Groth16 proofs — same VK | Batching + Fp12 (B5) | 2123 | 90.7% | 89.1% |
| 2 real Zolana Groth16 proofs — distinct VKs | Batching syscalls (B5) | 1473 | 90.2% | 88.2% |
| 2 real Zolana Groth16 proofs — distinct VKs | Batching + VK registry (B5) | 1473 | 88.0% | 85.8% |
| 2 real Zolana Groth16 proofs — distinct VKs | Batching + Fp12 (B5) | 1473 | 89.4% | 87.5% |
| 3 real Zolana Groth16 proofs — distinct VKs | Batching syscalls (B5) | 2147 | 91.4% | 89.6% |
| 3 real Zolana Groth16 proofs — distinct VKs | Batching + VK registry (B5) | 2147 | 89.6% | 87.6% |
| 3 real Zolana Groth16 proofs — distinct VKs | Batching + Fp12 (B5) | 2147 | 89.3% | 87.4% |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | Batching syscalls (B5) | 1171 | 80.2% | 78.2% |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | Batching + VK registry (B5) | 1171 | 77.3% | 75.1% |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | Batching + Fp12 (B5) | 1171 | 80.2% | 78.1% |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | Batching syscalls (B5) | 1694 | 79.3% | 77.1% |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | Batching + VK registry (B5) | 1694 | 77.0% | 74.7% |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | Batching + Fp12 (B5) | 1694 | 79.2% | 77.0% |

The lowest syscall-bearing share is 74.7% once the hash charge is returned to the guest side.

No breach.
