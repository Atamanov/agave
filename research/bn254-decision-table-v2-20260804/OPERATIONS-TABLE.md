# BN254 decision table, operations per transaction

ML live Miller pair · pML prepared pair (lines cached, subgroup paid at registration) · SC G2 subgroup check · FE final exponentiation · kMSM(np) k MSM syscalls over n points · GT(t) target multiexp · CMP FP12 identity compare. ⁸ marks a call the 8-wide IFMA kernel takes.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---|---|---|---|---|---|
| 5 real Zolana Groth16 proofs — same VK | 20ML + 20SC + 5FE | 8ML⁸ + 8SC + FE + 8MSM(13p) | 5ML⁸ + 3pML⁸ + 5SC + FE + 8MSM(13p) | 6ML + 6SC + FE + 6MSM(14p) | 15ML + 15SC + 5FE + CMP | 7ML + 7SC + FE + 7MSM(12p) + CMP |
| 2 real Zolana Groth16 proofs — distinct VKs | 8ML + 8SC + 2FE | 8ML⁸ + 8SC + FE + 8MSM(10p) | 2ML⁸ + 6pML⁸ + 2SC + FE + 8MSM(10p) | 6ML + 6SC + FE + 6MSM(11p) | 6ML + 6SC + 2FE + CMP | 6ML + 6SC + FE + 5MSM(7p) + GT(2t) + CMP |
| 3 real Zolana Groth16 proofs — distinct VKs | 12ML + 12SC + 3FE | 12ML⁸ + 12SC + FE + 12MSM(15p) | 3ML⁸ + 9pML⁸ + 3SC + FE + 12MSM(15p) | 6ML + 6SC + FE + 6MSM(12p) | 9ML + 9SC + 3FE + CMP | 9ML⁸ + 9SC + FE + 8MSM(11p) + GT(3t) + CMP |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 4ML + 4SC + 2FE | 2ML + 2SC + FE + 2MSM(40p) | 2pML + FE + 2MSM(40p) | 6ML + 6SC + FE + 6MSM(12p) | 4ML + 4SC + 2FE + CMP | 2ML + 2SC + FE + 2MSM(40p) + CMP |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 6ML + 6SC + 3FE | 2ML + 2SC + FE + 2MSM(60p) | 2pML + FE + 2MSM(60p) | 6ML + 6SC + FE + 6MSM(15p) | 6ML + 6SC + 3FE + CMP | 2ML + 2SC + FE + 2MSM(60p) + CMP |
