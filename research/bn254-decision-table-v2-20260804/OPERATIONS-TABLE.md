# BN254 decision table, operations per transaction

c×pML reads as c pairing calls of p live Miller pairs each, never as the product · pML prepared pair (lines cached, subgroup paid at registration) · SC G2 subgroup check · FE final exponentiation · kMSM(np) k MSM syscalls over n points · GT(t) target multiexp · RED(c/p) PLONK multi-VK reduction over c contexts and p proofs · kLC(nt) k scalar inner products over n terms · kH(ns) k hash syscalls over n slices · CMP FP12 identity compare.

[nL+r] is how one call is charged, n full 8-wide IFMA lanes plus r pairs left over. No bracket means the call never fills a lane and every pair is charged singly. A remainder pair costs more than a pair inside a lane, which is why 8 pairs cost less than 7 and why a call is padded to a lane boundary where that is cheaper.

Padding is why a call can carry more pairs than another and still charge less. Compare [1L] against a bare 7ML.

| Scenario | Current | Batching syscalls (B5) | Batching + VK registry (B5) | Recursion over B5 | Current + Fp12 | Batching + Fp12 (B5) |
|---|---|---|---|---|---|---|
| 5 real Zolana Groth16 proofs — same VK | 5×4ML + 20SC + 5FE | 1×8ML[1L] + 8SC + FE + 8MSM(13p) + 7LC(15t) + 7H(47s) | 1×(5ML+3pML)[1L] + 5SC + FE + 8MSM(13p) + 7LC(15t) + 7H(47s) | 1×8ML[1L] + 8SC + FE + 6MSM(14p) + 10LC(12t) + 7H(40s) | 5×3ML + 15SC + 5FE + 1H(8s) + CMP | 1×9ML[1L+1] + 9SC + FE + 7MSM(12p) + 9LC(25t) + 7H(53s) + CMP |
| 2 real Zolana Groth16 proofs — distinct VKs | 2×4ML + 8SC + 2FE | 1×8ML[1L] + 8SC + FE + 8MSM(10p) + 4LC(4t) + 5H(35s) | 1×(2ML+6pML)[1L] + 2SC + FE + 8MSM(10p) + 4LC(4t) + 5H(35s) | 1×8ML[1L] + 8SC + FE + 6MSM(11p) + 7LC(9t) + 7H(34s) | 2×3ML + 6SC + 2FE + 2H(16s) + CMP | 1×8ML[1L] + 8SC + FE + 5MSM(7p) + GT(2t) + 6LC(6t) + 5H(35s) + CMP |
| 3 real Zolana Groth16 proofs — distinct VKs | 3×4ML + 12SC + 3FE | 1×16ML[2L] + 16SC + FE + 12MSM(15p) + 6LC(6t) + 7H(51s) | 1×(7ML+9pML)[2L] + 7SC + FE + 12MSM(15p) + 6LC(6t) + 7H(51s) | 1×8ML[1L] + 8SC + FE + 6MSM(12p) + 8LC(10t) + 7H(36s) | 3×3ML + 9SC + 3FE + 3H(24s) + CMP | 1×9ML[1L+1] + 9SC + FE + 8MSM(11p) + GT(3t) + 9LC(9t) + 7H(51s) + CMP |
| 2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 2×2ML + 4SC + 2FE + 15H(65s) | 1×2ML + 2SC + FE + 2MSM(40p) + RED(2c/2p) + 3H(7s) | 1×2pML + FE + 2MSM(40p) + RED(2c/2p) + 3H(7s) | 1×8ML[1L] + 8SC + FE + 6MSM(12p) + 8LC(10t) + 7H(36s) | 2×2ML + 4SC + 2FE + 15H(65s) + CMP | 1×2ML + 2SC + FE + 2MSM(40p) + RED(2c/2p) + 3H(7s) + CMP |
| 3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS | 3×2ML + 6SC + 3FE + 22H(96s) | 1×2ML + 2SC + FE + 2MSM(60p) + RED(3c/3p) + 4H(9s) | 1×2pML + FE + 2MSM(60p) + RED(3c/3p) + 4H(9s) | 1×8ML[1L] + 8SC + FE + 6MSM(15p) + 11LC(13t) + 7H(42s) | 3×2ML + 6SC + 3FE + 22H(96s) + CMP | 1×2ML + 2SC + FE + 2MSM(60p) + RED(3c/3p) + 4H(9s) + CMP |

## Poseidon, the application work beside verification

Measured on the unmodified zolana shielded pool, every call at arity 2 and so 786 CU. No cell above runs one.

The split is a partition. Statement compression folds the public statement into the single field element the verifier consumes, so it holds for any column keeping that convention and moves if the convention does. The rest is tree, nullifier and hash-chain work that no choice of pairing kernel touches.

| Legs | Calls | CU | Statement compression | State machine |
|---:|---:|---:|---:|---:|
| 1 | 58 | 45588 | 23 calls, 18078 CU | 35 calls, 27510 CU |
| 2 | 119 | 93534 | 46 calls, 36156 CU | 73 calls, 57378 CU |
| 3 | 181 | 142266 | 69 calls, 54234 CU | 112 calls, 88032 CU |

Aggregation stops at 3 legs. AggregateCircuitId::is_supported rejects batch above 3 on every rail, and no verifying key beyond b3 is compiled into the program.

Per-leg growth is not constant, so no row is extrapolated. The tree append costs what the leaf index makes it cost, not what the leg count does.
