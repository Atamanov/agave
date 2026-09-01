# Cryptographic syscall benchmarks, four backends

Reference: agave PR 14889 table, AMD EPYC 9354P. Measured here: AMD EPYC
9354P bare metal, the PR's hardware, one sealed campaign (sha256 manifest,
SMT sibling offline, pinned core, frequency telemetry, stock A/A rerun).
stock/ark06/mcl/narsil-v2 columns: agave's deployed codegen floor
(x86-64-v2), narsil-v2 engages AVX-512 IFMA through CPUID dispatch and
needs only the std feature. narsil column: the ceiling build
(target-cpu=native, codegen-units=1). mcl always runs its own prebuilt
asm. hash/curve25519/bls12_381/big_mod_exp rows: stock backend only.

Every CU@10ns cell is a 9354P hot-cache criterion estimate (median,
ceil), not a network-safe price. A schedule proposal still needs a
confidence bound, a safety margin, and a policy for hosts where narsil
falls back from IFMA.

The agave team plans to reprice syscalls at 10 ns/CU. The CU@10ns columns
are ceil-rounded post-repricing estimates per backend. '10ns effect
stock' is the price multiplier of repricing on the current backend
(above 1x the op gets more expensive). 'CU now / narsil@10ns' is how far
today's price sits above the narsil-backed repriced cost (above 1x the
op gets cheaper than today when repricing lands on narsil). Rows marked
^ price from the worst measured input variant per lane (the PR scalars
plus the adversarial sweep target), not the displayed PR-comparability
row.

### alt_bn128

| op | CU | PR 9354P ns | stock ns | ark06 ns | mcl ns | narsil-v2 ns | narsil ns | ns/CU stock | stock CU@10ns | ark06 CU@10ns | mcl CU@10ns | narsil-v2 CU@10ns | narsil CU@10ns | 10ns effect stock | CU now / narsil@10ns |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| g1_add | 334 | 5,500 | 5,360 | 5,211 | 3,112 | 1,927 | 1,544 | 16.05 | 536 | 522 | 312 | 193 | 155 | 1.60x | 2.16x |
| g2_add | 535 | 8,400 | 8,074 | 8,116 | 5,399 | 3,160 | 2,691 | 15.09 | 808 | 812 | 540 | 317 | 270 | 1.51x | 1.99x |
| g1_mul (r-1)^ | 3,840 | 77,500 | 74,417 | 68,375 | 37,973 | 4,370 | 3,370 | 19.38 | 8,212 | 7,482 | 3,843 | 4,212 | 3,712 | 2.14x | 1.03x |
| g2_mul (r-1)^ | 15,670 | 360,800 | 348,425 | 326,544 | 201,339 | 245,965 | 217,605 | 22.24 | 37,082 | 34,604 | 20,134 | 24,924 | 22,105 | 2.37x | 0.71x |
| g1_compress | 130 | 1,000 | 943 | 966 | 974 | 195 | 171 | 7.25 | 95 | 97 | 98 | 20 | 18 | 0.73x | 7.62x |
| g1_decompress | 498 | 8,100 | 7,828 | 7,878 | 7,186 | 12,338 | 9,648 | 15.72 | 783 | 788 | 719 | 1,234 | 965 | 1.57x | 0.52x |
| g2_compress | 186 | 2,000 | 1,954 | 2,022 | 1,948 | 297 | 275 | 10.50 | 196 | 203 | 195 | 30 | 28 | 1.05x | 6.76x |
| g2_decompress | 13,710 | 26,600 | 25,718 | 25,665 | 21,375 | 38,928 | 30,471 | 1.88 | 2,572 | 2,567 | 2,138 | 3,893 | 3,048 | 0.19x | 4.50x |
| pairing (n=1) | 36,673 | 808,000 | 757,699 | 679,014 | 550,974 | 258,095 | 234,770 | 20.66 | 75,770 | 67,902 | 55,098 | 25,810 | 23,477 | 2.07x | 1.56x |
| pairing (n=8) | 122,864 | 3,700,000 | 3,584,668 | 3,336,007 | 2,363,641 | 638,427 | 576,756 | 29.18 | 358,467 | 333,601 | 236,365 | 63,843 | 57,676 | 2.92x | 2.13x |
| pairing (n=112) | 1,403,416 | 45,100,000 | 43,701,801 | 40,857,194 | 29,641,859 | 6,287,620 | 5,660,298 | 31.14 | 4,370,181 | 4,085,720 | 2,964,186 | 628,763 | 566,030 | 3.11x | 2.48x |

### curve25519

| op | CU | PR 9354P ns | stock ns | ark06 ns | mcl ns | narsil-v2 ns | narsil ns | ns/CU stock | stock CU@10ns | ark06 CU@10ns | mcl CU@10ns | narsil-v2 CU@10ns | narsil CU@10ns | 10ns effect stock | CU now / narsil@10ns |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| edwards validate | 159 | 4,100 | 3,954 | - | - | - | - | 24.87 | 396 | - | - | - | - | 2.49x | - |
| edwards add | 473 | 12,300 | 11,665 | - | - | - | - | 24.66 | 1,167 | - | - | - | - | 2.47x | - |
| edwards mul | 2,177 | 40,500 | 39,112 | - | - | - | - | 17.97 | 3,912 | - | - | - | - | 1.80x | - |
| edwards msm (n=16) | 13,643 | 114,000 | 109,716 | - | - | - | - | 8.04 | 10,972 | - | - | - | - | 0.80x | - |
| edwards msm (n=512) | 389,611 | 2,940,000 | 2,926,336 | - | - | - | - | 7.51 | 292,634 | - | - | - | - | 0.75x | - |
| ristretto add | 521 | 13,100 | 12,817 | - | - | - | - | 24.60 | 1,282 | - | - | - | - | 2.46x | - |
| ristretto mul | 2,208 | 41,100 | 40,025 | - | - | - | - | 18.13 | 4,003 | - | - | - | - | 1.81x | - |
| ristretto msm (n=16) | 14,123 | 122,000 | 114,737 | - | - | - | - | 8.12 | 11,474 | - | - | - | - | 0.81x | - |

### bls12_381

| op | CU | PR 9354P ns | stock ns | ark06 ns | mcl ns | narsil-v2 ns | narsil ns | ns/CU stock | stock CU@10ns | ark06 CU@10ns | mcl CU@10ns | narsil-v2 CU@10ns | narsil CU@10ns | 10ns effect stock | CU now / narsil@10ns |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| g1 add | 128 | 4,400 | 4,245 | - | - | - | - | 33.16 | 425 | - | - | - | - | 3.32x | - |
| g1 mul | 4,627 | 157,000 | 152,800 | - | - | - | - | 33.02 | 15,281 | - | - | - | - | 3.30x | - |
| g1 validate | 1,565 | 52,900 | 51,681 | - | - | - | - | 33.02 | 5,169 | - | - | - | - | 3.30x | - |
| g1 decompress | 2,100 | 71,000 | 69,292 | - | - | - | - | 33.00 | 6,930 | - | - | - | - | 3.30x | - |
| g2 mul | 8,255 | 281,000 | 275,477 | - | - | - | - | 33.37 | 27,548 | - | - | - | - | 3.34x | - |
| g2 decompress | 3,050 | 103,000 | 100,591 | - | - | - | - | 32.98 | 10,060 | - | - | - | - | 3.30x | - |
| pairing (n=1) | 25,445 | 869,000 | 838,660 | - | - | - | - | 32.96 | 83,866 | - | - | - | - | 3.30x | - |
| pairing (n=8) | 116,606 | 3,970,000 | 3,846,389 | - | - | - | - | 32.99 | 384,639 | - | - | - | - | 3.30x | - |

### big_mod_exp

| op | CU | PR 9354P ns | stock ns | ark06 ns | mcl ns | narsil-v2 ns | narsil ns | ns/CU stock | stock CU@10ns | ark06 CU@10ns | mcl CU@10ns | narsil-v2 CU@10ns | narsil CU@10ns | 10ns effect stock | CU now / narsil@10ns |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| n=32 | 1,804 | 24,300 | 23,116 | - | - | - | - | 12.81 | 2,312 | - | - | - | - | 1.28x | - |
| n=64 | 5,949 | 52,400 | 49,047 | - | - | - | - | 8.24 | 4,905 | - | - | - | - | 0.82x | - |
| n=256 | 51,541 | 618,000 | 591,618 | - | - | - | - | 11.48 | 59,162 | - | - | - | - | 1.15x | - |
| full (256B) | 410,776 | 4,770,000 | 4,533,657 | - | - | - | - | 11.04 | 453,366 | - | - | - | - | 1.10x | - |
| reduce (n=512, exp=1) | 9,281 | 1,000 | 876 | - | - | - | - | 0.09 | 88 | - | - | - | - | 0.01x | - |

### hash sha256

| op | CU | PR 9354P ns | stock ns | ark06 ns | mcl ns | narsil-v2 ns | narsil ns | ns/CU stock | stock CU@10ns | ark06 CU@10ns | mcl CU@10ns | narsil-v2 CU@10ns | narsil CU@10ns | 10ns effect stock | CU now / narsil@10ns |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| base (len=0) | 85 | 92 | 89 | - | - | - | - | 1.05 | 9 | - | - | - | - | 0.10x | - |
| len=16 | 95 | 100 | 96 | - | - | - | - | 1.01 | 10 | - | - | - | - | 0.10x | - |
| len=128 | 149 | 170 | 166 | - | - | - | - | 1.11 | 17 | - | - | - | - | 0.11x | - |
| len=1024 | 597 | 652 | 646 | - | - | - | - | 1.08 | 65 | - | - | - | - | 0.11x | - |
| len=16384 | 8,277 | 8,900 | 8,883 | - | - | - | - | 1.07 | 889 | - | - | - | - | 0.11x | - |
| len=65536 | 32,853 | 35,240 | 35,268 | - | - | - | - | 1.07 | 3,527 | - | - | - | - | 0.11x | - |

### hash sha512

| op | CU | PR 9354P ns | stock ns | ark06 ns | mcl ns | narsil-v2 ns | narsil ns | ns/CU stock | stock CU@10ns | ark06 CU@10ns | mcl CU@10ns | narsil-v2 CU@10ns | narsil CU@10ns | 10ns effect stock | CU now / narsil@10ns |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| base (len=0) | 85 | 474 | 451 | - | - | - | - | 5.31 | 46 | - | - | - | - | 0.53x | - |
| len=16 | 95 | 489 | 461 | - | - | - | - | 4.85 | 47 | - | - | - | - | 0.48x | - |
| len=128 | 149 | 905 | 863 | - | - | - | - | 5.79 | 87 | - | - | - | - | 0.58x | - |
| len=1024 | 597 | 3,750 | 3,553 | - | - | - | - | 5.95 | 356 | - | - | - | - | 0.60x | - |
| len=16384 | 8,277 | 52,330 | 49,758 | - | - | - | - | 6.01 | 4,976 | - | - | - | - | 0.60x | - |
| len=65536 | 32,853 | 206,540 | 197,566 | - | - | - | - | 6.01 | 19,757 | - | - | - | - | 0.60x | - |

### hash keccak256

| op | CU | PR 9354P ns | stock ns | ark06 ns | mcl ns | narsil-v2 ns | narsil ns | ns/CU stock | stock CU@10ns | ark06 CU@10ns | mcl CU@10ns | narsil-v2 CU@10ns | narsil CU@10ns | 10ns effect stock | CU now / narsil@10ns |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| base (len=0) | 85 | 692 | 658 | - | - | - | - | 7.74 | 66 | - | - | - | - | 0.77x | - |
| len=16 | 95 | 706 | 674 | - | - | - | - | 7.09 | 68 | - | - | - | - | 0.71x | - |
| len=128 | 149 | 687 | 660 | - | - | - | - | 4.43 | 67 | - | - | - | - | 0.44x | - |
| len=1024 | 597 | 4,910 | 4,722 | - | - | - | - | 7.91 | 473 | - | - | - | - | 0.79x | - |
| len=16384 | 8,277 | 75,070 | 70,076 | - | - | - | - | 8.47 | 7,008 | - | - | - | - | 0.85x | - |
| len=65536 | 32,853 | 295,210 | 278,832 | - | - | - | - | 8.49 | 27,884 | - | - | - | - | 0.85x | - |

### hash blake3

| op | CU | PR 9354P ns | stock ns | ark06 ns | mcl ns | narsil-v2 ns | narsil ns | ns/CU stock | stock CU@10ns | ark06 CU@10ns | mcl CU@10ns | narsil-v2 CU@10ns | narsil CU@10ns | 10ns effect stock | CU now / narsil@10ns |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| base (len=0) | 85 | 126 | 121 | - | - | - | - | 1.43 | 13 | - | - | - | - | 0.14x | - |
| len=16 | 95 | 147 | 141 | - | - | - | - | 1.48 | 15 | - | - | - | - | 0.15x | - |
| len=128 | 149 | 200 | 193 | - | - | - | - | 1.29 | 20 | - | - | - | - | 0.13x | - |
| len=1024 | 597 | 1,080 | 1,066 | - | - | - | - | 1.79 | 107 | - | - | - | - | 0.18x | - |
| len=16384 | 8,277 | 2,660 | 2,625 | - | - | - | - | 0.32 | 263 | - | - | - | - | 0.03x | - |
| len=65536 | 32,853 | 9,970 | 9,873 | - | - | - | - | 0.30 | 988 | - | - | - | - | 0.03x | - |

### poseidon

| op | CU | PR 9354P ns | stock ns | ark06 ns | mcl ns | narsil-v2 ns | narsil ns | ns/CU stock | stock CU@10ns | ark06 CU@10ns | mcl CU@10ns | narsil-v2 CU@10ns | narsil CU@10ns | 10ns effect stock | CU now / narsil@10ns |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| n=1 | 603 | 22,210 | 21,426 | 21,680 | 21,356 | 11,559 | 8,938 | 35.53 | 2,143 | 2,168 | 2,136 | 1,156 | 894 | 3.55x | 0.67x |
| n=2 | 786 | 33,150 | 32,015 | 32,039 | 31,917 | 16,070 | 12,561 | 40.73 | 3,202 | 3,204 | 3,192 | 1,608 | 1,257 | 4.07x | 0.63x |
| n=3 | 1,091 | 46,030 | 44,305 | 44,350 | 44,196 | 20,665 | 14,365 | 40.61 | 4,431 | 4,435 | 4,420 | 2,067 | 1,437 | 4.06x | 0.76x |
| n=4 | 1,518 | 65,620 | 63,037 | 63,747 | 62,742 | 27,027 | 19,120 | 41.53 | 6,304 | 6,375 | 6,275 | 2,703 | 1,912 | 4.15x | 0.79x |
| n=5 | 2,067 | 85,180 | 82,695 | 82,300 | 81,971 | 32,903 | 21,470 | 40.01 | 8,270 | 8,231 | 8,198 | 3,291 | 2,148 | 4.00x | 0.96x |
| n=6 | 2,738 | 112,250 | 108,946 | 108,164 | 108,030 | 40,138 | 27,089 | 39.79 | 10,895 | 10,817 | 10,804 | 4,014 | 2,709 | 3.98x | 1.01x |
| n=7 | 3,531 | 139,740 | 136,863 | 136,092 | 134,828 | 47,260 | 29,967 | 38.76 | 13,687 | 13,610 | 13,483 | 4,727 | 2,997 | 3.88x | 1.18x |
| n=8 | 4,446 | 168,120 | 164,079 | 162,988 | 161,405 | 53,775 | 34,359 | 36.90 | 16,408 | 16,299 | 16,141 | 5,378 | 3,436 | 3.69x | 1.29x |
| n=9 | 5,483 | 195,040 | 187,869 | 188,051 | 186,047 | 59,700 | 36,056 | 34.26 | 18,787 | 18,806 | 18,605 | 5,970 | 3,606 | 3.43x | 1.52x |
| n=10 | 6,642 | 247,770 | 240,987 | 240,532 | 237,954 | 70,867 | 45,868 | 36.28 | 24,099 | 24,054 | 23,796 | 7,087 | 4,587 | 3.63x | 1.45x |
| n=11 | 7,923 | 268,080 | 258,934 | 259,173 | 256,439 | 75,272 | 46,030 | 32.68 | 25,894 | 25,918 | 25,644 | 7,528 | 4,603 | 3.27x | 1.72x |
| n=12 | 9,326 | 330,540 | 320,410 | 320,383 | 320,441 | 87,103 | 53,971 | 34.36 | 32,042 | 32,039 | 32,045 | 8,711 | 5,398 | 3.44x | 1.73x |

### appendix, stock A/A dispersion (same lane rerun)

| op | stock ns | stock-aa ns | delta |
|---|---|---|---|
| g1_add | 5,360 | 5,373 | +0.26% |
| g2_add | 8,074 | 8,078 | +0.05% |
| g1_mul (r-1) | 74,417 | 74,462 | +0.06% |
| g2_mul (r-1) | 348,425 | 348,666 | +0.07% |

### groth16 (added rows, precomputed-coefficient byte-level syscall trace, VM overhead excluded)

| op | CU* | current ns | ark06 ns | mcl ns | narsil ns | ns/CU current | current CU@10ns | ark06 CU@10ns | mcl CU@10ns | narsil CU@10ns | CU now / narsil@10ns |
|---|---|---|---|---|---|---|---|---|---|---|---|
| verify (1 input) | 77,786 | 2,085,726 | 2,074,972 | 1,354,074 | 648,994 | 26.81 | 208,573 | 207,498 | 135,408 | 64,900 | 1.20x |
| verify (9 inputs) | 111,178 | 2,740,301 | 2,711,276 | 1,615,490 | 898,336 | 24.65 | 274,031 | 271,128 | 161,550 | 89,834 | 1.24x |
| RLC aggregate (n=2) | 113,473 | 2,901,338 | 2,879,099 | 1,823,559 | 973,722 | 25.57 | 290,134 | 287,910 | 182,356 | 97,373 | 1.17x |
| RLC aggregate (n=3) | 133,800 | 3,384,982 | 3,355,593 | 2,141,546 | 1,136,975 | 25.30 | 338,499 | 335,560 | 214,155 | 113,698 | 1.18x |

\* derived, the sum of the trace's current syscall charges
