# BN254 backend campaign, sealed results

AMD EPYC 9354P bare metal, one sealed criterion campaign, results root
sealed-20260829T1835. Lanes stock, ark06, mcl, and narsil-v2 build at the
agave x86-64-v2 floor, narsil is the target-cpu=native ceiling. The backends
live on the solana-sdk fork branch alex/bn254-backend-select and one is
selected per build with SOLANA_BN254_BACKEND. This branch carries the bench
targets and the patch entries that bind them.

- final-table.md, the PR 14889 reference table with measured lane columns
- agave-rows-table.md, byte level four lane rows with derived CU pricing
- summary.md, per lane medians, ratios, A/A dispersion, pairing slope fits
- manifest.txt, host state, revisions, flags, script and binary hashes
- MANIFEST.sha256, per file digests of the sealed results tree
- sealed-archive.sha256, outer digest of the full evidence tarball

The raw tree with criterion samples, logs, and telemetry is the tarball named
in sealed-archive.sha256, kept outside the repository for size.
