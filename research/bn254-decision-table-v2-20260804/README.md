# Reproducible BN254 decision campaign

> Two columns of `TRANSACTION-TABLE.md` do not measure the features they name.
> "Recursion over B5" verifies a fixed-arity payload in a synthetic guest, not
> `aggregate_transact`; "Batching + VK registry (B5)" models a keyset registry
> against a stale prepared-blob size. Both are owned by other sessions and
> measured independently there. See `CONFORMANCE-PLAN.md` before quoting either.
> The remaining four columns and the whole charge schedule are unaffected.

Run the complete campaign through one public entrypoint:

```sh
./cargo bench -p solana-bn254-decision-bench --bench decision_table -- \
  --campaign /absolute/path/to/campaign.json \
  --output /absolute/path/to/empty-output-directory
```

With `tariff_source.kind: "fresh"`, this command builds the B1–B5 probe
executables in parallel in isolated target directories, then measures the eight
pricing families sequentially to prevent cross-load contamination. Each shape
is measured directly; ratio substitution and the old B1 column aliases are
schema errors. The B5 executable must attest both its compile-time IFMA cfg and
an observed eight-pair batch8 dispatch. Final mode also requires local x86_64
AVX512IFMA runtime detection. `tariff_source.kind: "pinned"` instead consumes a
sealed exact-shape tariff without changing its digest.

The executor then supplies all 30 full-transaction cells. `command` sends one
strict execution request per cell to a transaction adapter and accepts only a
successful full Agave transaction with a runtime-observed operation trace.
`measurements` consumes a sealed 30-cell measurement bundle.
`deterministic_estimate` consumes a sealed 30-cell, in-tree-host-observed
non-core residual contract and reconstructs each proposed-pricing total from
the newly measured exact-shape tariffs. Estimates are explicitly labeled and
cannot masquerade as current-runtime measurements; missing residuals, shapes,
digests, or observations hard-fail.

Before execution, the bench authenticates the Zolana source manifest, dirty
path list, proving-key lock and prefix, every proving key, all 60 fixture files,
and the independent 5-by-6 operation-count contract. It writes exactly:

- `decision-table.canonical.json`
- `exact-shape-tariff.json`
- `REPORT.md`, containing exactly the three requested report sections

`expected-counts.v1.json` is the independent-checker contract. Current + Fp12
remains independent per proof: Groth16 performs `n` three-pair maps and PLONK
performs `n` two-pair maps, with `n` final exponentiations and no MSM syscall.
Only Batching + Fp12 performs one folded map and folded MSMs.

## Seals

`cargo test -p solana-bn254-decision-bench --test seals` recomputes every
committed digest from the bytes it names. Run it after any edit under this
directory.

**A rename never edits a sealed artifact.** Rename code only. If a rename does
reach a sealed file, restore the file; do not re-seal it. A recomputed digest
stops describing the bytes the exporter produced and starts describing whatever
is in the tree, which is how provenance is lost. The old spelling inside these
artifacts is the exported evidence, not a leftover. Four separate seals have
been corrupted this way already.

`recursion-v2/manifest.json` records the Zolana manifest it was built from at an
absolute path that resolves on no current machine. Read `fixtures-v3/manifest.json`
instead; it is that manifest, committed, byte for byte. The recorded path stays
because the manifest is frozen by its own digest.
