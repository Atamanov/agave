# Vendored mcl subset

Upstream: https://github.com/herumi/mcl
Commit: e107c70e814aaa3079fbb6fd630a8c48693c4c27
Vendored: 2026-07-19

## Subset

The minimal file set that compiles the BN_SNARK1 (alt_bn128) 256-bit C API
as one portable no-asm translation unit:

- `include/mcl/**`, `include/cybozu/**`: the public header trees, whole.
- `src/fp.cpp`: the single library translation unit; at this pin it also
  compiles the whole `mclBn*` C API via `bn_c_impl.hpp`.
- `src/bn_c256.cpp`: empty build-system compat stub, kept for fidelity with
  the upstream Makefile's `MCL_SUF=256` source list.
- `src/*.hpp` reachable from `fp.cpp` with our build defines: bint_impl,
  bint_switch, bn_c_impl, cast, compress, conversion_impl, fp_tower_impl,
  glv, llvm_proto, low_func, map_impl, mapto_wb19, msm, pairing_impl.
- `src/xbyak/*.h`: included unconditionally by `bint_impl.hpp` on x86-64
  hosts (only the `Cpu` cpuid class is used under `MCL_DONT_USE_XBYAK`).

Excluded: `src/asm/`, `src/*.ll` (LLVM-IR fast paths), `ffi/`, `test/`,
`sample/`, docs, `she_*`/`ecdsa_*` sources, `fp_generator.hpp` (JIT, dead
under `MCL_DONT_USE_XBYAK`), `fp_static_code.hpp` (dead without
`MCL_STATIC_CODE`), `avx512.hpp`/`msm_avx*` (dead with `MCL_MSM=0`),
`sqr256_wasm.hpp` (wasm only), `llvm_gen.hpp` (generator tooling).

## Re-vendoring

From a fresh checkout of the pinned commit:

```
git clone https://github.com/herumi/mcl mcl && cd mcl
git checkout e107c70e814aaa3079fbb6fd630a8c48693c4c27
```

then copy `include/` whole and the `src/` files listed above into
`vendor/mcl/`, preserving paths. No file is patched; the build flags live
entirely in `build.rs`.
