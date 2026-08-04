# Vendored MCL subset

Upstream: https://github.com/herumi/mcl
Commit: e107c70e814aaa3079fbb6fd630a8c48693c4c27
Vendored: 2026-07-19

## Subset

The subset includes the upstream `COPYRIGHT`, the full public header trees, and two source files:

- `src/fp.cpp` provides the `mclBn*` C API through `bn_c_impl.hpp`.
- `src/bn_c256.cpp` matches the upstream 256-bit source list.

The selected headers support the portable 256-bit build. The build excludes assembly, LLVM fast paths, JIT code, tests, samples, and other libraries.

## Prebuilt archive

Set `MCL_LIB_DIR` to a directory that contains `libmcl.a` to use a prebuilt archive. The build script checks the directory, the file type, and the Unix archive header. The archive must use the pinned commit above and this ABI:

- `MCL_FP_BIT=256`
- `MCL_FR_BIT=256`
- `MCL_SIZEOF_UNIT=8`
- `BN_SNARK1`

The safe API calls `mclBn_init(4, 44)` before it uses MCL. This call checks the compiled MCL ABI. It cannot check the source commit. Use the vendored build when the archive source is not known.

## Re-vendoring

From a fresh checkout of the pinned commit:

```
git clone https://github.com/herumi/mcl mcl && cd mcl
git checkout e107c70e814aaa3079fbb6fd630a8c48693c4c27
```

Copy `COPYRIGHT`, `include/`, and the required `src/` files into `vendor/mcl/`. Preserve their paths and code. Normalize text files to LF. Keep all build options in `build.rs`.
