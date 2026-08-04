//! x86-64 (BMI2+ADX) Montgomery backend using the generated kernel leaves.
//!
//! The assembly is generated at build time from the readable schedule DSL in
//! `build/schedule.rs` and verified by `tests/kernelgen_verify.rs`; see
//! ADR 0001 (build-time amendment). Inspect a copy with
//! `HELIUS_DUMP_ASM=<absolute dir> cargo build`. This module exists only
//! when `build.rs` emitted `helius_mont4_x86_64_adx`, i.e. the target is
//! x86-64 Linux with `bmi2` and `adx` in the compile-time target features.
//! Anything else uses the portable tier -- never a silent runtime fallback.

use crate::fp::Fp;
#[cfg(any(
    test,
    not(helius_fp6_active),
    not(helius_fp12_sqr_active),
    not(helius_fp12_034_active),
))]
use crate::fp::sos::Fp2Product;

// Arithmetic constants remain typed Rust data; the assembly owns only the
// instruction schedule. `repr(C)` plus the assertions pins the tiny FFI view.
#[repr(C)]
struct Mont4Constants {
    modulus: [u64; 4],
    negative_inverse: u64,
}

static MONT4_CONSTANTS: Mont4Constants = Mont4Constants {
    modulus: crate::consts::P,
    negative_inverse: crate::consts::P_INV,
};

const _: () = {
    assert!(core::mem::size_of::<Mont4Constants>() == 5 * core::mem::size_of::<u64>());
    assert!(core::mem::align_of::<Mont4Constants>() == core::mem::align_of::<u64>());
    assert!(
        core::mem::offset_of!(Mont4Constants, negative_inverse) == 4 * core::mem::size_of::<u64>()
    );
};

/// Extended table of the fp6 kernel: the mont4 shape plus the xi-scaling
/// quotient estimate `mu = floor(2^310/p)`. A separate static so the mont4
/// contract stays untouched.
#[cfg(any(
    test,
    helius_fp6_active,
    helius_fp12_034_active,
    helius_fp12_sqr_active,
    helius_cyc_sqr_active,
    helius_fp12_mul_active,
))]
#[repr(C)]
struct Fp6MulConstants {
    modulus: [u64; 4],
    negative_inverse: u64,
    mu: u64,
}

#[cfg(any(
    test,
    helius_fp6_active,
    helius_fp12_034_active,
    helius_fp12_sqr_active,
    helius_cyc_sqr_active,
    helius_fp12_mul_active,
))]
static FP6_MUL_CONSTANTS: Fp6MulConstants = Fp6MulConstants {
    modulus: crate::consts::P,
    negative_inverse: crate::consts::P_INV,
    mu: crate::consts::P_MU_310,
};

#[cfg(any(
    test,
    helius_fp6_active,
    helius_fp12_034_active,
    helius_fp12_sqr_active,
    helius_cyc_sqr_active,
    helius_fp12_mul_active,
))]
const _: () = {
    assert!(core::mem::size_of::<Fp6MulConstants>() == 6 * core::mem::size_of::<u64>());
    assert!(core::mem::offset_of!(Fp6MulConstants, negative_inverse) == 32);
    assert!(core::mem::offset_of!(Fp6MulConstants, mu) == 40);
};

// Kernel-ABI layout invariant: Fp6 is 24 contiguous limbs in component
// order c0.re, c0.im, c1.re, c1.im, c2.re, c2.im (repr(C) on Fp6/Fp2/Fp).
const _: () = {
    use crate::fp2::Fp2;
    use crate::fp6::Fp6;
    assert!(core::mem::size_of::<Fp6>() == 24 * core::mem::size_of::<u64>());
    assert!(core::mem::align_of::<Fp6>() == core::mem::align_of::<u64>());
    assert!(core::mem::offset_of!(Fp6, c0) == 0);
    assert!(core::mem::offset_of!(Fp6, c1) == 64);
    assert!(core::mem::offset_of!(Fp6, c2) == 128);
    assert!(core::mem::size_of::<Fp2>() == 8 * core::mem::size_of::<u64>());
    assert!(core::mem::offset_of!(Fp2, c0) == 0);
    assert!(core::mem::offset_of!(Fp2, c1) == 32);
};

// Kernel-ABI layout invariant: Fp12 is 48 contiguous limbs, c0 then c1
// (repr(C) on Fp12; the Fp6/Fp2/Fp layers are pinned above).
const _: () = {
    use crate::fp2::Fp2;
    use crate::fp12::Fp12;
    assert!(core::mem::size_of::<Fp12>() == 48 * core::mem::size_of::<u64>());
    assert!(core::mem::align_of::<Fp12>() == core::mem::align_of::<u64>());
    assert!(core::mem::offset_of!(Fp12, c0) == 0);
    assert!(core::mem::offset_of!(Fp12, c1) == 192);
    // The wrapper stages the three sparse coefficients as [Fp2; 3].
    assert!(core::mem::size_of::<[Fp2; 3]>() == 24 * core::mem::size_of::<u64>());
};

/// Debug-build check of the canonical-input half of a kernel contract.
///
/// `components(n): a, b` views each operand as `n` contiguous `[u64; 4]`
/// components (the repr(C) layouts pinned by the const assertions above)
/// and requires every component < p -- the Fp invariant the mont-shaped
/// leaves need. `at_most_p: x, y` takes `&[u64; 4]` operands directly and
/// admits p itself -- the SoS bound (`negp(0) == p` is a legal row).
#[cfg(any(
    test,
    helius_sosd2_active,
    helius_sosd6_active,
    helius_fp6_active,
    helius_fp12_034_active,
    helius_fp12_sqr_active,
    helius_cyc_sqr_active,
    helius_fp12_mul_active,
))]
macro_rules! debug_assert_canonical {
    (components($count:literal): $($operand:expr),+ $(,)?) => {{
        // Compile-time guard: each operand's byte size must equal $count
        // contiguous [u64; 4] components, so a miscounted call site fails to
        // build rather than reinterpreting memory in the cast below. Fires in
        // every build, not only under debug_assertions.
        fn assert_component_bytes<T, const COUNT: usize>(_operand: &T) {
            const { assert!(core::mem::size_of::<T>() == COUNT * 32) };
        }
        $(assert_component_bytes::<_, $count>($operand);)+
        #[cfg(debug_assertions)]
        for operand in [$($operand),+] {
            // SAFETY: the operand's repr(C) layout is $count contiguous
            // [u64; 4] components, size-checked above and at the top of this
            // module.
            let components = unsafe { &*(operand as *const _ as *const [[u64; 4]; $count]) };
            for component in components {
                debug_assert!(!crate::limb::gte(component, &crate::consts::P));
            }
        }
    }};
    (at_most_p: $($operand:expr),+ $(,)?) => {
        #[cfg(debug_assertions)]
        for operand in [$($operand),+] {
            debug_assert!(!crate::limb::gt(operand, &crate::consts::P));
        }
    };
}

unsafe extern "C" {
    fn helius_mont4_mul_x86(
        z: *mut u64,
        x: *const u64,
        y: *const u64,
        constants: *const Mont4Constants,
    );
    fn helius_mont4_sqr_x86(
        z: *mut u64,
        x: *const u64,
        y: *const u64,
        constants: *const Mont4Constants,
    );
    fn helius_sos_x86(
        z: *mut u64,
        pairs: *const *const u64,
        pair_count: u64,
        constants: *const Mont4Constants,
    );
    #[cfg(any(test, helius_sosd2_active))]
    fn helius_sosd2_small_x86(
        z: *mut u64,
        x0: *const u64,
        x1: *const u64,
        y0: *const u64,
        y1: *const u64,
        constants: *const Mont4Constants,
    );
    #[cfg(any(
        test,
        all(
            helius_sosd6_active,
            any(
                not(helius_fp6_active),
                not(helius_fp12_sqr_active),
                not(helius_fp12_034_active),
            ),
        ),
    ))]
    fn helius_sosd6_x86(z: *mut u64, stage: *mut u64, constants: *const Mont4Constants);
    #[cfg(any(test, helius_fp6_active))]
    fn helius_fp6_mul_x86(
        z: *mut u64,
        a: *const u64,
        b: *const u64,
        constants: *const Fp6MulConstants,
    );
    #[cfg(any(test, helius_fp12_034_active))]
    fn helius_fp12_034_x86(
        z: *mut u64,
        f: *const u64,
        c: *const u64,
        constants: *const Fp6MulConstants,
    );
    #[cfg(any(test, helius_fp12_sqr_active))]
    fn helius_fp12_sqr_x86(z: *mut u64, f: *const u64, constants: *const Fp6MulConstants);
    #[cfg(any(test, helius_cyc_sqr_active))]
    fn helius_cyc_sqr_x86(z: *mut u64, f: *const u64, constants: *const Fp6MulConstants);
    #[cfg(any(test, helius_fp12_mul_active))]
    fn helius_fp12_mul_x86(
        z: *mut u64,
        a: *const u64,
        b: *const u64,
        constants: *const Fp6MulConstants,
    );
}

/// Whole Fp12 product through the lazy double-width leaf: mcl's operation
/// shape (54 raw 4x4 products + 12 Montgomery reductions -- three
/// Fp6Dbl::mulPre plus the v-shifted assembly, cross terms held as 512-bit
/// values mod p*2^256) where the composed Fp6-Karatsuba path pays 108
/// products and 18 reductions. Runs 60 times per final exponentiation plus
/// once per Miller loop.
///
/// Kernel contract: `f` is a readable and writable, 8-byte-aligned 384-byte
/// array of canonical residues (every Fp < p; the Fp invariant); `rhs` is a
/// readable such array. The kernel updates `f` in place (`z == a`, the
/// production MulAssign shape): it stages both operands into its frame
/// before any output store, so no store can alias a live operand (`z == b`
/// and `a == b` are equally allowed by the leaf). All 48 output limbs are
/// canonical on return. The leaf saves every callee-saved register it uses,
/// keeps rsp 8-mod-16 aligned as on entry, and neither calls Rust nor
/// unwinds.
// Dispatched by default on Intel targets, opt-in elsewhere (build.rs
// HELIUS_FP12_MUL_ASM: Zen 4's latency chain dislikes the serial staging);
// always covered by the leaf differential tests.
#[inline(never)]
#[cfg(any(test, helius_fp12_mul_active))]
pub(crate) fn fp12_mul_assign(f: &mut crate::fp12::Fp12, rhs: &crate::fp12::Fp12) {
    debug_assert_canonical!(components(12): &*f, rhs);
    unsafe {
        // SAFETY: the repr(C) Fp12 references satisfy the complete kernel
        // contract above (canonical inputs are the Fp invariant); z == a is
        // the contract's in-place shape. The assembly initializes all 384
        // output bytes and cannot retain any pointer.
        helius_fp12_mul_x86(
            f as *mut crate::fp12::Fp12 as *mut u64,
            f as *const crate::fp12::Fp12 as *const u64,
            rhs as *const crate::fp12::Fp12 as *const u64,
            &FP6_MUL_CONSTANTS,
        );
    }
}

/// Whole Fp12 square through the lazy double-width leaf: mcl's operation
/// shape (36 raw 4x4 products + 12 Montgomery reductions, cross terms held
/// as 512-bit values mod p*2^256) where the composed SoS path pays 72
/// products (flattened to six sosd6 rows; the earlier 84-product body is now
/// the `#[cfg(test)]` differential reference). Runs 63 times per Miller loop
/// plus the final-exp squares that are not cyclotomic.
///
/// Kernel contract: `f` is a readable and writable, 8-byte-aligned 384-byte
/// array of canonical residues (every Fp < p; the Fp invariant). The kernel
/// updates `f` in place (`z == f`): it stages all of `f` into its frame
/// before any output store, so no store can alias a live operand. All 48
/// output limbs are canonical on return. The leaf saves every callee-saved
/// register it uses, keeps rsp 8-mod-16 aligned as on entry, and neither
/// calls Rust nor unwinds.
// Dispatched by default on Intel targets, opt-in elsewhere (build.rs
// HELIUS_FP12_SQR_ASM: -6% Miller on Granite Rapids, neutral on Zen 4);
// always covered by the leaf differential tests.
#[inline(never)]
#[cfg(any(test, helius_fp12_sqr_active))]
pub(crate) fn fp12_sqr_assign(f: &mut crate::fp12::Fp12) {
    debug_assert_canonical!(components(12): &*f);
    unsafe {
        // SAFETY: the repr(C) Fp12 reference satisfies the complete kernel
        // contract above (canonical inputs are the Fp invariant); z == f is
        // the contract's in-place shape. The assembly initializes all 384
        // output bytes and cannot retain any pointer.
        helius_fp12_sqr_x86(
            f as *mut crate::fp12::Fp12 as *mut u64,
            f as *const crate::fp12::Fp12 as *const u64,
            &FP6_MUL_CONSTANTS,
        );
    }
}

/// Granger-Scott cyclotomic square through the lazy double-width leaf:
/// mcl's operation shape (three lazy Fp4 squares of two Fp2Dbl::sqrPre
/// products each = 18 raw 4x4 products + 12 Montgomery reductions, with the
/// z-combines single-width on the reduced values) where the composed path
/// pays 36 products through the fp4_square dispatches. Runs 192 times per
/// final exponentiation, all on the latency-critical pow_x dependent chain.
/// Computes the composed `cyclotomic_square` formula bit for bit on any
/// canonical input; the result equals `f^2` exactly on the cyclotomic
/// subgroup (the Granger-Scott precondition, as for the composed path).
///
/// Kernel contract: `f` is a readable and writable, 8-byte-aligned 384-byte
/// array of canonical residues (every Fp < p; the Fp invariant). The kernel
/// updates `f` in place (`z == f`): it stages all of `f` into its frame
/// before any output store, so no store can alias a live operand. All 48
/// output limbs are canonical on return. The leaf saves every callee-saved
/// register it uses, keeps rsp 8-mod-16 aligned as on entry, and neither
/// calls Rust nor unwinds.
// Dispatched by default on every target (build.rs HELIUS_CYC_SQR_ASM=0
// restores the composed path): the one lazy leaf that wins on both microarchs;
// always covered by the leaf differential tests.
#[inline(never)]
#[cfg(any(test, helius_cyc_sqr_active))]
pub(crate) fn cyc_sqr_assign(f: &mut crate::fp12::Fp12) {
    debug_assert_canonical!(components(12): &*f);
    unsafe {
        // SAFETY: the repr(C) Fp12 reference satisfies the complete kernel
        // contract above (canonical inputs are the Fp invariant); z == f is
        // the contract's in-place shape. The assembly initializes all 384
        // output bytes and cannot retain any pointer.
        helius_cyc_sqr_x86(
            f as *mut crate::fp12::Fp12 as *mut u64,
            f as *const crate::fp12::Fp12 as *const u64,
            &FP6_MUL_CONSTANTS,
        );
    }
}

/// Whole sparse Fp12 product `f *= c0 + c3*w + c4*v*w` (the Miller loop's
/// per-line update, arkworks `mul_by_034`) through the dedicated leaf: six
/// dual-lane T = 6 sums of products with the xi = 9 + u scalings of c3/c4
/// computed in-kernel. Replaces, per call, the composed path's six sosd6
/// dispatches (twelve `helius_sos_x86` calls with their call/prologue tax
/// and 144 pointer-table stores, or six sosd6-leaf calls on the AMD default),
/// eighteen `negp` temporaries, and two Rust `mul_by_nonresidue` evaluations.
///
/// Kernel contract: `f` is a readable and writable, 8-byte-aligned 384-byte
/// array of canonical residues (every Fp < p; the Fp invariant); the
/// coefficients are staged here as a contiguous `[Fp2; 3]` (192 bytes,
/// canonical). The kernel updates `f` in place (`z == f`): it stages all of
/// `f` into its frame before the first output store, so no output can
/// alias a live operand. All 48 output limbs are canonical on return. The
/// leaf saves every callee-saved register it uses, keeps rsp 8-mod-16
/// aligned as on entry, and neither calls Rust nor unwinds.
// Dispatched by default on Intel targets, opt-in elsewhere (build.rs
// HELIUS_FP12_034_ASM: Zen 4 store ports favor the composed path); always
// covered by the leaf differential tests.
#[inline(never)]
#[cfg(any(test, helius_fp12_034_active))]
pub(crate) fn fp12_034_assign(
    f: &mut crate::fp12::Fp12,
    c0: &crate::fp2::Fp2,
    c3: &crate::fp2::Fp2,
    c4: &crate::fp2::Fp2,
) {
    let coefficients = [*c0, *c3, *c4];
    debug_assert_canonical!(components(12): &*f);
    debug_assert_canonical!(components(6): &coefficients);
    unsafe {
        // SAFETY: the repr(C) Fp12 reference and the staged coefficients
        // satisfy the complete kernel contract above (canonical inputs are
        // the Fp invariant); z == f is the contract's in-place shape. The
        // assembly initializes all 384 output bytes and cannot retain any
        // pointer.
        helius_fp12_034_x86(
            f as *mut crate::fp12::Fp12 as *mut u64,
            f as *const crate::fp12::Fp12 as *const u64,
            coefficients.as_ptr() as *const u64,
            &FP6_MUL_CONSTANTS,
        );
    }
}

/// Whole-Fp6 product `a * b` through the dedicated leaf: three dual-lane
/// T = 6 sums of products with the xi = 9 + u scaling of b1/b2 computed
/// in-kernel. Replaces, per call, the composed path's three sosd6 dispatches
/// (six `helius_sos_x86` calls with their call/prologue tax and 72
/// pointer-table stores, or three sosd6-leaf calls on the AMD default), nine
/// `negp` temporaries, and two Rust `mul_by_nonresidue` evaluations --
/// frontend mass the Intel scalar profile showed dominating the composed path.
///
/// Kernel contract: `a` and `b` are readable, 8-byte-aligned 192-byte
/// arrays of canonical residues (every Fp < p; the Fp invariant). They may
/// alias each other. `z` receives 24 limbs (repr(C) Fp6 order), all
/// initialized and canonical on return. The leaf saves every callee-saved
/// register it uses, keeps rsp 8-mod-16 aligned as on entry, and neither
/// calls Rust nor unwinds.
// Dispatched by default (HELIUS_FP6_ASM=0 restores composed); always covered by
// the leaf differential tests.
#[inline(never)]
#[cfg(any(test, helius_fp6_active))]
pub(crate) fn fp6_mul(a: &crate::fp6::Fp6, b: &crate::fp6::Fp6) -> crate::fp6::Fp6 {
    debug_assert_canonical!(components(6): a, b);
    let mut z = core::mem::MaybeUninit::<crate::fp6::Fp6>::uninit();
    unsafe {
        // SAFETY: repr(C) Fp6 references and the local output satisfy the
        // complete kernel contract above (canonical inputs are the Fp
        // invariant). The assembly initializes all 192 bytes before
        // `assume_init` and cannot retain any pointer.
        helius_fp6_mul_x86(
            z.as_mut_ptr() as *mut u64,
            a as *const crate::fp6::Fp6 as *const u64,
            b as *const crate::fp6::Fp6 as *const u64,
            &FP6_MUL_CONSTANTS,
        );
        z.assume_init()
    }
}

/// Reduced Montgomery multiplication through the generated x86-64 leaf.
///
/// Kernel contract: `a` and `b` are readable, 8-byte-aligned 32-byte arrays.
/// `a` and `b` must both be residues below the BN254 base modulus. The
/// dual-chain schedule's 2^320 carry bound needs both operands below p:
/// larger `a` miscomputes (interpreter-caught, hardware-confirmed), so
/// `Fp::from_raw` reduces before calling. They
/// may alias each other. The wrapper supplies distinct output and immutable
/// constant-table
/// pointers, both suitably aligned and live for the call. The leaf
/// initializes all four output limbs, returns a fully reduced residue, saves
/// every callee-saved register it uses, keeps rsp 8-mod-16 aligned as on
/// entry, and neither calls Rust nor unwinds.
#[inline(never)]
pub fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> Fp {
    debug_assert!(!crate::limb::gte(a, &crate::consts::P));
    debug_assert!(!crate::limb::gte(b, &crate::consts::P));
    let mut z = core::mem::MaybeUninit::<[u64; 4]>::uninit();
    unsafe {
        // SAFETY: fixed-size references and the local output satisfy the
        // complete kernel contract above. The assembly initializes 32 bytes
        // before `assume_init` and cannot retain any pointer.
        helius_mont4_mul_x86(
            z.as_mut_ptr() as *mut u64,
            a.as_ptr(),
            b.as_ptr(),
            &MONT4_CONSTANTS,
        );
        Fp(z.assume_init())
    }
}

/// Dedicated Montgomery squaring (ten-product schedule); same contract as
/// [`mont_mul`], with the unused `y` argument passed as `a`.
#[inline(never)]
pub fn mont_sqr(a: &[u64; 4]) -> Fp {
    debug_assert!(!crate::limb::gte(a, &crate::consts::P));
    let mut z = core::mem::MaybeUninit::<[u64; 4]>::uninit();
    unsafe {
        // SAFETY: as in `mont_mul`; the square reads only `x` and the table.
        helius_mont4_sqr_x86(
            z.as_mut_ptr() as *mut u64,
            a.as_ptr(),
            a.as_ptr(),
            &MONT4_CONSTANTS,
        );
        Fp(z.assume_init())
    }
}

/// `(sum_i a_i * b_i) * R^{-1} mod p` through the rolled SoS leaf: `N/2`
/// operand pairs as a pointer table (`a_0, b_0, a_1, b_1, ...`).
///
/// Kernel contract: an even count of 2..=10 pairs (the inner walk takes two
/// pairs per iteration); every pointer refers to a readable,
/// 8-byte-aligned 32-byte array holding a value at most p (`negp` output may
/// equal p; the SoS bounds only need operands <= p, unlike the strict < p of
/// the mont4 leaves). The wrapper supplies distinct output and constant-table
/// pointers, live for the call. The leaf initializes all four output limbs,
/// returns the canonical residue, saves every callee-saved register it uses,
/// keeps rsp 8-mod-16 aligned as on entry, and neither calls Rust nor
/// unwinds.
#[inline(always)]
fn sos_leaf<const N: usize>(pairs: &[*const u64; N]) -> [u64; 4] {
    const {
        assert!(
            N.is_multiple_of(4) && N >= 4 && N <= 20,
            "even pair count in 2..=10"
        );
    }
    #[cfg(debug_assertions)]
    for operand in pairs {
        // SAFETY: caller passes pointers to live [u64; 4] operands.
        debug_assert!(!crate::limb::gt(
            unsafe { &*(*operand as *const [u64; 4]) },
            &crate::consts::P
        ));
    }
    let mut z = core::mem::MaybeUninit::<[u64; 4]>::uninit();
    unsafe {
        // SAFETY: fixed-size table and the local output satisfy the complete
        // kernel contract above. The assembly initializes 32 bytes before
        // `assume_init` and cannot retain any pointer.
        helius_sos_x86(
            z.as_mut_ptr() as *mut u64,
            pairs.as_ptr(),
            (N / 2) as u64,
            &MONT4_CONSTANTS,
        );
        z.assume_init()
    }
}

// Leaf-backed SoS entry points, one per portable kernel in `fp/sos.rs`
// (identical semantics; `fp/sos.rs` dispatches here on the ADX tier). The
// dual-lane pairs mirror the portable lane definitions exactly:
// lane0 = sum x_{i0}*y_{i0} - x_{i1}*y_{i1} (subtraction via negp),
// lane1 = sum x_{i0}*y_{i1} + x_{i1}*y_{i0}.

#[cfg(any(test, not(helius_cyc_sqr_active)))]
pub(crate) fn sos2(a0: &[u64; 4], b0: &[u64; 4], a1: &[u64; 4], b1: &[u64; 4]) -> [u64; 4] {
    sos_leaf(&[a0.as_ptr(), b0.as_ptr(), a1.as_ptr(), b1.as_ptr()])
}
#[cfg(any(test, not(helius_cyc_sqr_active)))]
pub(crate) fn sos4(
    a0: &[u64; 4],
    b0: &[u64; 4],
    a1: &[u64; 4],
    b1: &[u64; 4],
    a2: &[u64; 4],
    b2: &[u64; 4],
    a3: &[u64; 4],
    b3: &[u64; 4],
) -> [u64; 4] {
    sos_leaf(&[
        a0.as_ptr(),
        b0.as_ptr(),
        a1.as_ptr(),
        b1.as_ptr(),
        a2.as_ptr(),
        b2.as_ptr(),
        a3.as_ptr(),
        b3.as_ptr(),
    ])
}

/// Dual-lane Fp2 product through a dedicated sosd2 leaf:
/// `lane0 = (x0*y0 + x1*(p - y1))/R`, `lane1 = (x0*y1 + x1*y0)/R`, both
/// canonical, in one call. The leaf computes `p - y1` and interleaves the
/// two lanes' rows itself, so the cross-lane ILP that two serial
/// `helius_sos_x86` calls lose (measured -13% on the g2 subgroup) is kept.
///
/// The rolled `helius_sosd2_small_x86` leaf implements the contract (its
/// retired unrolled twin won in isolation but its 2.4 KiB pressured the op
/// cache inside the combined pairing loop).
///
/// Kernel contract: every operand is a readable, 8-byte-aligned 32-byte
/// array holding a value at most p (the portable `sosd2` bound). `z`
/// receives eight limbs, lane0 then lane1. The leaf initializes all eight
/// output limbs, saves every callee-saved register it uses, keeps rsp
/// 8-mod-16 aligned as on entry, and neither calls Rust nor unwinds.
// Dispatched in production only under HELIUS_SOSD2_ASM=1; always covered by
// the leaf differential tests.
#[cfg(any(test, helius_sosd2_active))]
pub(crate) fn sosd2(
    x0: &[u64; 4],
    x1: &[u64; 4],
    y0: &[u64; 4],
    y1: &[u64; 4],
) -> ([u64; 4], [u64; 4]) {
    debug_assert_canonical!(at_most_p: x0, x1, y0, y1);
    let mut z = core::mem::MaybeUninit::<[u64; 8]>::uninit();
    unsafe {
        // SAFETY: fixed-size references and the local output satisfy the
        // complete kernel contract above. The assembly initializes 64 bytes
        // before `assume_init` and cannot retain any pointer.
        helius_sosd2_small_x86(
            z.as_mut_ptr() as *mut u64,
            x0.as_ptr(),
            x1.as_ptr(),
            y0.as_ptr(),
            y1.as_ptr(),
            &MONT4_CONSTANTS,
        );
        let z = z.assume_init();
        ([z[0], z[1], z[2], z[3]], [z[4], z[5], z[6], z[7]])
    }
}
pub(crate) fn sosd4(
    x00: &[u64; 4],
    x01: &[u64; 4],
    y00: &[u64; 4],
    y01: &[u64; 4],
    x10: &[u64; 4],
    x11: &[u64; 4],
    y10: &[u64; 4],
    y11: &[u64; 4],
) -> ([u64; 4], [u64; 4]) {
    let ny01 = crate::fp::sos::negp(y01);
    let ny11 = crate::fp::sos::negp(y11);
    (
        sos_leaf(&[
            x00.as_ptr(),
            y00.as_ptr(),
            x01.as_ptr(),
            ny01.as_ptr(),
            x10.as_ptr(),
            y10.as_ptr(),
            x11.as_ptr(),
            ny11.as_ptr(),
        ]),
        sos_leaf(&[
            x00.as_ptr(),
            y01.as_ptr(),
            x01.as_ptr(),
            y00.as_ptr(),
            x10.as_ptr(),
            y11.as_ptr(),
            x11.as_ptr(),
            y10.as_ptr(),
        ]),
    )
}

/// Composed dual-lane T = 6 sum through two rolled `helius_sos_x86` walks;
/// the reference implementation the dedicated [`sosd6_leaf`] is measured
/// against (build.rs `HELIUS_SOSD6_ASM` selects which one `sos::sosd6`
/// dispatches).
#[cfg(any(
    test,
    all(
        not(helius_sosd6_active),
        any(
            not(helius_fp6_active),
            not(helius_fp12_sqr_active),
            not(helius_fp12_034_active),
        ),
    ),
))]
pub(crate) fn sosd6(products: [Fp2Product<'_>; 3]) -> ([u64; 4], [u64; 4]) {
    let [
        Fp2Product {
            x0: x00,
            x1: x01,
            y0: y00,
            y1: y01,
        },
        Fp2Product {
            x0: x10,
            x1: x11,
            y0: y10,
            y1: y11,
        },
        Fp2Product {
            x0: x20,
            x1: x21,
            y0: y20,
            y1: y21,
        },
    ] = products;
    let ny01 = crate::fp::sos::negp(y01);
    let ny11 = crate::fp::sos::negp(y11);
    let ny21 = crate::fp::sos::negp(y21);
    (
        sos_leaf(&[
            x00.as_ptr(),
            y00.as_ptr(),
            x01.as_ptr(),
            ny01.as_ptr(),
            x10.as_ptr(),
            y10.as_ptr(),
            x11.as_ptr(),
            ny11.as_ptr(),
            x20.as_ptr(),
            y20.as_ptr(),
            x21.as_ptr(),
            ny21.as_ptr(),
        ]),
        sos_leaf(&[
            x00.as_ptr(),
            y01.as_ptr(),
            x01.as_ptr(),
            y00.as_ptr(),
            x10.as_ptr(),
            y11.as_ptr(),
            x11.as_ptr(),
            y10.as_ptr(),
            x20.as_ptr(),
            y21.as_ptr(),
            x21.as_ptr(),
            y20.as_ptr(),
        ]),
    )
}

/// Dual-lane sum of three Fp2 products through the dedicated T = 6 leaf:
/// `lane0 = (sum x_i0*y_i0 + x_i1*(p - y_i1))/R`, `lane1 = (sum x_i0*y_i1 +
/// x_i1*y_i0)/R`, both canonical, in one call -- the composed [`sosd6`]
/// route's value with the two lanes' carry chains interleaved in-kernel.
/// Two serial `helius_sos_x86` walks are each one ~700-instruction
/// single-lane chain, so their independent lanes get no overlap; the leaf
/// alternates lane rows per multiplicand (the sosd2 finding at T = 6) and
/// computes the three `p - y_i1` images itself.
///
/// The leaf's ABI is one staged block built here: the 24 x limbs
/// transposed (so the kernel's multiplicand pointer walks linearly), then
/// five 64-byte y pair blocks `[y00, y01] [y01, y00] [y10, y11] [y11, y10]
/// [y20, y21]` -- pair block i holds pair i's lane0 row source then its
/// lane1 row source, and the kernel overwrites the low vectors of blocks 1
/// and 3 with `p - y01`, `p - y11` in place. Plain value copies here
/// replace the composed route's 24 pointer-table stores and three `negp`
/// temporaries; a 12-pointer-table ABI would instead cost the kernel ~120
/// staging instructions per call (see the schedule's ABI note).
///
/// Kernel contract: every operand is at most p (the portable `sosd6`
/// bound); `stage` is the writable 512-byte block above, `z` receives
/// eight limbs (lane0 then lane1), all initialized and canonical on
/// return. The leaf saves every callee-saved register it uses, keeps rsp
/// 8-mod-16 aligned as on entry, and neither calls Rust nor unwinds.
// Dispatched by default on AMD targets, opt-in elsewhere (build.rs
// HELIUS_SOSD6_ASM: Miller -3.8% on Zen 4, flipping the pairing past mcl);
// always covered by the leaf differential tests.
#[cfg(any(
    test,
    all(
        helius_sosd6_active,
        any(
            not(helius_fp6_active),
            not(helius_fp12_sqr_active),
            not(helius_fp12_034_active),
        ),
    ),
))]
pub(crate) fn sosd6_leaf(products: [Fp2Product<'_>; 3]) -> ([u64; 4], [u64; 4]) {
    let [
        Fp2Product {
            x0: x00,
            x1: x01,
            y0: y00,
            y1: y01,
        },
        Fp2Product {
            x0: x10,
            x1: x11,
            y0: y10,
            y1: y11,
        },
        Fp2Product {
            x0: x20,
            x1: x21,
            y0: y20,
            y1: y21,
        },
    ] = products;
    debug_assert_canonical!(at_most_p: x00, x01, y00, y01, x10, x11, y10, y11, x20, x21, y20, y21);
    let mut stage = [0u64; 64];
    for (i, x) in [x00, x01, x10, x11, x20, x21].into_iter().enumerate() {
        for (j, limb) in x.iter().enumerate() {
            stage[6 * j + i] = *limb;
        }
    }
    for (block, y) in [y00, y01, y01, y00, y10, y11, y11, y10, y20, y21]
        .into_iter()
        .enumerate()
    {
        stage[24 + 4 * block..28 + 4 * block].copy_from_slice(y);
    }
    let mut z = core::mem::MaybeUninit::<[u64; 8]>::uninit();
    unsafe {
        // SAFETY: the local stage block and fixed-size references satisfy
        // the complete kernel contract above. The assembly initializes 64
        // output bytes before `assume_init`, writes nothing outside z and
        // stage, and cannot retain any pointer.
        helius_sosd6_x86(
            z.as_mut_ptr() as *mut u64,
            stage.as_mut_ptr(),
            &MONT4_CONSTANTS,
        );
        let z = z.assume_init();
        ([z[0], z[1], z[2], z[3]], [z[4], z[5], z[6], z[7]])
    }
}
#[cfg(test)]
pub(crate) fn sosd8(products: [Fp2Product<'_>; 4]) -> ([u64; 4], [u64; 4]) {
    let [
        Fp2Product {
            x0: x00,
            x1: x01,
            y0: y00,
            y1: y01,
        },
        Fp2Product {
            x0: x10,
            x1: x11,
            y0: y10,
            y1: y11,
        },
        Fp2Product {
            x0: x20,
            x1: x21,
            y0: y20,
            y1: y21,
        },
        Fp2Product {
            x0: x30,
            x1: x31,
            y0: y30,
            y1: y31,
        },
    ] = products;
    let ny01 = crate::fp::sos::negp(y01);
    let ny11 = crate::fp::sos::negp(y11);
    let ny21 = crate::fp::sos::negp(y21);
    let ny31 = crate::fp::sos::negp(y31);
    (
        sos_leaf(&[
            x00.as_ptr(),
            y00.as_ptr(),
            x01.as_ptr(),
            ny01.as_ptr(),
            x10.as_ptr(),
            y10.as_ptr(),
            x11.as_ptr(),
            ny11.as_ptr(),
            x20.as_ptr(),
            y20.as_ptr(),
            x21.as_ptr(),
            ny21.as_ptr(),
            x30.as_ptr(),
            y30.as_ptr(),
            x31.as_ptr(),
            ny31.as_ptr(),
        ]),
        sos_leaf(&[
            x00.as_ptr(),
            y01.as_ptr(),
            x01.as_ptr(),
            y00.as_ptr(),
            x10.as_ptr(),
            y11.as_ptr(),
            x11.as_ptr(),
            y10.as_ptr(),
            x20.as_ptr(),
            y21.as_ptr(),
            x21.as_ptr(),
            y20.as_ptr(),
            x30.as_ptr(),
            y31.as_ptr(),
            x31.as_ptr(),
            y30.as_ptr(),
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{MONT_ONE, MONT_R2, P};
    use crate::fp::Fp;
    use crate::fp::portable;
    use crate::limb;

    fn next_residue(state: &mut u64) -> [u64; 4] {
        let mut value = [0u64; 4];
        for limb in &mut value {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *limb = *state;
        }
        while limb::gte(&value, &P) {
            value = limb::sub_noborrow(&value, &P);
        }
        value
    }

    fn edge_and_carry_corpus() -> Vec<[u64; 4]> {
        let p_minus_one = limb::sub_noborrow(&P, &[1, 0, 0, 0]);
        let mut cases = vec![
            [0; 4],
            [1, 0, 0, 0],
            MONT_ONE,
            MONT_R2,
            p_minus_one,
            [u64::MAX, u64::MAX, u64::MAX, P[3] - 1],
            [u64::MAX, 0, u64::MAX, 0],
            [0, u64::MAX, 0, 0x1000_0000_0000_0000],
        ];
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for _ in 0..256 {
            cases.push(next_residue(&mut state));
        }
        cases
    }

    #[test]
    fn hot_matches_asm() {
        let a = Fp::from_u64(0x123456789);
        let b = Fp::from_u64(0x987654321);
        assert_eq!(a * b, mont_mul(&a.0, &b.0));
        assert_eq!(a.square(), mont_sqr(&a.0));
    }

    #[test]
    fn assembly_matches_portable_on_edges_and_carries() {
        let cases = edge_and_carry_corpus();
        for (index, a) in cases.iter().enumerate() {
            assert_eq!(mont_sqr(a), portable::mont_sqr(a), "square case {index}");
            assert_eq!(
                mont_sqr(a),
                mont_mul(a, a),
                "square/multiply divergence, case {index}",
            );
            for (other_index, b) in cases.iter().step_by(17).enumerate() {
                assert_eq!(
                    mont_mul(a, b),
                    portable::mont_mul(a, b),
                    "multiply case {index}/{other_index}",
                );
                assert_eq!(
                    mont_mul(a, b),
                    mont_mul(b, a),
                    "commutativity case {index}/{other_index}",
                );
            }
        }
    }

    #[test]
    fn assembly_matches_portable_on_random_products() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for case in 0..65_536 {
            let a = next_residue(&mut state);
            let b = next_residue(&mut state);
            assert_eq!(
                mont_mul(&a, &b),
                portable::mont_mul(&a, &b),
                "multiply case {case}",
            );
            assert_eq!(mont_sqr(&a), portable::mont_sqr(&a), "square case {case}",);
        }
    }

    #[test]
    #[ignore = "million-case release stress gate; run explicitly before changing field backends"]
    fn million_products_match_assembly() {
        let mut state = 0xd1b5_4a32_d192_ed03u64;
        for case in 0..1_000_000 {
            let a = next_residue(&mut state);
            let b = next_residue(&mut state);
            assert_eq!(
                mont_mul(&a, &b),
                portable::mont_mul(&a, &b),
                "multiply case {case}",
            );
            assert_eq!(mont_sqr(&a), portable::mont_sqr(&a), "square case {case}",);
        }
    }
}
