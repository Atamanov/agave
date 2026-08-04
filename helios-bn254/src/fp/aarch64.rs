//! AArch64 Montgomery backend using the generated leaf assembly kernel.
//!
//! The assembly is generated at build time from the schedule DSL in
//! `build/a64/schedule.rs` (ADR 0001, build-time amendment) and pinned
//! byte-for-byte by `tests/golden/mont4_aarch64.s`. Inspect a copy with
//! `HELIOS_DUMP_ASM=<absolute dir> cargo build`.

use crate::fp::Fp;

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

unsafe extern "C" {
    fn helios_mont4(z: *mut u64, x: *const u64, y: *const u64, constants: *const Mont4Constants);
}

/// Reduced Montgomery multiplication through the shared Apple AArch64 leaf.
///
/// Kernel contract: `a` and `b` are readable, 8-byte-aligned 32-byte arrays.
/// `a` and `b` must both be residues below the BN254 base modulus (the
/// shared backend contract; `Fp::from_raw` reduces first). The A64 schedule
/// additionally tolerates `a < 2^256` (single-chain rows plus CSET give
/// 2^321 headroom, interpreter-verified) but callers must not rely on it.
/// They may alias each other.
/// The wrapper supplies distinct output and immutable constant-table pointers,
/// both suitably aligned and live for the call. The leaf initializes all four
/// output limbs, returns a fully reduced residue, saves every callee-saved
/// register it uses, preserves the 16-byte stack alignment, and neither calls
/// Rust nor unwinds.
#[inline(never)]
pub fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> Fp {
    debug_assert!(!crate::limb::gte(a, &crate::consts::P));
    debug_assert!(!crate::limb::gte(b, &crate::consts::P));
    let mut z = core::mem::MaybeUninit::<[u64; 4]>::uninit();
    unsafe {
        // SAFETY: fixed-size references and the local output satisfy the
        // complete kernel contract above. The assembly initializes 32 bytes
        // before `assume_init` and cannot retain any pointer.
        helios_mont4(
            z.as_mut_ptr() as *mut u64,
            a.as_ptr(),
            b.as_ptr(),
            &MONT4_CONSTANTS,
        );
        Fp(z.assume_init())
    }
}

#[inline(always)]
pub fn mont_sqr(a: &[u64; 4]) -> Fp {
    mont_mul(a, a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{MONT_ONE, MONT_R2, P};
    use crate::fp::Fp;
    use crate::fp::portable;
    use crate::limb;

    #[test]
    fn hot_matches_asm() {
        let a = Fp::from_u64(0x123456789);
        let b = Fp::from_u64(0x987654321);
        assert_eq!(a * b, mont_mul(&a.0, &b.0));
        assert_eq!(a.square(), mont_sqr(&a.0));
    }

    #[test]
    fn assembly_matches_portable_on_edges_and_carries() {
        let p_minus_one = limb::sub_noborrow(&P, &[1, 0, 0, 0]);
        let mut cases = vec![
            [0; 4],
            [1, 0, 0, 0],
            MONT_ONE,
            MONT_R2,
            p_minus_one,
            [u64::MAX, 0, u64::MAX, 0],
            [0, u64::MAX, 0, 0x1000_0000_0000_0000],
        ];
        for value in cases.iter_mut().skip(5) {
            while limb::gte(value, &P) {
                *value = limb::sub_noborrow(value, &P);
            }
        }

        let mut state = 0x243f_6a88_85a3_08d3u64;
        for _ in 0..256 {
            let mut value = [0u64; 4];
            for limb in &mut value {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *limb = state;
            }
            while limb::gte(&value, &P) {
                value = limb::sub_noborrow(&value, &P);
            }
            cases.push(value);
        }

        for (index, a) in cases.iter().enumerate() {
            assert_eq!(mont_sqr(a), portable::mont_sqr(a), "square case {index}");
            for (other_index, b) in cases.iter().step_by(17).enumerate() {
                assert_eq!(
                    mont_mul(a, b),
                    portable::mont_mul(a, b),
                    "multiply case {index}/{other_index}",
                );
            }
        }
    }

    #[test]
    #[ignore = "million-case release stress gate; run explicitly before changing field backends"]
    fn million_products_match_assembly_and_arkworks_raw_montgomery() {
        use ark_ff::BigInt;

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

        let mut state = 0xd1b5_4a32_d192_ed03u64;
        for case in 0..1_000_000 {
            let a = next_residue(&mut state);
            let b = next_residue(&mut state);
            let portable = portable::mont_mul(&a, &b);
            assert_eq!(portable, mont_mul(&a, &b), "assembly case {case}");

            // Arkworks and Helios use the same four-limb R=2^256 Montgomery
            // representation. `new_unchecked` deliberately consumes those raw
            // limbs, so this oracle compares the kernel result directly: no
            // Helios conversion path can mask a common error.
            let ark_a = ark_bn254::Fq::new_unchecked(BigInt::new(a));
            let ark_b = ark_bn254::Fq::new_unchecked(BigInt::new(b));
            let ark_product = (ark_a * ark_b).0.0;
            assert_eq!(portable.0, ark_product, "Arkworks case {case}");
        }
    }
}
