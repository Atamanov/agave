//! Allocation-free BSB22 hash-to-field, byte-exact with gnark-crypto's
//! `fr.Hash(commitment, "bsb22-commitment", 1)`.

use solana_bn254_batch_syscall::{PodScalar, Version, alt_bn128_fr_lincomb};

#[cfg(target_os = "solana")]
fn sha256(input: &[u8]) -> [u8; 32] {
    use pinocchio::syscalls::sol_sha256;
    let slices: [&[u8]; 1] = [input];
    let mut out = [0u8; 32];
    // SAFETY: both buffers remain valid for the synchronous syscall.
    unsafe {
        sol_sha256(
            slices.as_ptr() as *const u8,
            slices.len() as u64,
            out.as_mut_ptr(),
        );
    }
    out
}

#[cfg(not(target_os = "solana"))]
fn sha256(input: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(input).into()
}

const B_IN_BYTES: usize = 32;
const R_IN_BYTES: usize = 64;
const L: usize = 48;
const MAX_SCRATCH: usize = 256;
const LIMB_BYTES: usize = 16;

pub(crate) fn expand_message_xmd_sha256_l48<const MSG_LEN: usize, const DST_LEN: usize>(
    msg: &[u8; MSG_LEN],
    dst: &[u8; DST_LEN],
) -> [u8; L] {
    const { assert!(DST_LEN <= 255) };
    const {
        let b0_len = R_IN_BYTES + MSG_LEN + 2 + 1 + (DST_LEN + 1);
        assert!(b0_len <= MAX_SCRATCH)
    };
    let mut scratch = [0u8; MAX_SCRATCH];
    let append_dst = |scratch: &mut [u8; MAX_SCRATCH], offset: usize| -> usize {
        scratch[offset..offset + DST_LEN].copy_from_slice(dst);
        scratch[offset + DST_LEN] = DST_LEN as u8;
        offset + DST_LEN + 1
    };

    let mut offset = R_IN_BYTES;
    scratch[offset..offset + MSG_LEN].copy_from_slice(msg);
    offset += MSG_LEN;
    scratch[offset..offset + 2].copy_from_slice(&(L as u16).to_be_bytes());
    offset += 2;
    scratch[offset] = 0;
    offset += 1;
    offset = append_dst(&mut scratch, offset);
    let b0 = sha256(&scratch[..offset]);

    scratch[..B_IN_BYTES].copy_from_slice(&b0);
    let mut offset = B_IN_BYTES;
    scratch[offset] = 1;
    offset += 1;
    offset = append_dst(&mut scratch, offset);
    let b1 = sha256(&scratch[..offset]);

    for (out, (x, y)) in scratch.iter_mut().zip(b0.iter().zip(&b1)) {
        *out = x ^ y;
    }
    let mut offset = B_IN_BYTES;
    scratch[offset] = 2;
    offset += 1;
    offset = append_dst(&mut scratch, offset);
    let b2 = sha256(&scratch[..offset]);

    let mut out = [0u8; L];
    out[..B_IN_BYTES].copy_from_slice(&b1);
    out[B_IN_BYTES..].copy_from_slice(&b2[..L - B_IN_BYTES]);
    out
}

/// `2^256 mod r`, big-endian. The top limb of the 384-bit digest carries this
/// weight; a wrong byte moves the BSB22 challenge to a different statement that
/// the proof still satisfies.
const TWO_POW_256_MOD_R: PodScalar = PodScalar([
    0x0e, 0x0a, 0x77, 0xc1, 0x9a, 0x07, 0xdf, 0x2f, 0x66, 0x6e, 0xa3, 0x6f, 0x78, 0x79, 0x46, 0x2e,
    0x36, 0xfc, 0x76, 0x95, 0x9f, 0x60, 0xcd, 0x29, 0xac, 0x96, 0x34, 0x1c, 0x4f, 0xff, 0xff, 0xfb,
]);

/// `2^128`, below r and so already canonical.
const TWO_POW_128: PodScalar = PodScalar([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

const ONE: PodScalar = PodScalar([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
]);

/// `x mod r` for a 384-bit big-endian `x`.
///
/// Writing `x = c2*2^256 + c1*2^128 + c0`, every `ci` is below `2^128 < r` and
/// so is a canonical scalar. The reduction is then one three-term inner
/// product, which the scalar-field syscall performs with a single reduction.
pub(crate) fn reduce_be_384(x: &[u8; L]) -> Option<[u8; 32]> {
    let mut limbs = [PodScalar([0u8; 32]); 3];
    for (limb, chunk) in limbs.iter_mut().zip(x.chunks_exact(LIMB_BYTES)) {
        limb.0[32 - LIMB_BYTES..].copy_from_slice(chunk);
    }
    let weights = [TWO_POW_256_MOD_R, TWO_POW_128, ONE];
    Some(alt_bn128_fr_lincomb(Version::V0, &limbs, &weights).ok()?.0)
}

pub fn hash_to_field_bn254_fr<const MSG_LEN: usize, const DST_LEN: usize>(
    msg: &[u8; MSG_LEN],
    dst: &[u8; DST_LEN],
) -> Option<[u8; 32]> {
    reduce_be_384(&expand_message_xmd_sha256_l48(msg, dst))
}

#[cfg(test)]
mod tests {
    use {super::*, ark_bn254::Fr, ark_ff::PrimeField};

    /// The reduction this replaced, kept as the byte-exactness reference.
    fn arkworks_reduce_be_384(x: &[u8; L]) -> [u8; 32] {
        let mut raw = *x;
        raw.reverse();
        let limbs = Fr::from_le_bytes_mod_order(&raw).into_bigint().0;
        let mut out = [0u8; 32];
        for (chunk, limb) in out.chunks_exact_mut(8).zip(limbs.iter().rev()) {
            chunk.copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    /// r as a 384-bit big-endian integer.
    const R_BE_384: [u8; L] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0,
        0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9,
        0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
    ];

    fn offset_by(base: &[u8; L], delta: i8) -> [u8; L] {
        let mut out = *base;
        let mut carry = i16::from(delta);
        for byte in out.iter_mut().rev() {
            let value = i16::from(*byte) + carry;
            *byte = value.rem_euclid(256) as u8;
            carry = value.div_euclid(256);
            if carry == 0 {
                break;
            }
        }
        out
    }

    fn power_of_two(exponent: usize) -> [u8; L] {
        let mut out = [0u8; L];
        out[L - 1 - exponent / 8] = 1 << (exponent % 8);
        out
    }

    /// The folding weight is derived here, never copied in from a note.
    #[test]
    fn two_pow_256_weight_is_the_arkworks_reduction() {
        assert_eq!(
            TWO_POW_256_MOD_R.0,
            arkworks_reduce_be_384(&power_of_two(256))
        );
        assert_eq!(TWO_POW_128.0, arkworks_reduce_be_384(&power_of_two(128)));
        assert_eq!(ONE.0, arkworks_reduce_be_384(&power_of_two(0)));
    }

    #[test]
    fn matches_arkworks_on_modulus_boundaries() {
        for (label, x) in [
            ("zero", [0u8; L]),
            ("2^384-1", [0xffu8; L]),
            ("r-1", offset_by(&R_BE_384, -1)),
            ("r", R_BE_384),
            ("r+1", offset_by(&R_BE_384, 1)),
            ("2^128", power_of_two(128)),
            ("2^256", power_of_two(256)),
            ("2^383", power_of_two(383)),
            ("2^128-1", {
                let mut x = [0u8; L];
                x[32..].fill(0xff);
                x
            }),
            ("top limb only", {
                let mut x = [0u8; L];
                x[..16].fill(0xff);
                x
            }),
        ] {
            assert_eq!(
                reduce_be_384(&x),
                Some(arkworks_reduce_be_384(&x)),
                "{label}"
            );
        }
    }

    #[test]
    fn matches_arkworks_on_a_deterministic_sweep() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..4_096 {
            let mut x = [0u8; L];
            for chunk in x.chunks_exact_mut(8) {
                chunk.copy_from_slice(&next().to_be_bytes());
            }
            assert_eq!(reduce_be_384(&x), Some(arkworks_reduce_be_384(&x)));
        }
    }

    #[test]
    fn gnark_golden_vector_for_zero_g1() {
        assert_eq!(
            hash_to_field_bn254_fr(&[0u8; 64], b"bsb22-commitment"),
            Some([
                0x1f, 0x14, 0x07, 0xef, 0x74, 0x5a, 0x0b, 0x1e, 0xae, 0x05, 0x67, 0x30, 0x6b, 0x45,
                0x60, 0x47, 0x9d, 0x99, 0xb9, 0x43, 0xb3, 0x40, 0x72, 0xd9, 0x83, 0xad, 0x2e, 0xc6,
                0xd3, 0x7a, 0x13, 0x60,
            ])
        );
    }
}
