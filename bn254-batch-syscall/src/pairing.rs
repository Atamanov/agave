//! Boolean multi-pairing check, forwarded to the helios-bn254 backend.
//!
//! The pod slice casts to the backend's identical wire type (layout pinned by
//! the const-asserts in `pod`), so forwarding adds no copy or conversion.

use {
    crate::{Version, backend_version, pod::PodG1G2Pair, validation::AltBn128BatchError},
    helios_bn254 as backend,
};

/// Boolean multi-pairing check: true iff the product of e(G1_i, G2_i) is the
/// identity in GT.
///
/// Each `PodG1G2Pair` is a validated G1 point then its G2 partner, big-endian
/// and byte-for-byte the input encoding of the existing `sol_alt_bn128_group_op`
/// pairing. Every point is validated (canonical coordinates, on-curve, and for
/// G2 subgroup membership) before any arithmetic; a pair with an infinity member
/// contributes the identity factor and is skipped. G2 preparation, the Miller
/// loop, the final exponentiation, and the identity compare all happen in the
/// backend: no prepared point and no GT value crosses this API in either
/// direction. Pair width is fixed by the type, so a malformed length faults at
/// the syscall boundary, never here.
pub fn alt_bn128_pairing_check(
    version: Version,
    pairs: &[PodG1G2Pair],
) -> Result<bool, AltBn128BatchError> {
    let pairs = bytemuck::cast_slice::<_, backend::PodG1G2Pair>(pairs);
    backend::alt_bn128_pairing_check(backend_version(version), pairs)
        .map_err(AltBn128BatchError::from)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            encoding::{G1_BYTES, PAIR_BYTES, PAIRING_MAX_PAIRS, parse_g1},
            test_utils::{
                be_add_one, decode_hex, fq_modulus_be, g1_bytes, non_subgroup_g2, pair_bytes,
                random_g1, random_g2, rng, telescoping_pairs,
            },
        },
        ark_bn254::{Fq, Fr, G1Affine, G1Projective, G2Affine, G2Projective},
        ark_ec::{AffineRepr, CurveGroup, PrimeGroup},
        ark_ff::UniformRand,
        ark_std::rand::Rng,
    };

    // the "jeff1" test vector (two pairs, product == 1), byte-for-byte the input
    // of the existing group-op pairing syscall
    const TRUE_PAIRS_HEX: &str = "1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa";

    // byte-oriented bodies drive the typed entry point through a zero-cost cast
    fn check(pairs: &[u8]) -> Result<bool, AltBn128BatchError> {
        alt_bn128_pairing_check(Version::V0, bytemuck::cast_slice(pairs))
    }

    #[test]
    fn test_pairing_check_known_vector() {
        let pairs = decode_hex(TRUE_PAIRS_HEX);
        assert_eq!(check(&pairs), Ok(true));
        // flip the sign of the first G1 point: the product is no longer 1
        let g1 = parse_g1(&pairs[..G1_BYTES]).unwrap();
        let mut corrupted = pairs.clone();
        corrupted[..G1_BYTES].copy_from_slice(&g1_bytes(&-g1));
        assert_eq!(check(&corrupted), Ok(false));
    }

    #[test]
    fn test_pairing_check_matches_solana_bn254_verdict() {
        let mut rng = rng();
        for n in [2usize, 3, 4, 8] {
            for corrupt in [false, true] {
                let mut pairs = telescoping_pairs(&mut rng, n);
                if corrupt {
                    let g1 = parse_g1(&pairs[..G1_BYTES]).unwrap();
                    pairs[..G1_BYTES].copy_from_slice(&g1_bytes(&-g1));
                }
                let expected = solana_bn254::prelude::alt_bn128_pairing_be(&pairs).unwrap();
                let expected_true = *expected.last().unwrap() == 1;
                assert_eq!(
                    check(&pairs),
                    Ok(expected_true),
                    "n = {n}, corrupt = {corrupt}"
                );
            }
        }
    }

    #[test]
    fn test_pairing_check_bilinearity_fold() {
        // the batch-fold identity: e([a]P, Q) * e(-P, [a]Q) == 1
        let mut rng = rng();
        let a = Fr::rand(&mut rng);
        let p = G1Projective::generator() * Fr::rand(&mut rng);
        let q = G2Projective::generator() * Fr::rand(&mut rng);
        let pairs = [
            pair_bytes(&(p * a).into_affine(), &q.into_affine()),
            pair_bytes(&(-p).into_affine(), &(q * a).into_affine()),
        ]
        .concat();
        assert_eq!(check(&pairs), Ok(true));
    }

    #[test]
    fn test_pairing_check_telescoping_true_and_sign_flip_false() {
        let mut rng = rng();
        for n in [2usize, 4, 16, 33] {
            let pairs = telescoping_pairs(&mut rng, n);
            assert_eq!(check(&pairs), Ok(true), "n = {n}");
            let g1 = parse_g1(&pairs[..G1_BYTES]).unwrap();
            let mut flipped = pairs.clone();
            flipped[..G1_BYTES].copy_from_slice(&g1_bytes(&-g1));
            // an invalid product is a false verdict, not an error
            assert_eq!(check(&flipped), Ok(false), "n = {n}");
        }
    }

    #[test]
    fn test_pairing_check_single_real_pair_is_false() {
        let mut rng = rng();
        let pairs = pair_bytes(&random_g1(&mut rng), &random_g2(&mut rng));
        assert_eq!(check(&pairs), Ok(false));
    }

    #[test]
    fn test_pairing_check_skips_infinity_pairs() {
        let mut rng = rng();
        let telescoping = telescoping_pairs(&mut rng, 2);
        let infinity_g1 = pair_bytes(&G1Affine::zero(), &random_g2(&mut rng));
        let infinity_g2 = pair_bytes(&random_g1(&mut rng), &G2Affine::zero());
        // an infinity member contributes the identity factor
        assert_eq!(
            check(&[telescoping.clone(), infinity_g1.to_vec()].concat()),
            Ok(true)
        );
        assert_eq!(
            check(&[infinity_g2.to_vec(), telescoping].concat()),
            Ok(true)
        );
    }

    #[test]
    fn test_pairing_check_all_infinity_pairs_true() {
        assert_eq!(check(&[0u8; 3 * PAIR_BYTES]), Ok(true));
    }

    #[test]
    fn test_pairing_check_validates_partner_of_infinity_point() {
        // the pair would be skipped, but validation happens per declared point
        let pairs = pair_bytes(&G1Affine::zero(), &non_subgroup_g2());
        assert_eq!(check(&pairs), Err(AltBn128BatchError::NotInSubgroup));
    }

    #[test]
    fn test_pairing_check_rejects_non_subgroup_g2_at_any_position() {
        let mut rng = rng();
        let bad = pair_bytes(&random_g1(&mut rng), &non_subgroup_g2());
        for position in [0usize, 3, 7] {
            let mut pairs = telescoping_pairs(&mut rng, 8);
            pairs[position * PAIR_BYTES..(position + 1) * PAIR_BYTES].copy_from_slice(&bad);
            assert_eq!(
                check(&pairs),
                Err(AltBn128BatchError::NotInSubgroup),
                "position {position}"
            );
        }
    }

    #[test]
    fn test_pairing_check_rejects_cancelling_non_subgroup_pairs() {
        // (P, T) and (P, -T) with T outside the subgroup: a check that batched
        // or deferred the membership test unsoundly would see the product
        // cancel to 1 and answer true; the per-point check must reject instead
        let mut rng = rng();
        let p = random_g1(&mut rng);
        let t = non_subgroup_g2();
        let pairs = [pair_bytes(&p, &t), pair_bytes(&p, &-t)].concat();
        assert_eq!(check(&pairs), Err(AltBn128BatchError::NotInSubgroup));
    }

    #[test]
    fn test_subgroup_failure_order_across_pairs() {
        // earlier-pair subgroup failure outranks a later parse error, and an
        // earlier parse error hides a later subgroup failure: pins the backend
        // to the per-pair check order
        let mut rng = rng();
        let bad_subgroup = pair_bytes(&random_g1(&mut rng), &non_subgroup_g2());
        let mut bad_parse = pair_bytes(&random_g1(&mut rng), &random_g2(&mut rng)).to_vec();
        bad_parse[..32].copy_from_slice(&fq_modulus_be());
        assert_eq!(
            check(&[bad_subgroup.as_slice(), bad_parse.as_slice()].concat()),
            Err(AltBn128BatchError::NotInSubgroup)
        );
        assert_eq!(
            check(&[bad_parse.as_slice(), bad_subgroup.as_slice()].concat()),
            Err(AltBn128BatchError::NonCanonical)
        );
    }

    #[test]
    fn test_pairing_check_rejects_off_curve_points() {
        let mut rng = rng();
        let g1 = random_g1(&mut rng);
        let g2 = random_g2(&mut rng);
        let off_g1 = G1Affine::new_unchecked(g1.x, g1.y + Fq::from(1u64));
        assert_eq!(
            check(&pair_bytes(&off_g1, &g2)),
            Err(AltBn128BatchError::NotOnCurve)
        );
        let mut off_g2 = g2;
        off_g2.y.c0 += Fq::from(1u64);
        assert_eq!(
            check(&pair_bytes(&g1, &off_g2)),
            Err(AltBn128BatchError::NotOnCurve)
        );
    }

    #[test]
    fn test_pairing_check_rejects_noncanonical_limbs() {
        let mut rng = rng();
        let mut plus_one = fq_modulus_be();
        be_add_one(&mut plus_one);
        for bad in [fq_modulus_be(), plus_one, [0xffu8; 32]] {
            // every 32-byte slot of the 192-byte pair: G1 x, y then G2 x1, x0, y1, y0
            for slot in 0..6usize {
                let mut pairs = pair_bytes(&random_g1(&mut rng), &random_g2(&mut rng)).to_vec();
                pairs[slot * 32..(slot + 1) * 32].copy_from_slice(&bad);
                assert_eq!(
                    check(&pairs),
                    Err(AltBn128BatchError::NonCanonical),
                    "slot {slot}"
                );
            }
        }
    }

    #[test]
    fn test_pairing_check_validates_g1_before_g2() {
        // off-curve G1 and non-canonical G2 in one pair: G1 is validated first
        let mut rng = rng();
        let g1 = random_g1(&mut rng);
        let off_g1 = G1Affine::new_unchecked(g1.x, g1.y + Fq::from(1u64));
        let mut pairs = pair_bytes(&off_g1, &random_g2(&mut rng)).to_vec();
        pairs[G1_BYTES..G1_BYTES + 32].copy_from_slice(&fq_modulus_be());
        assert_eq!(check(&pairs), Err(AltBn128BatchError::NotOnCurve));
    }

    #[test]
    fn test_pairing_check_rejects_zero_pairs() {
        // an unguarded empty product would be a vacuous accept
        assert_eq!(check(&[]), Err(AltBn128BatchError::ZeroInput));
    }

    #[test]
    fn test_pairing_check_rejects_over_cap() {
        let pairs = vec![0u8; (PAIRING_MAX_PAIRS + 1) * PAIR_BYTES];
        assert_eq!(check(&pairs), Err(AltBn128BatchError::CapExceeded));
        assert_eq!(check(&pairs[..PAIRING_MAX_PAIRS * PAIR_BYTES]), Ok(true));
    }

    #[test]
    fn test_pairing_check_total_on_random_bytes_and_deterministic() {
        let mut rng = rng();
        for _ in 0..1_000 {
            let n = rng.gen_range(1..4usize);
            let mut pairs = vec![0u8; n * PAIR_BYTES];
            rng.fill(&mut pairs[..]);
            let first = check(&pairs);
            assert_eq!(first, check(&pairs), "must be deterministic");
        }
    }

    #[test]
    fn test_pairing_check_total_on_bit_flips_of_valid_input() {
        let mut rng = rng();
        let pairs = telescoping_pairs(&mut rng, 2);
        for byte in 0..pairs.len() {
            for bit in [0u8, 7] {
                let mut mutated = pairs.clone();
                mutated[byte] ^= 1 << bit;
                let first = check(&mutated);
                assert_eq!(first, check(&mutated));
            }
        }
    }
}
