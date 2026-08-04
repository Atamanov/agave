pub mod agave_fixtures;

use agave_fixtures::{
    fq_modulus, g1_generator, g1_negative_generator, g1_off_curve, g2_generator,
    g2_negative_non_subgroup, g2_non_subgroup, g2_off_curve, pair,
};
use helios_bn254::{
    G1Bytes, G2Bytes, InputError, PAIRING_MAX_PAIRS, pairing_map, pairing_product_is_one,
};

#[test]
fn pairing_product_matches_basic_eip197_identities() {
    let generator_pair = pair(g1_generator(), g2_generator());
    assert_eq!(pairing_product_is_one(&[generator_pair]), Ok(false));
    assert_eq!(
        pairing_product_is_one(&[
            generator_pair,
            pair(g1_negative_generator(), g2_generator()),
        ]),
        Ok(true)
    );
}

#[test]
fn pairing_map_matches_boolean_identity_and_validation_precedence() {
    let generator_pair = pair(g1_generator(), g2_generator());
    assert_eq!(
        pairing_map(&[generator_pair]).map(|value| value.is_identity()),
        Ok(false)
    );
    let identity = [
        generator_pair,
        pair(g1_negative_generator(), g2_generator()),
    ];
    assert_eq!(
        pairing_map(&identity).map(|value| value.is_identity()),
        Ok(true)
    );

    let infinity_pair = pair(G1Bytes([0; 64]), G2Bytes([0; 128]));
    assert_eq!(
        pairing_map(&[infinity_pair]).map(|value| value.is_identity()),
        Ok(true)
    );
    assert_eq!(pairing_map(&[]), Err(InputError::ZeroInput));
    assert_eq!(
        pairing_map(&[pair(g1_off_curve(), g2_non_subgroup())]),
        Err(InputError::NotOnCurve)
    );
    assert_eq!(
        pairing_map(&[pair(g1_generator(), g2_non_subgroup())]),
        Err(InputError::NotInSubgroup)
    );
}

#[test]
fn infinity_pairs_contribute_identity_but_both_members_are_validated() {
    let infinity_g1 = G1Bytes([0; 64]);
    let infinity_g2 = G2Bytes([0; 128]);

    assert_eq!(
        pairing_product_is_one(&[
            pair(infinity_g1, g2_generator()),
            pair(g1_generator(), infinity_g2),
        ]),
        Ok(true)
    );
    assert_eq!(
        pairing_product_is_one(&[pair(infinity_g1, g2_non_subgroup())]),
        Err(InputError::NotInSubgroup)
    );
    assert_eq!(
        pairing_product_is_one(&[pair(g1_off_curve(), infinity_g2)]),
        Err(InputError::NotOnCurve)
    );
}

#[test]
fn pairing_rejects_empty_and_enforces_cap_before_validation() {
    assert_eq!(pairing_product_is_one(&[]), Err(InputError::ZeroInput));

    let at_cap = vec![pair(G1Bytes([0; 64]), G2Bytes([0; 128])); PAIRING_MAX_PAIRS];
    assert_eq!(pairing_product_is_one(&at_cap), Ok(true));

    let over = vec![pair(g1_off_curve(), G2Bytes([0; 128])); PAIRING_MAX_PAIRS + 1];
    assert_eq!(pairing_product_is_one(&over), Err(InputError::CapExceeded));
}

#[test]
fn pairing_rejects_on_curve_non_subgroup_g2_at_any_position() {
    for position in [0usize, 1, 3] {
        let mut pairs = vec![pair(G1Bytes([0; 64]), G2Bytes([0; 128])); 4];
        pairs[position] = pair(g1_generator(), g2_non_subgroup());
        assert_eq!(
            pairing_product_is_one(&pairs),
            Err(InputError::NotInSubgroup),
            "position {position}"
        );
    }
}

#[test]
fn pairing_does_not_allow_non_subgroup_terms_to_cancel() {
    // These two linearly opposite twist points would cancel in a deferred
    // product check. Agave requires every G2 input to pass membership first.
    let pairs = [
        pair(g1_generator(), g2_non_subgroup()),
        pair(g1_generator(), g2_negative_non_subgroup()),
    ];
    assert_eq!(
        pairing_product_is_one(&pairs),
        Err(InputError::NotInSubgroup)
    );
}

#[test]
fn pairing_rejects_off_curve_points() {
    assert_eq!(
        pairing_product_is_one(&[pair(g1_off_curve(), g2_generator())]),
        Err(InputError::NotOnCurve)
    );
    assert_eq!(
        pairing_product_is_one(&[pair(g1_generator(), g2_off_curve())]),
        Err(InputError::NotOnCurve)
    );
}

#[test]
fn pairing_rejects_noncanonical_value_in_each_coordinate_slot() {
    for slot in 0..6usize {
        let mut value = pair(g1_generator(), g2_generator());
        if slot < 2 {
            value.g1.0[slot * 32..(slot + 1) * 32].copy_from_slice(&fq_modulus());
        } else {
            let offset = (slot - 2) * 32;
            value.g2.0[offset..offset + 32].copy_from_slice(&fq_modulus());
        }
        assert_eq!(
            pairing_product_is_one(&[value]),
            Err(InputError::NonCanonical),
            "coordinate slot {slot}"
        );
    }
}

#[test]
fn pairing_validates_g1_before_its_g2_partner() {
    let mut noncanonical_g2 = g2_generator();
    noncanonical_g2.0[..32].copy_from_slice(&fq_modulus());
    assert_eq!(
        pairing_product_is_one(&[pair(g1_off_curve(), noncanonical_g2)]),
        Err(InputError::NotOnCurve)
    );
}

#[test]
fn cached_g2_lookup_still_follows_later_g1_validation() {
    let shared_g2 = g2_generator();
    assert_eq!(
        pairing_product_is_one(&[
            pair(g1_generator(), shared_g2),
            pair(g1_off_curve(), shared_g2),
        ]),
        Err(InputError::NotOnCurve)
    );
}

#[test]
fn a_different_g2_encoding_is_independently_validated() {
    assert_eq!(
        pairing_product_is_one(&[
            pair(g1_generator(), g2_generator()),
            pair(g1_generator(), g2_non_subgroup()),
        ]),
        Err(InputError::NotInSubgroup)
    );
}
