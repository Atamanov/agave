mod agave_fixtures;

use agave_fixtures::{
    fq_modulus, fr_minus_one, fr_modulus, g1_generator, g1_negative_generator, g1_off_curve, scalar,
};
use helios_bn254::{G1Bytes, InputError, MSM_MAX_POINTS, g1_msm};

#[test]
fn msm_matches_eip197_generator_vectors() {
    let generator = g1_generator();
    assert_eq!(g1_msm(&[generator], &[scalar(1)]), Ok(generator));
    assert_eq!(g1_msm(&[generator], &[scalar(0)]), Ok(G1Bytes([0; 64])));
    assert_eq!(
        g1_msm(&[generator], &[fr_minus_one()]),
        Ok(g1_negative_generator())
    );

    // [1]P + [r-1]P = [r]P = infinity, encoded as exactly 64 zero bytes.
    assert_eq!(
        g1_msm(&[generator, generator], &[scalar(1), fr_minus_one()]),
        Ok(G1Bytes([0; 64]))
    );
}

#[test]
fn msm_accepts_infinity_as_a_group_element() {
    let infinity = G1Bytes([0; 64]);
    assert_eq!(
        g1_msm(
            &[g1_generator(), infinity, g1_generator()],
            &[scalar(1), scalar(123), fr_minus_one()],
        ),
        Ok(infinity)
    );
}

#[test]
fn msm_shape_errors_have_agave_precedence() {
    assert_eq!(g1_msm(&[], &[]), Err(InputError::ZeroInput));
    assert_eq!(
        g1_msm(&[], &[fr_modulus()]),
        Err(InputError::LengthMismatch)
    );

    // Count mismatch wins even if one side is independently over the cap.
    let too_many_points = vec![G1Bytes([0; 64]); MSM_MAX_POINTS + 1];
    assert_eq!(
        g1_msm(&too_many_points, &[]),
        Err(InputError::LengthMismatch)
    );

    // Cap checking happens before parsing any declared element.
    let bad_scalars = vec![fr_modulus(); MSM_MAX_POINTS + 1];
    assert_eq!(
        g1_msm(&too_many_points, &bad_scalars),
        Err(InputError::CapExceeded)
    );

    let at_cap_points = vec![G1Bytes([0; 64]); MSM_MAX_POINTS];
    let at_cap_scalars = vec![scalar(0); MSM_MAX_POINTS];
    assert_eq!(
        g1_msm(&at_cap_points, &at_cap_scalars),
        Ok(G1Bytes([0; 64]))
    );
}

#[test]
fn msm_rejects_bad_coordinates_and_scalars() {
    assert_eq!(
        g1_msm(&[g1_off_curve()], &[scalar(1)]),
        Err(InputError::NotOnCurve)
    );

    for coordinate in [0usize, 1] {
        let mut bad = g1_generator();
        bad.0[coordinate * 32..(coordinate + 1) * 32].copy_from_slice(&fq_modulus());
        assert_eq!(g1_msm(&[bad], &[scalar(1)]), Err(InputError::NonCanonical));
    }

    for bad in [fr_modulus(), helios_bn254::ScalarBytes([0xff; 32])] {
        assert_eq!(
            g1_msm(&[g1_generator()], &[bad]),
            Err(InputError::NonCanonical)
        );
    }
}

#[test]
fn msm_validates_all_points_before_any_scalar() {
    assert_eq!(
        g1_msm(
            &[g1_generator(), g1_off_curve()],
            &[fr_modulus(), scalar(1)]
        ),
        Err(InputError::NotOnCurve)
    );
}
