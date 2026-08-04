pub mod agave_fixtures;

use agave_fixtures::{bytes, fr_modulus, scalar};
use helios_bn254::{FR_MAX_ELEMS, InputError, ScalarBytes, fr_batch_invert, fr_lincomb};

#[test]
fn lincomb_uses_canonical_big_endian_fr_arithmetic() {
    // 2*3 + 4*5 = 26. Small values place all significant bytes at the end,
    // catching an accidental little-endian implementation immediately.
    let a = [scalar(2), scalar(4)];
    let b = [scalar(3), scalar(5)];
    assert_eq!(fr_lincomb(&a, &b), Ok(scalar(26)));

    // Aliasing is valid at the syscall layer: <a,a> = 2^2 + 3^2 = 13.
    let aliased = [scalar(2), scalar(3)];
    assert_eq!(fr_lincomb(&aliased, &aliased), Ok(scalar(13)));

    let zeros = [scalar(0); 4];
    assert_eq!(fr_lincomb(&zeros, &[scalar(1); 4]), Ok(scalar(0)));
}

#[test]
fn lincomb_rejects_shape_errors_before_elements() {
    assert_eq!(fr_lincomb(&[], &[]), Err(InputError::ZeroInput));
    assert_eq!(
        fr_lincomb(&[], &[fr_modulus()]),
        Err(InputError::LengthMismatch)
    );
    assert_eq!(
        fr_lincomb(&[fr_modulus()], &[]),
        Err(InputError::LengthMismatch)
    );

    let over = vec![fr_modulus(); FR_MAX_ELEMS + 1];
    assert_eq!(fr_lincomb(&over, &over), Err(InputError::CapExceeded));

    // Exactly the cap is accepted; zero is canonical and makes this inexpensive.
    let at_cap = vec![scalar(0); FR_MAX_ELEMS];
    assert_eq!(fr_lincomb(&at_cap, &at_cap), Ok(scalar(0)));
}

#[test]
fn lincomb_rejects_every_noncanonical_scalar_form() {
    let mut modulus_plus_one = fr_modulus().0;
    modulus_plus_one[31] += 1;
    for bad in [
        fr_modulus(),
        ScalarBytes(modulus_plus_one),
        ScalarBytes([0xff; 32]),
    ] {
        assert_eq!(
            fr_lincomb(&[bad], &[scalar(1)]),
            Err(InputError::NonCanonical)
        );
        assert_eq!(
            fr_lincomb(&[scalar(1)], &[bad]),
            Err(InputError::NonCanonical)
        );
    }
}

#[test]
fn batch_invert_matches_fixed_field_vectors_and_order() {
    let input = [scalar(1), scalar(2), scalar(3), scalar(5)];
    let expected = vec![
        scalar(1),
        ScalarBytes(bytes(
            "183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000001",
        )),
        ScalarBytes(bytes(
            "2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001",
        )),
        ScalarBytes(bytes(
            "135b52945a13d9aa49b9b57c33cd568ba9ae5ce9ca4a2d06e7f3fbd4c6666667",
        )),
    ];
    assert_eq!(fr_batch_invert(&input), Ok(expected));
}

#[test]
fn batch_invert_rejects_empty_zero_noncanonical_and_over_cap() {
    assert_eq!(fr_batch_invert(&[]), Err(InputError::ZeroInput));

    for position in 0..3 {
        let mut values = [scalar(2), scalar(3), scalar(5)];
        values[position] = scalar(0);
        assert_eq!(fr_batch_invert(&values), Err(InputError::ZeroInput));
    }

    for position in 0..2 {
        let mut values = [scalar(2), scalar(3)];
        values[position] = fr_modulus();
        assert_eq!(fr_batch_invert(&values), Err(InputError::NonCanonical));
    }

    let over = vec![fr_modulus(); FR_MAX_ELEMS + 1];
    assert_eq!(fr_batch_invert(&over), Err(InputError::CapExceeded));
}
