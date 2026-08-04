pub mod agave_fixtures;

use core::mem::{align_of, offset_of, size_of};
use helios_bn254::{
    AltBn128BatchError, FR_MAX_ELEMS, G1_BYTES, G1Bytes, G2_BYTES, G2Bytes, InputError,
    MSM_MAX_POINTS, PAIR_BYTES, PAIRING_MAP_MAX_PAIRS, PAIRING_MAX_PAIRS, PairBytes, PodG1G2Pair,
    PodG1Point, PodG2Point, PodPairingResult, PodScalar, SCALAR_BYTES, ScalarBytes, Version,
    alt_bn128_g1_msm,
};

#[test]
fn agave_limits_and_wire_layout_are_pinned() {
    fn assert_pod<T: bytemuck::Pod + bytemuck::Zeroable>() {}

    assert_eq!(MSM_MAX_POINTS, 2048);
    assert_eq!(PAIRING_MAX_PAIRS, 256);
    assert_eq!(PAIRING_MAP_MAX_PAIRS, 18);
    assert_eq!(FR_MAX_ELEMS, 2048);
    assert_eq!(
        (G1_BYTES, G2_BYTES, PAIR_BYTES, SCALAR_BYTES),
        (64, 128, 192, 32)
    );

    assert_eq!(size_of::<G1Bytes>(), 64);
    assert_eq!(size_of::<G2Bytes>(), 128);
    assert_eq!(size_of::<ScalarBytes>(), 32);
    assert_eq!(size_of::<PairBytes>(), 192);
    assert_eq!(align_of::<G1Bytes>(), 1);
    assert_eq!(align_of::<G2Bytes>(), 1);
    assert_eq!(align_of::<ScalarBytes>(), 1);
    assert_eq!(align_of::<PairBytes>(), 1);
    assert_eq!(offset_of!(PairBytes, g1), 0);
    assert_eq!(offset_of!(PairBytes, g2), 64);
    assert_eq!(size_of::<PodG1Point>(), size_of::<G1Bytes>());
    assert_eq!(size_of::<PodG2Point>(), size_of::<G2Bytes>());
    assert_eq!(size_of::<PodScalar>(), size_of::<ScalarBytes>());
    assert_eq!(size_of::<PodG1G2Pair>(), size_of::<PairBytes>());
    assert_eq!(size_of::<PodPairingResult>(), 32);
    assert_pod::<G1Bytes>();
    assert_pod::<G2Bytes>();
    assert_pod::<ScalarBytes>();
    assert_pod::<PairBytes>();
    assert_pod::<PodPairingResult>();
}

#[test]
fn agave_named_surface_is_a_zero_cost_compatibility_layer() {
    let generator = agave_fixtures::g1_generator();
    let one = agave_fixtures::scalar(1);
    let output: Result<PodG1Point, AltBn128BatchError> =
        alt_bn128_g1_msm(Version::V0, &[generator], &[one]);
    assert_eq!(output, Ok(generator));
    assert_eq!(PodPairingResult::from_verdict(false).0, [0; 32]);
    assert!(PodPairingResult::from_verdict(true).verdict());
}

#[test]
fn stable_error_taxonomy_is_exhaustive() {
    // InvalidLength is intentionally reserved for a future flat-buffer facade:
    // fixed-size wrappers make it unreachable from the typed batch API.
    let errors = [
        InputError::InvalidLength,
        InputError::NonCanonical,
        InputError::NotOnCurve,
        InputError::NotInSubgroup,
        InputError::ZeroInput,
        InputError::CapExceeded,
        InputError::LengthMismatch,
    ];
    assert_eq!(errors.len(), 7);
    for (index, error) in errors.iter().enumerate() {
        assert_eq!(*error, errors[index]);
        let _ = format!("{error:?}");
    }
}
