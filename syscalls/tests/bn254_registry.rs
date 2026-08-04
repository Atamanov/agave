#![cfg(all(
    feature = "agave-unstable-api",
    any(feature = "backend-b4-helius", feature = "backend-b5-helius-ifma"),
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized"),
    not(feature = "backend-b3-mcl")
))]

use {
    ark_bn254::{Fr, G1Affine, G1Projective, G2Affine},
    ark_ec::{AffineRepr, CurveGroup, PrimeGroup},
    ark_ff::{BigInteger, PrimeField},
    solana_bn254_batch_syscall::{
        PodG1G2Pair, PodG1Point, PodG1RegisteredG2Pair, PodG2Point, PodScalar,
        PodTrustedGtExponent, Version, alt_bn128_pairing_map,
    },
    solana_pubkey::Pubkey,
    solana_syscalls::bn254_registry::{
        PreparedVkRegistryAccount, RegistryAccountView, RegistryError,
        pairing_check_registry_account, prepare_registry_account_bytes, registry_keyset_digest,
        trusted_gt_multiexp_registry_account,
    },
};

static REGISTRY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn fq(value: &ark_bn254::Fq) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let offset = 32usize.checked_sub(bytes.len()).unwrap();
    out[offset..].copy_from_slice(&bytes);
    out
}

fn g1(point: G1Affine) -> PodG1Point {
    if point.is_zero() {
        return PodG1Point([0; 64]);
    }
    let (x, y) = point.xy().unwrap();
    let mut out = [0; 64];
    out[..32].copy_from_slice(&fq(&x));
    out[32..].copy_from_slice(&fq(&y));
    PodG1Point(out)
}

fn g2(point: G2Affine) -> PodG2Point {
    let (x, y) = point.xy().unwrap();
    let mut out = [0; 128];
    out[..32].copy_from_slice(&fq(&x.c1));
    out[32..64].copy_from_slice(&fq(&x.c0));
    out[64..96].copy_from_slice(&fq(&y.c1));
    out[96..].copy_from_slice(&fq(&y.c0));
    PodG2Point(out)
}

fn fixture() -> (PreparedVkRegistryAccount, [u8; 32], PodG1G2Pair) {
    let consumer = [7u8; 32];
    let source = PodG1G2Pair {
        g1: g1(G1Affine::generator()),
        g2: g2(G2Affine::generator()),
    };
    let prepared = prepare_registry(consumer, &[source.g2], &[source]);
    (prepared, consumer, source)
}

fn prepare_registry(
    consumer: [u8; 32],
    g2_sources: &[PodG2Point],
    gt_sources: &[PodG1G2Pair],
) -> PreparedVkRegistryAccount {
    prepare_registry_account_bytes(
        consumer,
        registry_keyset_digest(g2_sources, gt_sources),
        g2_sources,
        gt_sources,
    )
    .unwrap()
}

fn view<'a>(
    prepared: &'a PreparedVkRegistryAccount,
    consumer: [u8; 32],
) -> RegistryAccountView<'a> {
    RegistryAccountView {
        key: prepared.key,
        owner: Pubkey::new_from_array(consumer),
        data: &prepared.data,
        is_writable: false,
    }
}

#[test]
fn registered_pairing_matches_full_pairing() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let (prepared, consumer, source) = fixture();
    let full = [PodG1G2Pair {
        g1: g1((-G1Projective::generator()).into_affine()),
        g2: source.g2,
    }];
    let registered = [PodG1RegisteredG2Pair {
        g1: source.g1,
        g2_id: prepared.g2_ids[0],
    }];
    assert!(
        pairing_check_registry_account(consumer, view(&prepared, consumer), &full, &registered,)
            .unwrap()
    );
}

#[test]
fn trusted_target_lookup_matches_pairing_map() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let (prepared, consumer, source) = fixture();
    let mut one = [0u8; 32];
    one[31] = 1;
    let actual = trusted_gt_multiexp_registry_account(
        consumer,
        view(&prepared, consumer),
        &[PodTrustedGtExponent {
            target_id: prepared.gt_ids[0],
            exponent: PodScalar(one),
        }],
    )
    .unwrap();
    assert_eq!(
        actual,
        alt_bn128_pairing_map(Version::V0, &[source]).unwrap()
    );
}

#[test]
fn owner_readonly_and_id_authentication_are_enforced() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let (prepared, consumer, source) = fixture();
    let registered = [PodG1RegisteredG2Pair {
        g1: source.g1,
        g2_id: prepared.g2_ids[0],
    }];
    let mut wrong_owner = view(&prepared, consumer);
    wrong_owner.owner = Pubkey::new_unique();
    assert!(matches!(
        pairing_check_registry_account(consumer, wrong_owner, &[], &registered),
        Err(RegistryError::InvalidAccount)
    ));

    let mut writable = view(&prepared, consumer);
    writable.is_writable = true;
    assert!(matches!(
        pairing_check_registry_account(consumer, writable, &[], &registered),
        Err(RegistryError::InvalidAccount)
    ));

    let mut forged = registered;
    forged[0].g2_id[0] ^= 1;
    assert!(matches!(
        pairing_check_registry_account(consumer, view(&prepared, consumer), &[], &forged),
        Err(RegistryError::InvalidIdentifier)
    ));
}

#[test]
fn duplicate_and_misdirected_indexed_ids_are_rejected() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let (prepared, consumer, source) = fixture();
    let operand = PodG1RegisteredG2Pair {
        g1: source.g1,
        g2_id: prepared.g2_ids[0],
    };
    assert!(matches!(
        pairing_check_registry_account(
            consumer,
            view(&prepared, consumer),
            &[],
            &[operand, operand],
        ),
        Err(RegistryError::InvalidIdentifier)
    ));

    let mut misdirected_id = prepared.gt_ids[0];
    misdirected_id[..2].copy_from_slice(&1u16.to_le_bytes());
    let mut one = [0u8; 32];
    one[31] = 1;
    assert!(matches!(
        trusted_gt_multiexp_registry_account(
            consumer,
            view(&prepared, consumer),
            &[PodTrustedGtExponent {
                target_id: misdirected_id,
                exponent: PodScalar(one),
            }],
        ),
        Err(RegistryError::InvalidIdentifier)
    ));
}

#[test]
fn distinct_targets_are_multiexponentiated_and_init_is_deterministic() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let consumer = [3u8; 32];
    let q = G2Affine::generator();
    let source1 = PodG1G2Pair {
        g1: g1(G1Affine::generator()),
        g2: g2(q),
    };
    let source2 = PodG1G2Pair {
        g1: g1(G1Projective::generator()
            .mul_bigint(Fr::from(2u64).into_bigint())
            .into_affine()),
        g2: g2(q),
    };
    let prepared = prepare_registry(consumer, &[], &[source1, source2]);
    let again = prepare_registry(consumer, &[], &[source1, source2]);
    assert_eq!(prepared.key, again.key);
    assert_eq!(prepared.data, again.data);

    let mut one = [0u8; 32];
    one[31] = 1;
    let actual = trusted_gt_multiexp_registry_account(
        consumer,
        view(&prepared, consumer),
        &[
            PodTrustedGtExponent {
                target_id: prepared.gt_ids[0],
                exponent: PodScalar(one),
            },
            PodTrustedGtExponent {
                target_id: prepared.gt_ids[1],
                exponent: PodScalar(one),
            },
        ],
    )
    .unwrap();
    assert_eq!(
        actual,
        alt_bn128_pairing_map(Version::V0, &[source1, source2]).unwrap()
    );

    assert!(matches!(
        prepare_registry_account_bytes(
            consumer,
            registry_keyset_digest(&[PodG2Point([0xff; 128])], &[]),
            &[PodG2Point([0xff; 128])],
            &[],
        ),
        Err(RegistryError::Backend(_))
    ));

    assert!(matches!(
        prepare_registry_account_bytes(consumer, [1u8; 32], &[], &[source1]),
        Err(RegistryError::InvalidIdentifier)
    ));
}

#[cfg(feature = "research-observer")]
#[test]
fn hot_registered_pairing_observer_proves_no_subgroup_or_line_preparation() {
    use solana_bn254_batch_syscall::{
        research_observer, trusted_gt_from_pair, trusted_gt_multiexp,
    };

    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    research_observer::reset();
    let (prepared, consumer, source) = fixture();
    // One subgroup validation and one prepared-line schedule are created only
    // by init (the GT target is the second init pairing source).
    assert_eq!(research_observer::observed_registry_init_shape(), (1, 1));
    assert_eq!(
        research_observer::observed_registry_g2_preparation_calls(),
        (1, 1)
    );

    research_observer::reset();
    let full = [PodG1G2Pair {
        g1: g1((-G1Projective::generator()).into_affine()),
        g2: source.g2,
    }];
    let registered = [PodG1RegisteredG2Pair {
        g1: source.g1,
        g2_id: prepared.g2_ids[0],
    }];
    for _ in 0..5 {
        assert!(pairing_check_registry_account(
            consumer,
            view(&prepared, consumer),
            &full,
            &registered,
        )
        .unwrap());
    }
    assert_eq!(
        research_observer::observed_registered_pairing_shapes(),
        vec![(1, 1, 2); 5]
    );
    // The hot call did not invoke either registry initialization primitive:
    // zero registered subgroup checks and zero registered line preparations.
    assert_eq!(research_observer::observed_registry_init_shape(), (0, 0));
    assert_eq!(
        research_observer::observed_registry_g2_preparation_calls(),
        (0, 0)
    );

    let target = trusted_gt_from_pair(&source).unwrap();
    let mut one = [0u8; 32];
    one[31] = 1;
    let mut rho = [0u8; 32];
    rho[31] = 2;
    trusted_gt_multiexp(&[target.clone(), target], &[PodScalar(one), PodScalar(rho)]).unwrap();
    assert_eq!(
        research_observer::observed_gt_multiexp_shapes(),
        vec![(2, 1)]
    );
}

#[cfg(all(feature = "research-observer", feature = "backend-b5-helius-ifma"))]
#[test]
fn mixed_five_plus_three_registry_call_attests_ifma_dispatch() {
    use solana_bn254_batch_syscall::research_observer;

    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let consumer = [0x35; 32];
    let source = PodG1G2Pair {
        g1: g1(G1Affine::generator()),
        g2: g2(G2Affine::generator()),
    };
    let prepared = prepare_registry(consumer, &[source.g2; 3], &[]);
    let full = [source; 5];
    let minus_seven = -G1Projective::generator()
        .mul_bigint(Fr::from(7u64).into_bigint())
        .into_affine();
    let registered = [
        PodG1RegisteredG2Pair {
            g1: source.g1,
            g2_id: prepared.g2_ids[0],
        },
        PodG1RegisteredG2Pair {
            g1: source.g1,
            g2_id: prepared.g2_ids[1],
        },
        PodG1RegisteredG2Pair {
            g1: g1(minus_seven),
            g2_id: prepared.g2_ids[2],
        },
    ];

    research_observer::reset();
    assert!(
        pairing_check_registry_account(consumer, view(&prepared, consumer), &full, &registered,)
            .unwrap()
    );
    assert_eq!(
        research_observer::observed_registered_pairing_shapes(),
        vec![(5, 3, 8)]
    );
    assert_eq!(
        research_observer::observed_ifma_mixed_batch8_dispatches(),
        1
    );
}
