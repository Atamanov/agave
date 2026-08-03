#![cfg(feature = "agave-unstable-api")]
#![allow(clippy::arithmetic_side_effects)]

//! Cross-branch wire-conformance fingerprint.
//!
//! Several backend branches of this crate must be byte-identical on the wire:
//! the same output bytes AND the same error variant, under the same check
//! precedence, for every input. This test drives the four public fns through
//! a fixed battery -- sizes past plausible dispatch thresholds, algebraic
//! identities that must reduce exactly (infinity, cancellation), scalar
//! representation edges (0, 1, limb boundaries 2^64/2^128/2^192, q-1),
//! positional edges (infinity or zero mid-input), cap-exact and cap+1, every
//! reachable error path with its precedence, a seeded fuzz sweep, and a
//! groth16-shaped end-to-end at n = 1 and 4 -- and folds every outcome into
//! one keccak256 fingerprint (keccak because the workspace already ships
//! solana-keccak-hasher; the choice of hash carries no meaning).
//!
//! Asserting against the committed GOLDEN constant lets each branch prove
//! conformance from its own `cargo test`, with no co-building of the other
//! branches; a single changed output byte or error discriminant anywhere in
//! the battery fails the assert. ANY intentional wire-behavior change must
//! update GOLDEN in the same commit and justify itself in that commit's
//! message.
//!
//! The perf-harness battery this ports also fed malformed byte LENGTHS
//! (truncated points and scalars). That class cannot exist at this typed
//! boundary -- element widths are fixed by the pod types, so a ragged length
//! faults at the syscall boundary -- and those cases are dropped here.
//!
//! Fixture bytes come from a seeded StdRng, so the fingerprint also depends
//! on the rand crate's StdRng algorithm staying fixed across the compared
//! branches; the branches share one Cargo.lock lineage, which makes that
//! hold. A rand major bump regenerates GOLDEN everywhere at once.

use {
    ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective},
    ark_ec::{AffineRepr, CurveGroup, PrimeGroup},
    ark_ff::{Field, PrimeField, UniformRand, Zero},
    ark_std::rand::{Rng, RngCore, SeedableRng, rngs::StdRng},
    solana_bn254_batch_syscall::{
        AltBn128BatchError, G1_BYTES, G2_BYTES, PodG1G2Pair, PodG1Point, PodG2Point, PodScalar,
        SCALAR_BYTES, Version, alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb, alt_bn128_g1_msm,
        alt_bn128_pairing_check,
    },
    solana_keccak_hasher::Hasher,
    std::sync::OnceLock,
};

/// Keccak256 hex over every battery outcome. Update ONLY with an intentional
/// wire-behavior change, in the same commit.
const GOLDEN: &str = "b0409af414dfbc41e08df43d723a68cca7dd7c4b838b2b23e65d34751691534c";

/// Number of absorbed cases. Pinned so a silently skipped battery section
/// (an early return, a miscounted loop) fails loud instead of shrinking the
/// hashed surface.
const CASE_COUNT: usize = 700;

#[test]
fn test_wire_fingerprint_matches_golden() {
    let (fingerprint, cases) = battery();
    println!("wire fingerprint: {fingerprint} ({cases} cases)");
    assert_eq!(fingerprint.as_str(), GOLDEN);
}

#[test]
fn test_battery_case_count_is_pinned() {
    let (_, cases) = battery();
    assert_eq!(*cases, CASE_COUNT);
}

/// One battery run shared by both tests.
fn battery() -> &'static (String, usize) {
    static RESULT: OnceLock<(String, usize)> = OnceLock::new();
    RESULT.get_or_init(run_battery)
}

fn run_battery() -> (String, usize) {
    let mut fp = Fingerprint::default();
    let mut r = rng();
    msm_battery(&mut fp, &mut r);
    pairing_battery(&mut fp, &mut r);
    fr_battery(&mut fp, &mut r);
    for n in [1usize, 4] {
        let fixture = groth16_setup(n);
        fp.absorb(&format!("groth16_{n}"), groth16_verify(&fixture));
    }
    fuzz_battery(&mut fp, &mut r);
    fp.finish()
}

// ---------------------------------------------------------------------------
// fingerprint accumulation

#[derive(Default)]
struct Fingerprint {
    hasher: Hasher,
    cases: usize,
}

type Outcome = Result<Vec<u8>, AltBn128BatchError>;

impl Fingerprint {
    /// Domain-separate by label, then absorb an Ok/Err tag followed by the
    /// output bytes or the stable error discriminant.
    fn absorb(&mut self, label: &str, outcome: Outcome) {
        self.cases += 1;
        self.hasher.hash(label.as_bytes());
        match outcome {
            Ok(bytes) => {
                self.hasher.hash(&[0u8]);
                self.hasher.hash(&bytes);
            }
            Err(e) => self.hasher.hash(&[1u8, error_code(&e)]),
        }
    }

    fn finish(self) -> (String, usize) {
        let hex: String = self
            .hasher
            .result()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        (hex, self.cases)
    }
}

/// Stable one-byte discriminant per error variant. Explicit, not derived, so
/// reordering the enum cannot silently change the codes the fingerprint pins.
fn error_code(e: &AltBn128BatchError) -> u8 {
    match e {
        AltBn128BatchError::InvalidLength => 1,
        AltBn128BatchError::NonCanonical => 2,
        AltBn128BatchError::NotOnCurve => 3,
        AltBn128BatchError::NotInSubgroup => 4,
        AltBn128BatchError::ZeroInput => 5,
        AltBn128BatchError::CapExceeded => 6,
        AltBn128BatchError::LengthMismatch => 7,
        // Only the solana target produces this, so no fingerprint case reaches it.
        AltBn128BatchError::SyscallFailed => 8,
    }
}

// uniform byte-vector outcomes so every op feeds the same absorb
fn msm(points: &[PodG1Point], scalars: &[PodScalar]) -> Outcome {
    alt_bn128_g1_msm(Version::V0, points, scalars).map(|p| p.0.to_vec())
}

fn pairing(pairs: &[PodG1G2Pair]) -> Outcome {
    alt_bn128_pairing_check(Version::V0, pairs).map(|v| vec![u8::from(v)])
}

fn lincomb(a: &[PodScalar], b: &[PodScalar]) -> Outcome {
    alt_bn128_fr_lincomb(Version::V0, a, b).map(|s| s.0.to_vec())
}

fn invert(a: &[PodScalar]) -> Outcome {
    alt_bn128_fr_batch_invert(Version::V0, a).map(|v| v.iter().flat_map(|s| s.0).collect())
}

// ---------------------------------------------------------------------------
// deterministic fixtures (fixed seed; identity is seed + call order alone)

const SEED: u64 = 0xa17b428;

fn rng() -> StdRng {
    StdRng::seed_from_u64(SEED)
}

fn pod_g1(p: G1Projective) -> PodG1Point {
    PodG1Point::from(&p.into_affine())
}

fn fq_be(x: &Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in x.into_bigint().0.iter().enumerate() {
        let start = 32 - 8 * (i + 1);
        out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

// x1 | x0 | y1 | y0 (imaginary limb first, the wire order); all zeros for
// infinity
fn pod_g2(p: &G2Affine) -> PodG2Point {
    let mut out = [0u8; G2_BYTES];
    if let Some((x, y)) = p.xy() {
        out[..32].copy_from_slice(&fq_be(&x.c1));
        out[32..64].copy_from_slice(&fq_be(&x.c0));
        out[64..96].copy_from_slice(&fq_be(&y.c1));
        out[96..].copy_from_slice(&fq_be(&y.c0));
    }
    PodG2Point(out)
}

fn pod_fr(s: Fr) -> PodScalar {
    PodScalar::from(&s)
}

fn fq_modulus_be() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in Fq::MODULUS.0.iter().enumerate() {
        let start = 32 - 8 * (i + 1);
        out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

fn fr_modulus_be() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in Fr::MODULUS.0.iter().enumerate() {
        let start = 32 - 8 * (i + 1);
        out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

/// Deterministic point on the twist curve outside the r-order subgroup: the
/// smallest x = (k, 0) whose lift is on the curve and fails the subgroup
/// check. The twist cofactor is ~2^254, so almost every lift qualifies.
fn non_subgroup_g2() -> G2Affine {
    (0u64..)
        .find_map(|k| {
            let x = Fq2::new(Fq::from(k), Fq::zero());
            G2Affine::get_point_from_x_unchecked(x, true)
                .filter(|p| !p.is_in_correct_subgroup_assuming_on_curve())
        })
        .expect("twist cofactor > 1 guarantees non-subgroup lifts")
}

fn msm_input(r: &mut StdRng, n: usize) -> (Vec<PodG1Point>, Vec<PodScalar>) {
    let mut points = Vec::with_capacity(n);
    let mut scalars = Vec::with_capacity(n);
    for _ in 0..n {
        points.push(pod_g1(G1Projective::rand(r)));
        scalars.push(pod_fr(Fr::rand(r)));
    }
    (points, scalars)
}

fn fr_array(r: &mut StdRng, n: usize) -> Vec<PodScalar> {
    (0..n).map(|_| pod_fr(Fr::rand(r))).collect()
}

fn rand_array<const N: usize>(r: &mut StdRng) -> [u8; N] {
    let mut out = [0u8; N];
    r.fill_bytes(&mut out);
    out
}

/// Sum-telescoping pairing input: n pairs (s_i * P, Q) with the last scalar
/// chosen so the product pairs to the GT identity for n >= 2. `flipped`
/// negates the first G1: the verdict must flip to false without an error.
struct PairingInput {
    valid: Vec<PodG1G2Pair>,
    flipped: Vec<PodG1G2Pair>,
}

fn pairing_input(r: &mut StdRng, n: usize) -> PairingInput {
    let q = pod_g2(&G2Projective::rand(r).into_affine());
    let p = G1Projective::rand(r);
    let mut sum = Fr::zero();
    let mut g1s = Vec::with_capacity(n);
    for i in 0..n {
        let g1 = if n >= 2 && i == n - 1 {
            p * -sum
        } else {
            let s = Fr::rand(r);
            sum += s;
            p * s
        };
        g1s.push(g1);
    }
    let serialize = |first: G1Projective| -> Vec<PodG1G2Pair> {
        g1s.iter()
            .enumerate()
            .map(|(i, &g1)| PodG1G2Pair {
                g1: pod_g1(if i == 0 { first } else { g1 }),
                g2: q,
            })
            .collect()
    };
    PairingInput {
        valid: serialize(g1s[0]),
        flipped: serialize(-g1s[0]),
    }
}

/// Scalar values at representation edges: 0, 1, 2, limb boundaries, q-1 and
/// its half. (q-1)^2 and cross-limb carries must reduce identically in any
/// delayed-reduction or raw-residue scheme.
fn edge_scalars() -> Vec<Fr> {
    let two_64 = Fr::from(u64::MAX) + Fr::from(1u64);
    let minus_one = -Fr::from(1u64);
    vec![
        Fr::zero(),
        Fr::from(1u64),
        Fr::from(2u64),
        Fr::from(u64::MAX),
        two_64,
        two_64 * two_64,
        two_64 * two_64 * two_64,
        minus_one,
        minus_one * Fr::from(2u64).inverse().expect("2 invertible"),
    ]
}

// ---------------------------------------------------------------------------
// batteries

fn msm_battery(fp: &mut Fingerprint, r: &mut StdRng) {
    // 96 and 256 sit past any plausible small-n dispatch threshold, so both
    // branches of a dispatching implementation are covered
    for n in [1usize, 2, 3, 7, 8, 96, 256] {
        let (points, scalars) = msm_input(r, n);
        fp.absorb(&format!("msm{n}"), msm(&points, &scalars));
    }
    let point = pod_g1(G1Projective::rand(r));
    // [1]P + [-1]P reduces to infinity, the all-zero encoding
    let one_minus_one = [pod_fr(Fr::from(1u64)), pod_fr(-Fr::from(1u64))];
    fp.absorb("msm_inf", msm(&[point, point], &one_minus_one));
    // every edge scalar against one fixed point
    for (i, s) in edge_scalars().into_iter().enumerate() {
        fp.absorb(&format!("msm_edge{i}"), msm(&[point], &[pod_fr(s)]));
    }
    // zero scalar mid-input: the zero term contributes nothing
    {
        let (points, mut scalars) = msm_input(r, 3);
        scalars[1] = pod_fr(Fr::zero());
        fp.absorb("msm_zero_mid", msm(&points, &scalars));
    }
    // infinity point mid-input: skipped by the group law
    {
        let (mut points, scalars) = msm_input(r, 3);
        points[1] = PodG1Point([0u8; G1_BYTES]);
        fp.absorb("msm_inf_mid", msm(&points, &scalars));
    }
    // all points infinity; all scalars zero
    {
        let scalars = fr_array(r, 4);
        fp.absorb(
            "msm_all_inf",
            msm(&[PodG1Point([0u8; G1_BYTES]); 4], &scalars),
        );
        let (points, _) = msm_input(r, 4);
        fp.absorb(
            "msm_all_zero_s",
            msm(&points, &[PodScalar([0u8; SCALAR_BYTES]); 4]),
        );
    }
    // duplicate points: [s1]P + [s2]P == [s1+s2]P through the bucket logic
    {
        fp.absorb("msm_dup", msm(&[point, point], &fr_array(r, 2)));
        fp.absorb("msm_dup7", msm(&[point; 7], &fr_array(r, 7)));
    }
    // cap exact and cap + 1
    {
        let (points, scalars) = msm_input(r, 2048);
        fp.absorb("msm_cap", msm(&points, &scalars));
        fp.absorb(
            "msm_cap1",
            msm(
                &[PodG1Point([0u8; G1_BYTES]); 2049],
                &[PodScalar([0u8; SCALAR_BYTES]); 2049],
            ),
        );
    }
    // error paths, each with its discriminant and precedence; the ragged
    // length cases of the byte-level battery have no typed equivalent
    let (points1, scalars1) = msm_input(r, 1);
    fp.absorb("msm_empty", msm(&[], &[]));
    fp.absorb("msm_mismatch", msm(&[points1[0], points1[0]], &scalars1));
    {
        let mut bad = points1.clone();
        bad[0].0[..32].copy_from_slice(&fq_modulus_be());
        fp.absorb("msm_bad_x", msm(&bad, &scalars1));
        let mut bad = points1.clone();
        bad[0].0[32..].copy_from_slice(&fq_modulus_be());
        fp.absorb("msm_bad_y", msm(&bad, &scalars1));
    }
    {
        let on = G1Projective::rand(r).into_affine();
        let off = G1Affine::new_unchecked(on.x, on.y + Fq::from(1u64));
        fp.absorb("msm_off_curve", msm(&[PodG1Point::from(&off)], &scalars1));
    }
    // x = 0 with y != 0 is NOT infinity and must fail the curve check
    {
        let mut near_inf = [0u8; G1_BYTES];
        near_inf[63] = 1;
        fp.absorb("msm_near_inf", msm(&[PodG1Point(near_inf)], &scalars1));
    }
    fp.absorb(
        "msm_bad_scalar",
        msm(&points1, &[PodScalar(fr_modulus_be())]),
    );
    fp.absorb(
        "msm_ff_scalar",
        msm(&points1, &[PodScalar([0xffu8; SCALAR_BYTES])]),
    );
    // combined defects pin cross-check PRECEDENCE, not just reachability: a
    // branch reordering its checks answers these with a different variant
    {
        // cap+1 with a non-canonical head element: the cap check wins before
        // any element is parsed
        let mut points = vec![PodG1Point([0u8; G1_BYTES]); 2049];
        points[0].0[..32].copy_from_slice(&[0xffu8; 32]);
        let scalars = vec![PodScalar([0u8; SCALAR_BYTES]); 2049];
        fp.absorb("msm_cap1_bad_head", msm(&points, &scalars));
        // ([], nonempty) is a length mismatch, not an empty-input error
        fp.absorb("msm_empty_vs_scalars", msm(&[], &scalars[..1]));
        // a bad point and a bad scalar in one call: points validate first
        let mut bad_point = points1.clone();
        bad_point[0].0[32..].copy_from_slice(&fq_modulus_be());
        fp.absorb(
            "msm_bad_point_and_scalar",
            msm(&bad_point, &[PodScalar(fr_modulus_be())]),
        );
        // 0xff..ff coordinate is non-canonical AND lands off-curve after any
        // reduction: the canonical check must fire first
        let mut ff_point = points1.clone();
        ff_point[0].0[..32].copy_from_slice(&[0xffu8; 32]);
        fp.absorb("msm_ff_coord", msm(&ff_point, &scalars1));
    }
}

fn pairing_battery(fp: &mut Fingerprint, r: &mut StdRng) {
    for n in [1usize, 2, 3, 4] {
        let input = pairing_input(r, n);
        fp.absorb(&format!("pair{n}"), pairing(&input.valid));
        fp.absorb(&format!("pairflip{n}"), pairing(&input.flipped));
    }
    // all-infinity pairs are skipped, leaving the vacuous true; 256 of them
    // also exercises the cap-exact path cheaply
    let inf_pair = PodG1G2Pair {
        g1: PodG1Point([0u8; G1_BYTES]),
        g2: PodG2Point([0u8; G2_BYTES]),
    };
    fp.absorb("pair_allinf", pairing(&[inf_pair; 3]));
    fp.absorb("pair_cap_inf", pairing(&[inf_pair; 256]));
    fp.absorb("pair_cap1", pairing(&[inf_pair; 257]));
    // an infinity pair BETWEEN two real pairs must be skipped, not break the
    // telescoping identity
    {
        let input = pairing_input(r, 2);
        let with_hole = [input.valid[0], inf_pair, input.valid[1]];
        fp.absorb("pair_inf_mid", pairing(&with_hole));
    }
    let p = G1Projective::rand(r);
    let q = G2Projective::rand(r).into_affine();
    // half-infinity pairs: either side zero skips the pair
    {
        let half = PodG1G2Pair {
            g1: PodG1Point([0u8; G1_BYTES]),
            g2: pod_g2(&q),
        };
        fp.absorb("pair_g1_inf", pairing(&[half]));
        let half = PodG1G2Pair {
            g1: pod_g1(p),
            g2: PodG2Point([0u8; G2_BYTES]),
        };
        fp.absorb("pair_g2_inf", pairing(&[half]));
    }
    // exact cancellations: e(P,Q)e(-P,Q) == 1 == e(P,Q)e(P,-Q)
    {
        let pq = PodG1G2Pair {
            g1: pod_g1(p),
            g2: pod_g2(&q),
        };
        let neg_p = PodG1G2Pair {
            g1: pod_g1(-p),
            g2: pod_g2(&q),
        };
        let p_negq = PodG1G2Pair {
            g1: pod_g1(p),
            g2: pod_g2(&-q),
        };
        fp.absorb("pair_cancel_g1", pairing(&[pq, neg_p]));
        fp.absorb("pair_cancel_g2", pairing(&[pq, p_negq]));
        // a single real pair is never the identity (non-degeneracy)
        fp.absorb("pair_single", pairing(&[pq]));
    }
    // bilinearity: e(aP,Q) * e(-P,aQ) == e(P,Q)^(a-a) == 1
    {
        let a = Fr::rand(r);
        let pairs = [
            PodG1G2Pair {
                g1: pod_g1(p * a),
                g2: pod_g2(&q),
            },
            PodG1G2Pair {
                g1: pod_g1(-p),
                g2: pod_g2(&(q * a).into_affine()),
            },
        ];
        fp.absorb("pair_bilinear", pairing(&pairs));
    }
    // error paths; the byte-level ragged case has no typed equivalent
    fp.absorb("pair_empty", pairing(&[]));
    {
        let on = G1Projective::rand(r).into_affine();
        let off = G1Affine::new_unchecked(on.x, on.y + Fq::from(1u64));
        let pair = PodG1G2Pair {
            g1: PodG1Point::from(&off),
            g2: pod_g2(&q),
        };
        fp.absorb("pair_off_g1", pairing(&[pair]));
    }
    {
        let mut bad_g2 = pod_g2(&q).0;
        // bump y0: off the twist curve
        bad_g2[127] = bad_g2[127].wrapping_add(1);
        let pair = PodG1G2Pair {
            g1: pod_g1(p),
            g2: PodG2Point(bad_g2),
        };
        fp.absorb("pair_off_g2", pairing(&[pair]));
    }
    {
        let mut bad_g2 = pod_g2(&q).0;
        bad_g2[..32].copy_from_slice(&fq_modulus_be());
        let pair = PodG1G2Pair {
            g1: pod_g1(p),
            g2: PodG2Point(bad_g2),
        };
        fp.absorb("pair_bad_g2_limb", pairing(&[pair]));
    }
    {
        let pair = PodG1G2Pair {
            g1: pod_g1(p),
            g2: pod_g2(&non_subgroup_g2()),
        };
        fp.absorb("pair_non_subgroup", pairing(&[pair]));
        // and at the LAST position after valid pairs
        let input = pairing_input(r, 2);
        let tail_bad = [input.valid[0], input.valid[1], pair];
        fp.absorb("pair_bad_last", pairing(&tail_bad));
    }
    // G2 x = 0 with y = (1, 0): not infinity, not on the twist
    {
        let mut near_inf = [0u8; G2_BYTES];
        near_inf[127] = 1;
        let pair = PodG1G2Pair {
            g1: pod_g1(p),
            g2: PodG2Point(near_inf),
        };
        fp.absorb("pair_near_inf", pairing(&[pair]));
    }
    // combined defects pin cross-check PRECEDENCE (see the msm section)
    {
        // an infinity G1 with a NON-SUBGROUP G2 partner: the pair is skipped
        // as a product factor only after full validation, so this must
        // reject, not vacuously accept
        let pair = PodG1G2Pair {
            g1: PodG1Point([0u8; G1_BYTES]),
            g2: pod_g2(&non_subgroup_g2()),
        };
        fp.absorb("pair_inf_g1_bad_g2", pairing(&[pair]));
        // off-curve G1 and non-subgroup G2 in one pair: G1 validates first
        let on = G1Projective::rand(r).into_affine();
        let off = G1Affine::new_unchecked(on.x, on.y + Fq::from(1u64));
        let pair = PodG1G2Pair {
            g1: PodG1Point::from(&off),
            g2: pod_g2(&non_subgroup_g2()),
        };
        fp.absorb("pair_off_g1_bad_g2", pairing(&[pair]));
        // cap+1 with a non-canonical head pair: the cap check wins
        let mut pairs = vec![inf_pair; 257];
        pairs[0].g2.0[..32].copy_from_slice(&fq_modulus_be());
        fp.absorb("pair_cap1_bad_head", pairing(&pairs));
    }
}

fn fr_battery(fp: &mut Fingerprint, r: &mut StdRng) {
    for n in [1usize, 2, 3, 7, 64] {
        let a = fr_array(r, n);
        let b = fr_array(r, n);
        fp.absorb(&format!("lin{n}"), lincomb(&a, &b));
        fp.absorb(&format!("inv{n}"), invert(&a));
        // aliasing: a == b computes the sum of squares
        fp.absorb(&format!("lin_alias{n}"), lincomb(&a, &a));
    }
    // representation edges paired against q-1 and against themselves
    {
        let edges: Vec<PodScalar> = edge_scalars().into_iter().map(pod_fr).collect();
        let max = vec![pod_fr(-Fr::from(1u64)); edges.len()];
        fp.absorb("lin_edge_max", lincomb(&edges, &max));
        fp.absorb("lin_edge_sq", lincomb(&edges, &edges));
        // nonzero edges only for the inverse
        let nonzero: Vec<PodScalar> = edge_scalars()
            .into_iter()
            .filter(|s| !s.is_zero())
            .map(pod_fr)
            .collect();
        fp.absorb("inv_edge", invert(&nonzero));
    }
    // all zeros and all ones
    {
        let zeros = [PodScalar([0u8; SCALAR_BYTES]); 4];
        let b = fr_array(r, 4);
        fp.absorb("lin_zeros", lincomb(&zeros, &b));
        let ones = [pod_fr(Fr::from(1u64)); 4];
        fp.absorb("lin_ones", lincomb(&ones, &b));
        fp.absorb("inv_ones", invert(&ones));
    }
    // cap exact and cap + 1
    {
        let a = fr_array(r, 2048);
        let b = fr_array(r, 2048);
        fp.absorb("lin_cap", lincomb(&a, &b));
        fp.absorb("inv_cap", invert(&a));
        let over = [PodScalar([1u8; SCALAR_BYTES]); 2049];
        fp.absorb("lin_cap1", lincomb(&over, &over));
        fp.absorb("inv_cap1", invert(&over));
    }
    // error paths: empties, mismatch, noncanonical at first/last, zero for
    // the inverse at first/mid/last; the byte-level ragged cases have no
    // typed equivalent
    {
        let a = fr_array(r, 2);
        let b = fr_array(r, 1);
        fp.absorb("lin_empty", lincomb(&[], &[]));
        fp.absorb("inv_empty", invert(&[]));
        fp.absorb("lin_mismatch", lincomb(&a, &b));
        for (label, slot) in [("first", 0usize), ("last", 2)] {
            let mut bad_a = fr_array(r, 3);
            bad_a[slot] = PodScalar(fr_modulus_be());
            let good = fr_array(r, 3);
            fp.absorb(&format!("lin_bad_a_{label}"), lincomb(&bad_a, &good));
            fp.absorb(&format!("lin_bad_b_{label}"), lincomb(&good, &bad_a));
            fp.absorb(&format!("inv_bad_{label}"), invert(&bad_a));
        }
        for (label, slot) in [("first", 0usize), ("mid", 3), ("last", 7)] {
            let mut with_zero = fr_array(r, 8);
            with_zero[slot] = PodScalar([0u8; SCALAR_BYTES]);
            fp.absorb(&format!("inv_zero_{label}"), invert(&with_zero));
        }
        fp.absorb("lin_ff", lincomb(&[PodScalar([0xffu8; SCALAR_BYTES])], &b));
        // combined defects pin cross-check PRECEDENCE (see the msm section):
        // ([], nonempty) is a mismatch, and cap+1 with a non-canonical head
        // must fail on the cap before any element parses
        fp.absorb("lin_empty_vs_b", lincomb(&[], &b));
        let mut over = vec![PodScalar([1u8; SCALAR_BYTES]); 2049];
        over[0] = PodScalar([0xffu8; SCALAR_BYTES]);
        fp.absorb("lin_cap1_bad_head", lincomb(&over, &over));
        fp.absorb("inv_cap1_bad_head", invert(&over));
    }
}

// ---------------------------------------------------------------------------
// groth16-shaped end-to-end: every fold a g1_msm, one boolean pairing_check

struct Groth16Fixture {
    proofs: Vec<(PodG1Point, PodG2Point, PodScalar)>,
    alpha_g1: PodG1Point,
    beta_g2: PodG2Point,
    gamma_g2: PodG2Point,
    delta_g2: PodG2Point,
    neg_r_sum: PodScalar,
    ic_basis: Vec<PodG1Point>,
    ic_coeffs: Vec<PodScalar>,
    c_points: Vec<PodG1Point>,
    neg_r: Vec<PodScalar>,
}

fn g1_gen(s: Fr) -> PodG1Point {
    pod_g1(G1Projective::generator() * s)
}

fn g2_gen(s: Fr) -> PodG2Point {
    pod_g2(&(G2Projective::generator() * s).into_affine())
}

/// Trapdoor-valid vanilla Groth16 batch (one public input per proof):
/// e(A_i, B_i)^{r_i} * e(alpha, beta)^{-sum r} * e(IC fold, gamma) *
/// e(C fold, delta) == 1 by construction, so the verify must return true.
fn groth16_setup(n: usize) -> Groth16Fixture {
    let mut rg = rng();
    let [alpha, beta, gamma, delta, ic0, ic1] = std::array::from_fn(|_| Fr::rand(&mut rg));
    let delta_inv = delta.inverse().expect("random delta is nonzero");
    let mut proofs = Vec::with_capacity(n);
    let mut c_points = Vec::with_capacity(n);
    let mut neg_r = Vec::with_capacity(n);
    let mut r_sum = Fr::zero();
    let mut ic1_coeff = Fr::zero();
    for _ in 0..n {
        let [a, b, x, r] = std::array::from_fn(|_| Fr::rand(&mut rg));
        let public = ic0 + x * ic1;
        // the trapdoor: C closes the Groth16 equation for this (A, B, input)
        let c = (a * b - alpha * beta - public * gamma) * delta_inv;
        proofs.push((g1_gen(a), g2_gen(b), pod_fr(r)));
        c_points.push(g1_gen(c));
        neg_r.push(pod_fr(-r));
        r_sum += r;
        ic1_coeff += r * x;
    }
    Groth16Fixture {
        proofs,
        alpha_g1: g1_gen(alpha),
        beta_g2: g2_gen(beta),
        gamma_g2: g2_gen(gamma),
        delta_g2: g2_gen(delta),
        neg_r_sum: pod_fr(-r_sum),
        ic_basis: vec![g1_gen(ic0), g1_gen(ic1)],
        ic_coeffs: vec![pod_fr(-r_sum), pod_fr(-ic1_coeff)],
        c_points,
        neg_r,
    }
}

fn groth16_verify(f: &Groth16Fixture) -> Outcome {
    let fold = |points: &[PodG1Point], scalars: &[PodScalar]| {
        alt_bn128_g1_msm(Version::V0, points, scalars)
    };
    let mut pairs = Vec::with_capacity(f.proofs.len() + 3);
    for (a, b, r) in &f.proofs {
        pairs.push(PodG1G2Pair {
            g1: fold(&[*a], std::slice::from_ref(r))?,
            g2: *b,
        });
    }
    pairs.push(PodG1G2Pair {
        g1: fold(&[f.alpha_g1], &[f.neg_r_sum])?,
        g2: f.beta_g2,
    });
    pairs.push(PodG1G2Pair {
        g1: fold(&f.ic_basis, &f.ic_coeffs)?,
        g2: f.gamma_g2,
    });
    pairs.push(PodG1G2Pair {
        g1: fold(&f.c_points, &f.neg_r)?,
        g2: f.delta_g2,
    });
    pairing(&pairs)
}

// ---------------------------------------------------------------------------
// seeded fuzz: valid random inputs (outputs hashed) plus garbage element
// bytes (discriminants hashed); catches divergence anywhere in the
// accept/reject frontier that the structured cases miss

fn fuzz_battery(fp: &mut Fingerprint, r: &mut StdRng) {
    for i in 0..24 {
        let n = r.gen_range(1..5usize);
        let (points, scalars) = msm_input(r, n);
        fp.absorb(&format!("fz_msm{i}"), msm(&points, &scalars));
        let a = fr_array(r, n);
        let b = fr_array(r, n);
        fp.absorb(&format!("fz_lin{i}"), lincomb(&a, &b));
        fp.absorb(&format!("fz_inv{i}"), invert(&a));
    }
    for i in 0..8 {
        let input = pairing_input(r, 1 + (i % 2));
        fp.absorb(&format!("fz_pair{i}"), pairing(&input.valid));
    }
    for i in 0..128 {
        let n = r.gen_range(1..4usize);
        let garbage_pairs: Vec<PodG1G2Pair> = (0..n)
            .map(|_| PodG1G2Pair {
                g1: PodG1Point(rand_array(r)),
                g2: PodG2Point(rand_array(r)),
            })
            .collect();
        fp.absorb(&format!("fz_g_pair{i}"), pairing(&garbage_pairs));
        let gp: Vec<PodG1Point> = (0..n).map(|_| PodG1Point(rand_array(r))).collect();
        let gs: Vec<PodScalar> = (0..n).map(|_| PodScalar(rand_array(r))).collect();
        fp.absorb(&format!("fz_g_msm{i}"), msm(&gp, &gs));
        let ga: Vec<PodScalar> = (0..n).map(|_| PodScalar(rand_array(r))).collect();
        let gb: Vec<PodScalar> = (0..n).map(|_| PodScalar(rand_array(r))).collect();
        fp.absorb(&format!("fz_g_lin{i}"), lincomb(&ga, &gb));
        fp.absorb(&format!("fz_g_inv{i}"), invert(&ga));
    }
}
