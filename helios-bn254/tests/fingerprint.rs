//! Consensus fingerprint battery over the public byte facade.
//!
//! Every outcome of a fixed, deterministic corpus -- output bytes or error
//! discriminant -- is absorbed into one SHA-256. The digest is pinned as
//! `GOLDEN`: any behavioral drift in decode, validation order, arithmetic,
//! or encode across the four batch ops breaks this test on every target.
//! Backends must agree byte for byte (portable, AArch64 leaf, x86-64 ADX,
//! AVX-512 IFMA), so one constant serves all tiers; the corpus includes a
//! >= 8-pair valid pairing batch to force the IFMA dispatch where it exists.
//!
//! Coverage: edge scalars (0, 1, 2^64, 2^128, r-1), infinity encodings,
//! cap-exact and cap+1, every reachable `InputError` variant with its
//! triggering input, cross-variant precedence when two errors are present at
//! once, non-canonical field and scalar encodings at every coordinate slot,
//! algebraic identities (cancellation to infinity, bilinearity), known-good
//! pairing checks, and a seeded garbage sweep of the accept/reject frontier.

use helios_bn254::{
    Fr, G1Bytes, G1Projective, G2Affine, G2Bytes, G2Projective, InputError, PairBytes,
    PodPairingResult, ScalarBytes, Version, alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb,
    alt_bn128_g1_msm, alt_bn128_pairing_check, consts, fr_batch_invert, fr_lincomb, g1_msm,
    pairing_product_is_one,
};

/// Pinned digest of the whole battery. Derive a new value only for an
/// intentional consensus-visible change: run the test, read the computed
/// digest from the failure message, and justify the drift in the commit.
const GOLDEN: &str = "9aea2740537c32ffa4396559980dc22b477de3e02d518c1f9891bd40ef2a5fd1";

#[test]
fn consensus_fingerprint_matches_golden() {
    let digest = fingerprint();
    assert_eq!(
        digest, GOLDEN,
        "\nconsensus fingerprint drifted\ncomputed: {digest}\npinned:   {GOLDEN}\n\
         every mismatch is a consensus-visible behavior change; if intended, \
         re-pin GOLDEN with the computed value and document why",
    );
}

// ---------------------------------------------------------------------------
// Minimal single-shot SHA-256 (FIPS 180-4); no dependencies.
// ---------------------------------------------------------------------------

const SHA_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_hex(data: &[u8]) -> String {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&(8 * data.len() as u64).to_be_bytes());
    for block in message.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(word.try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut hex = String::with_capacity(64);
    for word in state {
        for byte in word.to_be_bytes() {
            hex.push_str(&format!("{byte:02x}"));
        }
    }
    hex
}

// ---------------------------------------------------------------------------
// Battery plumbing.
// ---------------------------------------------------------------------------

/// Stable error discriminants for the digest. Never renumber: the mapping is
/// part of the pinned behavior.
fn err_byte(error: InputError) -> u8 {
    match error {
        InputError::InvalidLength => 0,
        InputError::NonCanonical => 1,
        InputError::NotOnCurve => 2,
        InputError::NotInSubgroup => 3,
        InputError::ZeroInput => 4,
        InputError::CapExceeded => 5,
        InputError::LengthMismatch => 6,
    }
}

const ALL_ERRORS: [InputError; 7] = [
    InputError::InvalidLength,
    InputError::NonCanonical,
    InputError::NotOnCurve,
    InputError::NotInSubgroup,
    InputError::ZeroInput,
    InputError::CapExceeded,
    InputError::LengthMismatch,
];

struct Battery {
    data: Vec<u8>,
}

impl Battery {
    fn new() -> Self {
        Battery { data: Vec::new() }
    }

    /// Unambiguous framing: label, tag (0 = ok / 1 = err), then the
    /// length-prefixed payload or the error discriminant.
    fn absorb(&mut self, label: &str, outcome: Result<Vec<u8>, InputError>) {
        self.data.extend_from_slice(label.as_bytes());
        self.data.push(b'|');
        match outcome {
            Ok(bytes) => {
                self.data.push(0);
                self.data
                    .extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                self.data.extend_from_slice(&bytes);
            }
            Err(error) => {
                self.data.push(1);
                self.data.push(err_byte(error));
            }
        }
    }

    fn msm(&mut self, label: &str, points: &[G1Bytes], scalars: &[ScalarBytes]) {
        self.absorb(label, g1_msm(points, scalars).map(|out| out.0.to_vec()));
    }

    fn pairing(&mut self, label: &str, pairs: &[PairBytes]) {
        self.absorb(
            label,
            pairing_product_is_one(pairs).map(|verdict| vec![u8::from(verdict)]),
        );
    }

    fn lincomb(&mut self, label: &str, a: &[ScalarBytes], b: &[ScalarBytes]) {
        self.absorb(label, fr_lincomb(a, b).map(|out| out.0.to_vec()));
    }

    fn invert(&mut self, label: &str, values: &[ScalarBytes]) {
        self.absorb(
            label,
            fr_batch_invert(values)
                .map(|out| out.iter().flat_map(|scalar| scalar.0).collect::<Vec<u8>>()),
        );
    }
}

/// xorshift64: the corpus generator; fixed seeds pin the corpus forever.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for chunk in out.chunks_mut(8) {
            let word = self.next().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        out
    }

    /// A uniform-enough Fr: the top limb is truncated below r's top limb.
    fn fr(&mut self) -> Fr {
        let mut limbs = [self.next(), self.next(), self.next(), self.next()];
        limbs[3] >>= 4;
        Fr::from_raw(limbs)
    }
}

// ---------------------------------------------------------------------------
// Corpus builders.
// ---------------------------------------------------------------------------

fn be_bytes(limbs: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        out[24 - 8 * i..32 - 8 * i].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

fn g1(scalar: Fr) -> G1Bytes {
    G1Bytes::from_affine(&G1Projective::generator().mul(scalar).to_affine())
}

fn g1_neg(scalar: Fr) -> G1Bytes {
    G1Bytes::from_affine(&G1Projective::generator().mul(scalar).to_affine().neg())
}

fn g2(scalar: Fr) -> G2Bytes {
    G2Bytes::from_affine(
        &G2Projective::from(G2Affine::arkworks_generator())
            .mul(scalar)
            .to_affine(),
    )
}

fn g2_neg(scalar: Fr) -> G2Bytes {
    G2Bytes::from_affine(
        &G2Projective::from(G2Affine::arkworks_generator())
            .mul(scalar)
            .to_affine()
            .neg(),
    )
}

fn scalar_bytes(scalar: Fr) -> ScalarBytes {
    ScalarBytes(scalar.to_bytes_be())
}

fn pair(g1: G1Bytes, g2: G2Bytes) -> PairBytes {
    PairBytes { g1, g2 }
}

/// The five task-pinned edge scalars: 0, 1, 2^64, 2^128, r-1.
fn edge_scalars() -> [ScalarBytes; 5] {
    let r_minus_one = {
        let mut limbs = consts::R;
        limbs[0] -= 1; // r is odd
        limbs
    };
    [
        ScalarBytes([0; 32]),
        ScalarBytes(be_bytes(&[1, 0, 0, 0])),
        ScalarBytes(be_bytes(&[0, 1, 0, 0])),
        ScalarBytes(be_bytes(&[0, 0, 1, 0])),
        ScalarBytes(be_bytes(&r_minus_one)),
    ]
}

/// A twist point outside the r-subgroup: x = (0, 1), y computed offline
/// (sqrt of x^3 + 3/(9+u) over Fp2; [r]P != O verified by an independent
/// script and re-checked by `non_subgroup_vector_error` below). Encoded
/// x1 | x0 | y1 | y0.
fn non_subgroup_g2() -> G2Bytes {
    let mut out = [0u8; 128];
    out[63] = 1; // x0 = 1, x1 = 0
    let y1 = [
        0x0d, 0x12, 0x71, 0x95, 0x3e, 0xd9, 0xea, 0x08, 0x36, 0x84, 0x6e, 0x70, 0xa1, 0x93, 0x41,
        0x87, 0x99, 0x8c, 0x7f, 0x79, 0x0c, 0xb4, 0xd7, 0x51, 0x1b, 0x7f, 0x8d, 0xa8, 0x2d, 0xe0,
        0x48, 0xa4,
    ];
    let y0 = [
        0x28, 0x69, 0x11, 0x1d, 0x53, 0x81, 0xf0, 0x72, 0xf8, 0xe2, 0x72, 0x8f, 0xdb, 0x82, 0x5a,
        0x51, 0xaa, 0xdd, 0x70, 0xe5, 0x2c, 0x98, 0x30, 0xe9, 0xab, 0x4b, 0x87, 0x1c, 0x05, 0x31,
        0xf1, 0xbb,
    ];
    out[64..96].copy_from_slice(&y1);
    out[96..128].copy_from_slice(&y0);
    G2Bytes(out)
}

// ---------------------------------------------------------------------------
// The battery.
// ---------------------------------------------------------------------------

fn fingerprint() -> String {
    let mut battery = Battery::new();
    taxonomy(&mut battery);
    msm_battery(&mut battery);
    pairing_battery(&mut battery);
    fr_battery(&mut battery);
    spelling_battery(&mut battery);
    fuzz_battery(&mut battery);
    sha256_hex(&battery.data)
}

/// Pin the constants, the full error taxonomy (including `InvalidLength`,
/// which the typed facade can never produce -- fixed-size Pod inputs make
/// ragged lengths unrepresentable), and the verdict-word encoding.
fn taxonomy(battery: &mut Battery) {
    let caps = [
        helios_bn254::MSM_MAX_POINTS as u64,
        helios_bn254::PAIRING_MAX_PAIRS as u64,
        helios_bn254::FR_MAX_ELEMS as u64,
        helios_bn254::G1_BYTES as u64,
        helios_bn254::G2_BYTES as u64,
        helios_bn254::PAIR_BYTES as u64,
        helios_bn254::SCALAR_BYTES as u64,
    ];
    battery.absorb(
        "caps",
        Ok(caps.iter().flat_map(|cap| cap.to_le_bytes()).collect()),
    );
    for error in ALL_ERRORS {
        battery.absorb(
            &format!("err{}", err_byte(error)),
            Ok(format!("{error}").into_bytes()),
        );
    }
    for verdict in [false, true] {
        let word = PodPairingResult::from_verdict(verdict);
        let mut bytes = word.0.to_vec();
        bytes.push(u8::from(word.verdict()));
        battery.absorb(&format!("verdict{}", u8::from(verdict)), Ok(bytes));
    }
}

fn msm_battery(battery: &mut Battery) {
    let mut rng = Rng(0x243f_6a88_85a3_08d3);
    for n in [1usize, 2, 3, 7, 8, 33, 96] {
        let points: Vec<G1Bytes> = (0..n).map(|_| g1(rng.fr())).collect();
        let scalars: Vec<ScalarBytes> = (0..n).map(|_| scalar_bytes(rng.fr())).collect();
        battery.msm(&format!("msm{n}"), &points, &scalars);
    }
    let point = g1(Fr::from_u64(7));
    // Edge scalars against one fixed point; 0 and r-1 exercise the
    // infinity-output and negation routes.
    for (i, scalar) in edge_scalars().into_iter().enumerate() {
        battery.msm(&format!("msm_edge{i}"), &[point], &[scalar]);
    }
    // [1]P + [r-1]P = infinity: the all-zero output encoding.
    battery.msm(
        "msm_cancel",
        &[point, point],
        &[edge_scalars()[1], edge_scalars()[4]],
    );
    // Explicit infinity input, alone and mid-batch; zero scalar mid-batch.
    let infinity = G1Bytes([0; 64]);
    battery.msm("msm_inf_only", &[infinity], &[scalar_bytes(rng.fr())]);
    battery.msm(
        "msm_inf_mid",
        &[point, infinity, g1(rng.fr())],
        &[
            scalar_bytes(rng.fr()),
            scalar_bytes(rng.fr()),
            scalar_bytes(rng.fr()),
        ],
    );
    battery.msm(
        "msm_zero_mid",
        &[point, g1(rng.fr()), g1(rng.fr())],
        &[
            scalar_bytes(rng.fr()),
            ScalarBytes([0; 32]),
            scalar_bytes(rng.fr()),
        ],
    );
    // Duplicate points fold through the bucket logic.
    battery.msm(
        "msm_dup",
        &[point, point, point],
        &[
            scalar_bytes(rng.fr()),
            scalar_bytes(rng.fr()),
            scalar_bytes(rng.fr()),
        ],
    );
    // Cap-exact (all-infinity keeps it cheap: the cap check and full decode
    // still run) and cap + 1.
    let cap = helios_bn254::MSM_MAX_POINTS;
    battery.msm(
        "msm_cap",
        &vec![infinity; cap],
        &vec![ScalarBytes([0; 32]); cap],
    );
    battery.msm(
        "msm_cap1",
        &vec![infinity; cap + 1],
        &vec![ScalarBytes([0; 32]); cap + 1],
    );
    // Error rows: each variant with its trigger.
    let good_scalar = scalar_bytes(rng.fr());
    battery.msm("msm_empty", &[], &[]);
    battery.msm("msm_mismatch", &[point, point], &[good_scalar]);
    let p_encoding = be_bytes(&consts::P);
    for (label, slot) in [("x", 0usize), ("y", 32)] {
        let mut bad = point;
        bad.0[slot..slot + 32].copy_from_slice(&p_encoding);
        battery.msm(&format!("msm_bad_{label}"), &[bad], &[good_scalar]);
    }
    let off_curve = {
        let mut bad = point;
        bad.0[63] ^= 1;
        bad
    };
    battery.msm("msm_off_curve", &[off_curve], &[good_scalar]);
    // x = 0, y = 1 is NOT the infinity encoding and must fail the curve test.
    let near_infinity = {
        let mut bad = G1Bytes([0; 64]);
        bad.0[63] = 1;
        bad
    };
    battery.msm("msm_near_inf", &[near_infinity], &[good_scalar]);
    battery.msm(
        "msm_bad_scalar",
        &[point],
        &[ScalarBytes(be_bytes(&consts::R))],
    );
    battery.msm("msm_ff_scalar", &[point], &[ScalarBytes([0xff; 32])]);
    // Precedence rows: two errors present at once, the winner pinned.
    // Mismatch beats empty and cap; cap beats element validation; every
    // point is validated before any scalar; earlier element wins.
    battery.msm("msm_prec_mismatch_empty", &[], &[good_scalar]);
    battery.msm(
        "msm_prec_mismatch_cap",
        &vec![infinity; cap + 1],
        &[good_scalar],
    );
    battery.msm(
        "msm_prec_cap_badpoint",
        &vec![off_curve; cap + 1],
        &vec![ScalarBytes([0xff; 32]); cap + 1],
    );
    battery.msm(
        "msm_prec_point_before_scalar",
        &[point, off_curve],
        &[ScalarBytes([0xff; 32]), good_scalar],
    );
    battery.msm(
        "msm_prec_first_point_wins",
        &[off_curve, {
            let mut bad = point;
            bad.0[0..32].copy_from_slice(&p_encoding);
            bad
        }],
        &[good_scalar, good_scalar],
    );
    battery.msm(
        "msm_prec_first_scalar_wins",
        &[point, point],
        &[ScalarBytes(be_bytes(&consts::R)), ScalarBytes([0xff; 32])],
    );
}

fn pairing_battery(battery: &mut Battery) {
    let mut rng = Rng(0x1319_8a2e_0370_7344);
    let a = rng.fr();
    let b = rng.fr();
    let p_generator = g1(Fr::from_u64(1));
    let q_generator = g2(Fr::from_u64(1));
    // Known-good checks: e(P, Q) * e(-P, Q) = 1 and the bilinear fold
    // e(aP, bQ) * e(-abP, Q) = 1; a lone real pair is never the identity.
    let cancel = [pair(g1(a), g2(b)), pair(g1_neg(a), g2(b))];
    battery.pairing("pair_cancel_g1", &cancel);
    battery.pairing(
        "pair_cancel_g2",
        &[pair(g1(a), g2(b)), pair(g1(a), g2_neg(b))],
    );
    battery.pairing(
        "pair_bilinear",
        &[pair(g1(a), g2(b)), pair(g1_neg(a * b), q_generator)],
    );
    battery.pairing("pair_single", &[pair(p_generator, q_generator)]);
    // Unbalanced product: must be false.
    battery.pairing(
        "pair_unbalanced",
        &[pair(g1(a), g2(b)), pair(g1_neg(a), g2_neg(b))],
    );
    // 8 non-identity pairs: on IFMA targets this is the multi_pairing8
    // dispatch row; every tier must agree on the verdict.
    let mut eight = Vec::new();
    for _ in 0..4 {
        let k = rng.fr();
        eight.push(pair(g1(k), g2(b)));
        eight.push(pair(g1_neg(k), g2(b)));
    }
    battery.pairing("pair_eight", &eight);
    // Infinity handling: all-infinity, half-infinity, and a hole mid-batch.
    let inf_pair = pair(G1Bytes([0; 64]), G2Bytes([0; 128]));
    battery.pairing("pair_all_inf", &[inf_pair, inf_pair, inf_pair]);
    battery.pairing("pair_g1_inf", &[pair(G1Bytes([0; 64]), g2(b))]);
    battery.pairing("pair_g2_inf", &[pair(g1(a), G2Bytes([0; 128]))]);
    battery.pairing("pair_inf_mid", &[cancel[0], inf_pair, cancel[1]]);
    // Cap-exact (all infinity: validation runs, the product is vacuous) and
    // cap + 1.
    let cap = helios_bn254::PAIRING_MAX_PAIRS;
    battery.pairing("pair_cap", &vec![inf_pair; cap]);
    battery.pairing("pair_cap1", &vec![inf_pair; cap + 1]);
    // Error rows.
    battery.pairing("pair_empty", &[]);
    let p_encoding = be_bytes(&consts::P);
    let mut bad_g1 = p_generator;
    bad_g1.0[0..32].copy_from_slice(&p_encoding);
    battery.pairing("pair_bad_g1_limb", &[pair(bad_g1, q_generator)]);
    let off_g1 = {
        let mut bad = p_generator;
        bad.0[63] ^= 1;
        bad
    };
    battery.pairing("pair_off_g1", &[pair(off_g1, q_generator)]);
    // Non-canonical G2 at each of the four coordinate slots.
    for slot in 0..4 {
        let mut bad = q_generator;
        bad.0[32 * slot..32 * slot + 32].copy_from_slice(&p_encoding);
        battery.pairing(
            &format!("pair_bad_g2_limb{slot}"),
            &[pair(p_generator, bad)],
        );
    }
    let off_g2 = {
        let mut bad = q_generator;
        bad.0[127] ^= 1;
        bad
    };
    battery.pairing("pair_off_g2", &[pair(p_generator, off_g2)]);
    battery.pairing("pair_non_subgroup", &[pair(p_generator, non_subgroup_g2())]);
    // G2 x = 0, y = (0, 1): not the infinity encoding, off the twist.
    let near_inf_g2 = {
        let mut bad = G2Bytes([0; 128]);
        bad.0[127] = 1;
        bad
    };
    battery.pairing("pair_near_inf_g2", &[pair(p_generator, near_inf_g2)]);
    // Precedence rows: G1 before G2 within a pair, pairs in order, the
    // subgroup check after curve and canonicity, errors behind valid pairs
    // still surface.
    battery.pairing("pair_prec_g1_before_g2", &[pair(off_g1, off_g2)]);
    battery.pairing(
        "pair_prec_pair_order",
        &[pair(p_generator, off_g2), pair(off_g1, q_generator)],
    );
    battery.pairing(
        "pair_prec_valid_then_bad",
        &[cancel[0], cancel[1], pair(p_generator, non_subgroup_g2())],
    );
    battery.pairing(
        "pair_prec_inf_then_bad",
        &[inf_pair, pair(off_g1, q_generator)],
    );
}

fn fr_battery(battery: &mut Battery) {
    let mut rng = Rng(0xa409_3822_299f_31d0);
    for n in [1usize, 2, 3, 7, 64] {
        let a: Vec<ScalarBytes> = (0..n).map(|_| scalar_bytes(rng.fr())).collect();
        let b: Vec<ScalarBytes> = (0..n).map(|_| scalar_bytes(rng.fr())).collect();
        battery.lincomb(&format!("lin{n}"), &a, &b);
        battery.lincomb(&format!("lin_alias{n}"), &a, &a);
        battery.invert(&format!("inv{n}"), &a);
    }
    // Edge scalars against r-1 and against themselves; nonzero edges
    // inverted.
    let edges = edge_scalars();
    let max = vec![edges[4]; edges.len()];
    battery.lincomb("lin_edge_max", &edges, &max);
    battery.lincomb("lin_edge_sq", &edges, &edges);
    battery.invert("inv_edge", &edges[1..]);
    // All zeros (valid: the zero output) and zero mid-input for the inverse.
    let zeros = vec![ScalarBytes([0; 32]); 4];
    let random: Vec<ScalarBytes> = (0..4).map(|_| scalar_bytes(rng.fr())).collect();
    battery.lincomb("lin_zeros", &zeros, &random);
    for (label, slot) in [("first", 0usize), ("mid", 2), ("last", 3)] {
        let mut values = random.clone();
        values[slot] = ScalarBytes([0; 32]);
        battery.invert(&format!("inv_zero_{label}"), &values);
    }
    // Cap-exact and cap + 1.
    let cap = helios_bn254::FR_MAX_ELEMS;
    let ones = vec![edges[1]; cap];
    battery.lincomb("lin_cap", &ones, &ones);
    battery.invert("inv_cap", &ones);
    let over = vec![edges[1]; cap + 1];
    battery.lincomb("lin_cap1", &over, &over);
    battery.invert("inv_cap1", &over);
    // Error rows.
    battery.lincomb("lin_empty", &[], &[]);
    battery.invert("inv_empty", &[]);
    battery.lincomb("lin_mismatch", &random, &random[..2]);
    let bad = ScalarBytes(be_bytes(&consts::R));
    for (label, slot) in [("first", 0usize), ("last", 2)] {
        let mut bad_side = vec![edges[1]; 3];
        bad_side[slot] = bad;
        battery.lincomb(&format!("lin_bad_a_{label}"), &bad_side, &random[..3]);
        battery.lincomb(&format!("lin_bad_b_{label}"), &random[..3], &bad_side);
        battery.invert(&format!("inv_bad_{label}"), &bad_side);
    }
    battery.lincomb("lin_ff", &[ScalarBytes([0xff; 32])], &[edges[1]]);
    // Precedence rows. Same-variant order (a[i] before b[i], i ascending) is
    // hashed via outputs elsewhere; here the cross-variant winners:
    // mismatch > empty, mismatch > cap, cap > element decode, and for the
    // inverse the position-order NonCanonical/ZeroInput race both ways.
    battery.lincomb("lin_prec_mismatch_empty", &[], &random[..1]);
    battery.lincomb("lin_prec_mismatch_cap", &over, &random[..1]);
    battery.lincomb("lin_prec_cap_bad", &vec![bad; cap + 1], &vec![bad; cap + 1]);
    battery.invert("inv_prec_cap_bad", &vec![bad; cap + 1]);
    battery.invert("inv_prec_bad_then_zero", &[bad, ScalarBytes([0; 32])]);
    battery.invert("inv_prec_zero_then_bad", &[ScalarBytes([0; 32]), bad]);
}

/// The alt_bn128_* spellings must be bit-identical delegates.
fn spelling_battery(battery: &mut Battery) {
    let mut rng = Rng(0x082e_fa98_ec4e_6c89);
    let points = [g1(rng.fr()), g1(rng.fr())];
    let scalars = [scalar_bytes(rng.fr()), scalar_bytes(rng.fr())];
    let plain = g1_msm(&points, &scalars);
    let spelled = alt_bn128_g1_msm(Version::V0, &points, &scalars);
    assert_eq!(plain, spelled, "alt_bn128_g1_msm drifted from g1_msm");
    battery.absorb("spell_msm", spelled.map(|out| out.0.to_vec()));

    let pairs = [
        pair(points[0], g2(rng.fr())),
        pair(g1_neg(rng.fr()), g2(rng.fr())),
    ];
    let plain = pairing_product_is_one(&pairs);
    let spelled = alt_bn128_pairing_check(Version::V0, &pairs);
    assert_eq!(
        plain, spelled,
        "alt_bn128_pairing_check drifted from pairing_product_is_one"
    );
    battery.absorb(
        "spell_pairing",
        spelled.map(|verdict| vec![u8::from(verdict)]),
    );

    let plain = fr_lincomb(&scalars, &scalars);
    let spelled = alt_bn128_fr_lincomb(Version::V0, &scalars, &scalars);
    assert_eq!(
        plain, spelled,
        "alt_bn128_fr_lincomb drifted from fr_lincomb"
    );
    battery.absorb("spell_lincomb", spelled.map(|out| out.0.to_vec()));

    let plain = fr_batch_invert(&scalars);
    let spelled = alt_bn128_fr_batch_invert(Version::V0, &scalars);
    assert_eq!(
        plain, spelled,
        "alt_bn128_fr_batch_invert drifted from fr_batch_invert"
    );
    battery.absorb(
        "spell_invert",
        spelled.map(|out| out.iter().flat_map(|scalar| scalar.0).collect()),
    );
}

/// Seeded garbage sweep: random bytes through every decoder pin the whole
/// accept/reject frontier (mostly NonCanonical, occasionally NotOnCurve).
fn fuzz_battery(battery: &mut Battery) {
    let mut rng = Rng(0x4528_21e6_38d0_1377);
    for i in 0..48 {
        let point = G1Bytes(rng.bytes::<64>());
        let scalar = ScalarBytes(rng.bytes::<32>());
        battery.msm(&format!("fz_msm{i}"), &[point], &[scalar]);
        let g2_bytes = G2Bytes(rng.bytes::<128>());
        battery.pairing(&format!("fz_pair{i}"), &[pair(point, g2_bytes)]);
        let other = ScalarBytes(rng.bytes::<32>());
        battery.lincomb(&format!("fz_lin{i}"), &[scalar], &[other]);
        battery.invert(&format!("fz_inv{i}"), &[scalar, other]);
    }
    // Garbage against a valid partner: the valid element must not mask the
    // garbage one, whichever side it is on.
    let anchor_point = g1(Fr::from_u64(11));
    let anchor_scalar = scalar_bytes(Fr::from_u64(13));
    for i in 0..16 {
        let garbage = ScalarBytes(rng.bytes::<32>());
        battery.msm(
            &format!("fz_mixed_msm{i}"),
            &[anchor_point, G1Bytes(rng.bytes::<64>())],
            &[anchor_scalar, garbage],
        );
        battery.lincomb(
            &format!("fz_mixed_lin{i}"),
            &[anchor_scalar, garbage],
            &[garbage, anchor_scalar],
        );
    }
}

// ---------------------------------------------------------------------------
// Readable hard assertions for the highest-value precedence pins. These
// duplicate battery rows so a drift names the broken rule instead of only
// flipping the digest.
// ---------------------------------------------------------------------------

#[test]
fn error_precedence_pins() {
    let good_point = g1(Fr::from_u64(3));
    let good_scalar = scalar_bytes(Fr::from_u64(5));
    let bad_scalar = ScalarBytes([0xff; 32]);
    let off_curve = {
        let mut bad = good_point;
        bad.0[63] ^= 1;
        bad
    };
    let cap = helios_bn254::MSM_MAX_POINTS;

    // LengthMismatch > ZeroInput(empty) > CapExceeded > element validation.
    assert_eq!(g1_msm(&[], &[good_scalar]), Err(InputError::LengthMismatch));
    assert_eq!(g1_msm(&[], &[]), Err(InputError::ZeroInput));
    assert_eq!(
        g1_msm(&vec![off_curve; cap + 1], &[good_scalar]),
        Err(InputError::LengthMismatch),
    );
    assert_eq!(
        g1_msm(&vec![off_curve; cap + 1], &vec![bad_scalar; cap + 1]),
        Err(InputError::CapExceeded),
    );
    // All points before any scalar; input order within each phase.
    assert_eq!(
        g1_msm(&[good_point, off_curve], &[bad_scalar, good_scalar]),
        Err(InputError::NotOnCurve),
    );
    assert_eq!(
        g1_msm(&[good_point, good_point], &[bad_scalar, good_scalar]),
        Err(InputError::NonCanonical),
    );

    // Pairing: G1 validated before G2 within a pair, pairs in input order.
    let good_g2 = g2(Fr::from_u64(1));
    let off_g2 = {
        let mut bad = good_g2;
        bad.0[127] ^= 1;
        bad
    };
    assert_eq!(
        pairing_product_is_one(&[pair(off_curve, off_g2)]),
        Err(InputError::NotOnCurve),
    );
    assert_eq!(
        pairing_product_is_one(&[pair(good_point, off_g2), pair(off_curve, good_g2)]),
        Err(InputError::NotOnCurve), // both NotOnCurve; order pinned by digest rows
    );

    // fr_batch_invert: elements scanned in order, decode before zero check.
    let noncanonical = ScalarBytes(be_bytes(&consts::R));
    assert_eq!(
        fr_batch_invert(&[noncanonical, ScalarBytes([0; 32])]),
        Err(InputError::NonCanonical),
    );
    assert_eq!(
        fr_batch_invert(&[ScalarBytes([0; 32]), noncanonical]),
        Err(InputError::ZeroInput),
    );
}

#[test]
fn non_subgroup_vector_error() {
    // The embedded vector must fail exactly the subgroup check: canonical
    // coordinates, on the twist, outside the r-order subgroup.
    let point = non_subgroup_g2();
    assert_eq!(point.to_affine(), Err(InputError::NotInSubgroup));
    assert_eq!(
        pairing_product_is_one(&[pair(g1(Fr::from_u64(1)), point)]),
        Err(InputError::NotInSubgroup),
    );
}

#[test]
fn known_good_pairing_holds() {
    let a = Fr::from_u64(6);
    let b = Fr::from_u64(35);
    // e(aP, bQ) * e(-abP, Q) = 1: true through every dispatch tier.
    let pairs = [pair(g1(a), g2(b)), pair(g1_neg(a * b), g2(Fr::from_u64(1)))];
    assert_eq!(pairing_product_is_one(&pairs), Ok(true));
    // Dropping the cancellation flips the verdict, not the error path.
    assert_eq!(pairing_product_is_one(&pairs[..1]), Ok(false));
}
