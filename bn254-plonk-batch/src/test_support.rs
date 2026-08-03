//! Trapdoor-SRS fixtures: a minimal PLONK prover over a fixed toy
//! circuit, shared by unit tests, the criterion bench, and off-tree drivers
//! (feature `test-fixtures`). Completeness only: wires and the grand product
//! carry no blinding, so fixtures exercise the verifier, not zero-knowledge.
//!
//! The trapdoor tau makes commitment = [poly(tau)]_1 a single scalar
//! multiplication, so no structured SRS is materialized. The prover derives
//! its challenges through the verifier's own `InnerTranscript` phases;
//! batch completeness is the test that the phase layout matches.

pub use crate::transcript::{InnerChallenges, derive_inner};
use {
    crate::{
        proof::{Evaluations, Proof},
        transcript::InnerTranscript,
        vk::{ValidatedVerifyingKey, VerifyingKey},
    },
    ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective},
    ark_ec::{AffineRepr, CurveGroup, PrimeGroup},
    ark_ff::{BigInteger, FftField, Field, One, PrimeField, UniformRand, Zero},
    ark_std::rand::{SeedableRng, rngs::StdRng},
    solana_bn254_batch_syscall::{PodG1Point, PodG2Point, PodScalar},
};

pub const DOMAIN_SIZE: u64 = 8;
const N: usize = DOMAIN_SIZE as usize;

pub fn rng() -> StdRng {
    StdRng::seed_from_u64(0x9b254c)
}

pub fn g1_bytes(point: &G1Affine) -> PodG1Point {
    let mut out = [0u8; 64];
    if let Some((x, y)) = point.xy() {
        out[..32].copy_from_slice(&x.into_bigint().to_bytes_be());
        out[32..].copy_from_slice(&y.into_bigint().to_bytes_be());
    }
    PodG1Point(out)
}

pub fn g2_bytes(point: &G2Affine) -> PodG2Point {
    let mut out = [0u8; 128];
    if let Some((x, y)) = point.xy() {
        out[0..32].copy_from_slice(&x.c1.into_bigint().to_bytes_be());
        out[32..64].copy_from_slice(&x.c0.into_bigint().to_bytes_be());
        out[64..96].copy_from_slice(&y.c1.into_bigint().to_bytes_be());
        out[96..128].copy_from_slice(&y.c0.into_bigint().to_bytes_be());
    }
    PodG2Point(out)
}

pub fn fr_bytes(scalar: &Fr) -> PodScalar {
    let mut out = [0u8; 32];
    out.copy_from_slice(&scalar.into_bigint().to_bytes_be());
    PodScalar(out)
}

pub fn g1(scalar: Fr) -> G1Affine {
    (G1Projective::generator() * scalar).into_affine()
}

pub fn g2(scalar: Fr) -> G2Affine {
    (G2Projective::generator() * scalar).into_affine()
}

/// Deterministic G2 point on the twist curve but outside the r-order
/// subgroup: the twist cofactor is ~2^254, so nearly every curve point
/// qualifies; the asserts fail loud if the found point is not the negative
/// test it claims to be.
pub fn non_subgroup_g2() -> G2Affine {
    for k in 0u64.. {
        let x = Fq2::new(Fq::from(k), Fq::zero());
        if let Some(point) = G2Affine::get_point_from_x_unchecked(x, true) {
            assert!(point.is_on_curve());
            if !point.is_in_correct_subgroup_assuming_on_curve() {
                return point;
            }
        }
    }
    unreachable!("BN254 twist has non-subgroup points with small x");
}

// --- dense coefficient-form polynomial helpers, low degree first; naive
// --- O(n^2) everywhere, which is fine at n = 8 and keeps deps minimal

fn poly_eval(poly: &[Fr], x: Fr) -> Fr {
    poly.iter().rev().fold(Fr::zero(), |acc, c| acc * x + c)
}

fn poly_add(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    let mut out = vec![Fr::zero(); a.len().max(b.len())];
    for (i, c) in a.iter().enumerate() {
        out[i] += c;
    }
    for (i, c) in b.iter().enumerate() {
        out[i] += c;
    }
    out
}

fn poly_sub(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    let mut out = vec![Fr::zero(); a.len().max(b.len())];
    for (i, c) in a.iter().enumerate() {
        out[i] += c;
    }
    for (i, c) in b.iter().enumerate() {
        out[i] -= c;
    }
    out
}

fn poly_scale(poly: &[Fr], scalar: Fr) -> Vec<Fr> {
    poly.iter().map(|c| *c * scalar).collect()
}

fn poly_mul(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let mut out = vec![Fr::zero(); a.len() + b.len() - 1];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            out[i + j] += *x * y;
        }
    }
    out
}

/// Long division; the zero remainder is asserted because every division in
/// the prover is exact iff the constraint system is satisfied.
fn poly_divide_exact(numerator: &[Fr], divisor: &[Fr]) -> Vec<Fr> {
    let degree = divisor.len() - 1;
    let mut remainder = numerator.to_vec();
    if remainder.len() <= degree {
        assert!(
            remainder.iter().all(|c| c.is_zero()),
            "division must be exact"
        );
        return vec![Fr::zero()];
    }
    let leading_inverse = divisor[degree].inverse().unwrap();
    let mut quotient = vec![Fr::zero(); remainder.len() - degree];
    for i in (degree..remainder.len()).rev() {
        let coefficient = remainder[i] * leading_inverse;
        quotient[i - degree] = coefficient;
        for (j, d) in divisor.iter().enumerate() {
            remainder[i - degree + j] -= coefficient * d;
        }
    }
    assert!(
        remainder.iter().all(|c| c.is_zero()),
        "division must be exact: unsatisfied constraint system"
    );
    quotient
}

/// Inverse DFT over the order-n subgroup generated by omega:
/// c_j = (1/n) sum_k e_k omega^(-jk).
fn interpolate(evals: &[Fr], omega: Fr) -> Vec<Fr> {
    let n = evals.len();
    let n_inverse = Fr::from(n as u64).inverse().unwrap();
    let omega_inverse = omega.inverse().unwrap();
    let mut coefficients = Vec::with_capacity(n);
    let mut root = Fr::one();
    for _ in 0..n {
        let mut acc = Fr::zero();
        let mut power = Fr::one();
        for e in evals {
            acc += *e * power;
            power *= root;
        }
        coefficients.push(acc * n_inverse);
        root *= omega_inverse;
    }
    coefficients
}

/// Trapdoor SRS plus the toy circuit in polynomial form. The circuit proves
/// knowledge of x, y with public input p = x*y + x over domain n = 8, under
/// the gate identity q_m a b + q_l a + q_r b + q_o c + q_c + PI(X) = 0 on H
/// with PI(X) = -sum_i w_i L_i(X) (the standard sign, matching snarkjs):
///   row 0: a + PI = 0 (public input exposure, q_l = 1; PI(1) = -p so a0 = p)
///   row 1: a b - c = 0 (q_m = 1, q_o = -1; a = x, b = y, c = x y)
///   row 2: a + b - c = 0 (q_l = q_r = 1, q_o = -1; a = x y, b = x, c = p)
///   row 3: c - 1 = 0 (q_o = 1, q_c = -1; keeps [q_c] off infinity)
///   rows 4..7: no-op
/// Copy constraints a0 = c2, a1 = b2, c1 = a2 wire the product and the sum
/// together; sigma permutes the coset labels X, k1 X, k2 X accordingly.
/// The zero-input variant blanks row 0's selector: a0 is then constrained
/// only by its copy to c2 and the statement moves entirely into the witness.
pub struct Trapdoor {
    pub tau: Fr,
    pub omega: Fr,
    pub k1: Fr,
    pub k2: Fr,
    pub q_m: Vec<Fr>,
    pub q_l: Vec<Fr>,
    pub q_r: Vec<Fr>,
    pub q_o: Vec<Fr>,
    pub q_c: Vec<Fr>,
    pub s_sigma_polys: [Vec<Fr>; 3],
    pub id_labels: [[Fr; N]; 3],
    pub sigma_labels: [[Fr; N]; 3],
    pub vk: ValidatedVerifyingKey,
}

pub fn make_vk(rng: &mut StdRng) -> (Trapdoor, ValidatedVerifyingKey) {
    make_vk_impl(Fr::rand(rng), true)
}

/// The zero-input circuit variant: no public-input row, PI identically zero.
pub fn make_vk_without_inputs(rng: &mut StdRng) -> (Trapdoor, ValidatedVerifyingKey) {
    make_vk_impl(Fr::rand(rng), false)
}

/// A key under a caller-chosen tau, so two distinct circuits can share one
/// SRS in shared-SRS fold fixtures.
pub fn make_vk_with_tau(tau: Fr, with_input: bool) -> (Trapdoor, ValidatedVerifyingKey) {
    make_vk_impl(tau, with_input)
}

fn make_vk_impl(tau: Fr, with_input: bool) -> (Trapdoor, ValidatedVerifyingKey) {
    let omega = Fr::get_root_of_unity(DOMAIN_SIZE).unwrap();
    // 2 and 3 shift H into disjoint cosets: 2^8, 3^8, and (3/2)^8 are all
    // far from 1 in Fr, which vk validation re-checks
    let k1 = Fr::from(2u64);
    let k2 = Fr::from(3u64);

    let zero = [Fr::zero(); N];
    let mut q_m_evals = zero;
    q_m_evals[1] = Fr::one();
    let mut q_l_evals = zero;
    if with_input {
        q_l_evals[0] = Fr::one();
    }
    q_l_evals[2] = Fr::one();
    let mut q_r_evals = zero;
    q_r_evals[2] = Fr::one();
    let mut q_o_evals = zero;
    q_o_evals[1] = -Fr::one();
    q_o_evals[2] = -Fr::one();
    q_o_evals[3] = Fr::one();
    let mut q_c_evals = zero;
    q_c_evals[3] = -Fr::one();

    let mut id_labels = [[Fr::zero(); N]; 3];
    {
        let [id_a, id_b, id_c] = &mut id_labels;
        let mut root = Fr::one();
        for (a, (b, c)) in id_a.iter_mut().zip(id_b.iter_mut().zip(id_c.iter_mut())) {
            *a = root;
            *b = k1 * root;
            *c = k2 * root;
            root *= omega;
        }
    }
    let mut sigma_labels = id_labels;
    // two-cycles a0 <-> c2, a1 <-> b2, c1 <-> a2
    sigma_labels[0][0] = id_labels[2][2];
    sigma_labels[2][2] = id_labels[0][0];
    sigma_labels[0][1] = id_labels[1][2];
    sigma_labels[1][2] = id_labels[0][1];
    sigma_labels[2][1] = id_labels[0][2];
    sigma_labels[0][2] = id_labels[2][1];

    let q_m = interpolate(&q_m_evals, omega);
    let q_l = interpolate(&q_l_evals, omega);
    let q_r = interpolate(&q_r_evals, omega);
    let q_o = interpolate(&q_o_evals, omega);
    let q_c = interpolate(&q_c_evals, omega);
    let s_sigma_polys = [
        interpolate(&sigma_labels[0], omega),
        interpolate(&sigma_labels[1], omega),
        interpolate(&sigma_labels[2], omega),
    ];

    let commit = |poly: &[Fr]| g1_bytes(&g1(poly_eval(poly, tau)));
    let vk = VerifyingKey {
        domain_size: DOMAIN_SIZE,
        num_public_inputs: u32::from(with_input),
        q_m: commit(&q_m),
        q_l: commit(&q_l),
        q_r: commit(&q_r),
        q_o: commit(&q_o),
        q_c: commit(&q_c),
        s_sigma: [
            commit(&s_sigma_polys[0]),
            commit(&s_sigma_polys[1]),
            commit(&s_sigma_polys[2]),
        ],
        k1: fr_bytes(&k1),
        k2: fr_bytes(&k2),
        g2_gen: g2_bytes(&G2Affine::generator()),
        g2_tau: g2_bytes(&g2(tau)),
    };
    let validated = vk.validate().expect("fixture key must validate");
    let trapdoor = Trapdoor {
        tau,
        omega,
        k1,
        k2,
        q_m,
        q_l,
        q_r,
        q_o,
        q_c,
        s_sigma_polys,
        id_labels,
        sigma_labels,
        vk: validated.clone(),
    };
    (trapdoor, validated)
}

/// PLONK prover for the toy circuit. Deterministic given (x, y): the
/// fixtures carry no blinding, so no rng is taken.
pub fn make_proof(trapdoor: &Trapdoor, x: Fr, y: Fr) -> Proof {
    let omega = trapdoor.omega;
    let p = x * y + x;
    let mut wires = [[Fr::zero(); N]; 3];
    wires[0][0] = p;
    wires[0][1] = x;
    wires[0][2] = x * y;
    wires[1][1] = y;
    wires[1][2] = x;
    wires[2][1] = x * y;
    wires[2][2] = p;
    wires[2][3] = Fr::one();
    let with_input = trapdoor.vk.key().num_public_inputs == 1;
    let public_inputs = if with_input {
        vec![fr_bytes(&p)]
    } else {
        Vec::new()
    };

    let commit = |poly: &[Fr]| g1_bytes(&g1(poly_eval(poly, trapdoor.tau)));

    // round 1: wire polynomials and commitments
    let a_poly = interpolate(&wires[0], omega);
    let b_poly = interpolate(&wires[1], omega);
    let c_poly = interpolate(&wires[2], omega);
    let wire_commitments = [commit(&a_poly), commit(&b_poly), commit(&c_poly)];
    let mut transcript = InnerTranscript::new(&trapdoor.vk, &public_inputs);
    let (beta, gamma) = transcript.wire_commitments(&wire_commitments);

    // round 2: grand product over the 3n wire slots
    let mut z_evals = [Fr::one(); N];
    let mut running = Fr::one();
    for j in 0..N {
        let mut factor = Fr::one();
        for (wire, (id, sigma)) in wires
            .iter()
            .zip(trapdoor.id_labels.iter().zip(&trapdoor.sigma_labels))
        {
            factor *= (wire[j] + beta * id[j] + gamma)
                * (wire[j] + beta * sigma[j] + gamma).inverse().unwrap();
        }
        running *= factor;
        if j + 1 < N {
            z_evals[j + 1] = running;
        }
    }
    // the cycle closes only for a satisfying copy assignment
    assert!(running.is_one(), "grand product must telescope to one");
    let z_poly = interpolate(&z_evals, omega);
    let grand_product = commit(&z_poly);
    let alpha = transcript.grand_product(&grand_product);

    // round 3: quotient t = (gate + alpha perm + alpha^2 L1 (z - 1)) / Z_H,
    // exact division iff the circuit is satisfied. PI carries the
    // minus sign; the zero-input variant has PI identically zero.
    let mut pi_evals = [Fr::zero(); N];
    if with_input {
        pi_evals[0] = -p;
    }
    let pi_poly = interpolate(&pi_evals, omega);
    let mut l1_evals = [Fr::zero(); N];
    l1_evals[0] = Fr::one();
    let l1_poly = interpolate(&l1_evals, omega);

    let gate = [
        poly_mul(&poly_mul(&trapdoor.q_m, &a_poly), &b_poly),
        poly_mul(&trapdoor.q_l, &a_poly),
        poly_mul(&trapdoor.q_r, &b_poly),
        poly_mul(&trapdoor.q_o, &c_poly),
        trapdoor.q_c.clone(),
        pi_poly.clone(),
    ]
    .iter()
    .fold(Vec::new(), |acc, term| poly_add(&acc, term));

    // wire(X) + beta shift X + gamma
    let coset_factor = |poly: &[Fr], shift: Fr| -> Vec<Fr> {
        let mut out = poly.to_vec();
        out[0] += gamma;
        out[1] += beta * shift;
        out
    };
    // wire(X) + beta sigma(X) + gamma
    let sigma_factor = |poly: &[Fr], sigma: &[Fr]| -> Vec<Fr> {
        poly_add(&poly_add(poly, &poly_scale(sigma, beta)), &[gamma])
    };
    let z_shifted: Vec<Fr> = z_poly
        .iter()
        .enumerate()
        .map(|(j, coefficient)| *coefficient * omega.pow([j as u64]))
        .collect();
    let perm_first = poly_mul(
        &poly_mul(
            &coset_factor(&a_poly, Fr::one()),
            &coset_factor(&b_poly, trapdoor.k1),
        ),
        &poly_mul(&coset_factor(&c_poly, trapdoor.k2), &z_poly),
    );
    let perm_second = poly_mul(
        &poly_mul(
            &sigma_factor(&a_poly, &trapdoor.s_sigma_polys[0]),
            &sigma_factor(&b_poly, &trapdoor.s_sigma_polys[1]),
        ),
        &poly_mul(
            &sigma_factor(&c_poly, &trapdoor.s_sigma_polys[2]),
            &z_shifted,
        ),
    );
    let l1_term = poly_mul(&l1_poly, &poly_sub(&z_poly, &[Fr::one()]));
    let numerator = poly_add(
        &poly_add(
            &gate,
            &poly_scale(&poly_sub(&perm_first, &perm_second), alpha),
        ),
        &poly_scale(&l1_term, alpha.square()),
    );
    let mut vanishing = vec![Fr::zero(); N + 1];
    vanishing[0] = -Fr::one();
    vanishing[N] = Fr::one();
    let mut t_poly = poly_divide_exact(&numerator, &vanishing);
    // deg t <= 3n - 4 without blinding, so the X^n-stitched split holds
    t_poly.resize(3 * N, Fr::zero());
    let quotient = [
        commit(&t_poly[..N]),
        commit(&t_poly[N..2 * N]),
        commit(&t_poly[2 * N..]),
    ];
    let zeta = transcript.quotient(&quotient);

    // round 4: evaluations
    let a_ev = poly_eval(&a_poly, zeta);
    let b_ev = poly_eval(&b_poly, zeta);
    let c_ev = poly_eval(&c_poly, zeta);
    let s1_ev = poly_eval(&trapdoor.s_sigma_polys[0], zeta);
    let s2_ev = poly_eval(&trapdoor.s_sigma_polys[1], zeta);
    let zw_ev = poly_eval(&z_poly, zeta * omega);
    let evaluations = Evaluations {
        a: fr_bytes(&a_ev),
        b: fr_bytes(&b_ev),
        c: fr_bytes(&c_ev),
        s_sigma1: fr_bytes(&s1_ev),
        s_sigma2: fr_bytes(&s2_ev),
        z_omega: fr_bytes(&zw_ev),
    };
    let v = transcript.evaluations(&evaluations);

    // round 5: full linearization r(X), constants included; r(zeta) = 0
    // certifies the identity at zeta before the opening divisions
    let zeta_n = zeta.pow([DOMAIN_SIZE]);
    let vanishing_ev = zeta_n - Fr::one();
    let l1_ev = poly_eval(&l1_poly, zeta);
    let pi_ev = poly_eval(&pi_poly, zeta);
    let perm_a = a_ev + beta * s1_ev + gamma;
    let perm_b = b_ev + beta * s2_ev + gamma;
    let mut r_poly = [
        poly_scale(&trapdoor.q_m, a_ev * b_ev),
        poly_scale(&trapdoor.q_l, a_ev),
        poly_scale(&trapdoor.q_r, b_ev),
        poly_scale(&trapdoor.q_o, c_ev),
        trapdoor.q_c.clone(),
        vec![pi_ev],
        poly_scale(
            &z_poly,
            alpha
                * (a_ev + beta * zeta + gamma)
                * (b_ev + beta * trapdoor.k1 * zeta + gamma)
                * (c_ev + beta * trapdoor.k2 * zeta + gamma),
        ),
        poly_scale(
            &poly_add(
                &poly_scale(&trapdoor.s_sigma_polys[2], beta),
                &[c_ev + gamma],
            ),
            -(alpha * perm_a * perm_b * zw_ev),
        ),
        poly_scale(&poly_sub(&z_poly, &[Fr::one()]), alpha.square() * l1_ev),
    ]
    .iter()
    .fold(Vec::new(), |acc, term| poly_add(&acc, term));
    let t_combined = poly_add(
        &poly_add(&t_poly[..N], &poly_scale(&t_poly[N..2 * N], zeta_n)),
        &poly_scale(&t_poly[2 * N..], zeta_n.square()),
    );
    r_poly = poly_sub(&r_poly, &poly_scale(&t_combined, vanishing_ev));
    assert!(
        poly_eval(&r_poly, zeta).is_zero(),
        "linearization must vanish at zeta"
    );

    let mut w_numerator = r_poly;
    let mut v_power = v;
    for (poly, ev) in [
        (&a_poly, a_ev),
        (&b_poly, b_ev),
        (&c_poly, c_ev),
        (&trapdoor.s_sigma_polys[0], s1_ev),
        (&trapdoor.s_sigma_polys[1], s2_ev),
    ] {
        w_numerator = poly_add(&w_numerator, &poly_scale(&poly_sub(poly, &[ev]), v_power));
        v_power *= v;
    }
    let w_zeta = poly_divide_exact(&w_numerator, &[-zeta, Fr::one()]);
    let w_zeta_omega =
        poly_divide_exact(&poly_sub(&z_poly, &[zw_ev]), &[-(zeta * omega), Fr::one()]);
    let opening = commit(&w_zeta);
    let shifted_opening = commit(&w_zeta_omega);
    // u is squeezed by the verifier only; the prover's transcript ends here

    Proof {
        wire_commitments,
        grand_product,
        quotient,
        opening,
        shifted_opening,
        evaluations,
        public_inputs,
    }
}
