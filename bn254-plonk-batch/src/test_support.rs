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
    core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    solana_bn254_batch_syscall::{PodG1Point, PodG2Point, PodScalar},
};

pub const DOMAIN_SIZE: u64 = 8;
const N: usize = DOMAIN_SIZE as usize;

/// Trapdoor SRS and toy-circuit polynomials for fixture proofs.
///
/// The circuit proves knowledge of `x` and `y` for `p = x * y + x` on a
/// domain of size 8. Its gate equation is
/// `q_m*a*b + q_l*a + q_r*b + q_o*c + q_c + PI(X) = 0`.
/// Row 0 exposes `p`. Row 1 computes `x * y`. Row 2 computes the sum. Row 3
/// constrains `c` to one. The copy constraints connect these rows. The
/// zero-input variant disables row 0 and puts the statement in the witness.
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
    G1Projective::generator().mul(scalar).into_affine()
}

pub fn g2(scalar: Fr) -> G2Affine {
    G2Projective::generator().mul(scalar).into_affine()
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

// Coefficients use low-degree-first order. Naive operations are sufficient for N = 8.

fn poly_eval(poly: &[Fr], x: Fr) -> Fr {
    poly.iter()
        .rev()
        .fold(Fr::zero(), |acc, c| fr_add(fr_mul(acc, x), *c))
}

fn poly_add(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    let mut out = vec![Fr::zero(); a.len().max(b.len())];
    for (i, c) in a.iter().enumerate() {
        out[i].add_assign(*c);
    }
    for (i, c) in b.iter().enumerate() {
        out[i].add_assign(*c);
    }
    out
}

fn poly_sub(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    let mut out = vec![Fr::zero(); a.len().max(b.len())];
    for (i, c) in a.iter().enumerate() {
        out[i].add_assign(*c);
    }
    for (i, c) in b.iter().enumerate() {
        out[i].sub_assign(*c);
    }
    out
}

fn poly_scale(poly: &[Fr], scalar: Fr) -> Vec<Fr> {
    poly.iter().map(|c| fr_mul(*c, scalar)).collect()
}

fn poly_mul(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let output_len = a
        .len()
        .checked_add(b.len())
        .and_then(|len| len.checked_sub(1))
        .expect("non-empty polynomial lengths must fit in usize");
    let mut out = vec![Fr::zero(); output_len];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            let index = i
                .checked_add(j)
                .expect("polynomial coefficient index must fit in usize");
            out[index].add_assign(fr_mul(*x, *y));
        }
    }
    out
}

/// Divide two polynomials and require a zero remainder.
fn poly_divide_exact(numerator: &[Fr], divisor: &[Fr]) -> Vec<Fr> {
    let degree = divisor
        .len()
        .checked_sub(1)
        .expect("the divisor polynomial must not be empty");
    let mut remainder = numerator.to_vec();
    if remainder.len() <= degree {
        assert!(
            remainder.iter().all(|c| c.is_zero()),
            "division must be exact"
        );
        return vec![Fr::zero()];
    }
    let leading_inverse = divisor[degree].inverse().unwrap();
    let quotient_len = remainder
        .len()
        .checked_sub(degree)
        .expect("the numerator degree must be at least the divisor degree");
    let mut quotient = vec![Fr::zero(); quotient_len];
    for i in (degree..remainder.len()).rev() {
        let coefficient = fr_mul(remainder[i], leading_inverse);
        let quotient_index = i
            .checked_sub(degree)
            .expect("the loop starts at the divisor degree");
        quotient[quotient_index] = coefficient;
        for (j, d) in divisor.iter().enumerate() {
            let remainder_index = quotient_index
                .checked_add(j)
                .expect("the remainder coefficient index must fit in usize");
            remainder[remainder_index].sub_assign(fr_mul(coefficient, *d));
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
            acc.add_assign(fr_mul(*e, power));
            power.mul_assign(root);
        }
        coefficients.push(fr_mul(acc, n_inverse));
        root.mul_assign(omega_inverse);
    }
    coefficients
}

fn fr_add(lhs: Fr, rhs: Fr) -> Fr {
    lhs.add(rhs)
}

fn fr_sub(lhs: Fr, rhs: Fr) -> Fr {
    lhs.sub(rhs)
}

fn fr_mul(lhs: Fr, rhs: Fr) -> Fr {
    lhs.mul(rhs)
}

fn fr_neg(value: Fr) -> Fr {
    value.neg()
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
    q_o_evals[1] = fr_neg(Fr::one());
    q_o_evals[2] = fr_neg(Fr::one());
    q_o_evals[3] = Fr::one();
    let mut q_c_evals = zero;
    q_c_evals[3] = fr_neg(Fr::one());

    let mut id_labels = [[Fr::zero(); N]; 3];
    {
        let [id_a, id_b, id_c] = &mut id_labels;
        let mut root = Fr::one();
        for (a, (b, c)) in id_a.iter_mut().zip(id_b.iter_mut().zip(id_c.iter_mut())) {
            *a = root;
            *b = fr_mul(k1, root);
            *c = fr_mul(k2, root);
            root.mul_assign(omega);
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
    let product = fr_mul(x, y);
    let p = fr_add(product, x);
    let mut wires = [[Fr::zero(); N]; 3];
    wires[0][0] = p;
    wires[0][1] = x;
    wires[0][2] = product;
    wires[1][1] = y;
    wires[1][2] = x;
    wires[2][1] = product;
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
            let numerator = fr_add(fr_add(wire[j], fr_mul(beta, id[j])), gamma);
            let denominator = fr_add(fr_add(wire[j], fr_mul(beta, sigma[j])), gamma);
            factor.mul_assign(fr_mul(numerator, denominator.inverse().unwrap()));
        }
        running.mul_assign(factor);
        if let Some(next) = j.checked_add(1).and_then(|index| z_evals.get_mut(index)) {
            *next = running;
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
        pi_evals[0] = fr_neg(p);
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
        out[0].add_assign(gamma);
        out[1].add_assign(fr_mul(beta, shift));
        out
    };
    // wire(X) + beta sigma(X) + gamma
    let sigma_factor = |poly: &[Fr], sigma: &[Fr]| -> Vec<Fr> {
        poly_add(&poly_add(poly, &poly_scale(sigma, beta)), &[gamma])
    };
    let z_shifted: Vec<Fr> = z_poly
        .iter()
        .enumerate()
        .map(|(j, coefficient)| fr_mul(*coefficient, omega.pow([j as u64])))
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
    let vanishing_len = N
        .checked_add(1)
        .expect("the fixture domain size must fit in usize");
    let two_n = N
        .checked_mul(2)
        .expect("twice the fixture domain size must fit in usize");
    let three_n = N
        .checked_mul(3)
        .expect("three times the fixture domain size must fit in usize");
    let mut vanishing = vec![Fr::zero(); vanishing_len];
    vanishing[0] = fr_neg(Fr::one());
    vanishing[N] = Fr::one();
    let mut t_poly = poly_divide_exact(&numerator, &vanishing);
    // deg t <= 3n - 4 without blinding, so the X^n-stitched split holds
    t_poly.resize(three_n, Fr::zero());
    let quotient = [
        commit(&t_poly[..N]),
        commit(&t_poly[N..two_n]),
        commit(&t_poly[two_n..]),
    ];
    let zeta = transcript.quotient(&quotient);

    // round 4: evaluations
    let a_ev = poly_eval(&a_poly, zeta);
    let b_ev = poly_eval(&b_poly, zeta);
    let c_ev = poly_eval(&c_poly, zeta);
    let s1_ev = poly_eval(&trapdoor.s_sigma_polys[0], zeta);
    let s2_ev = poly_eval(&trapdoor.s_sigma_polys[1], zeta);
    let zw_ev = poly_eval(&z_poly, fr_mul(zeta, omega));
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
    let vanishing_ev = fr_sub(zeta_n, Fr::one());
    let l1_ev = poly_eval(&l1_poly, zeta);
    let pi_ev = poly_eval(&pi_poly, zeta);
    let perm_a = fr_add(fr_add(a_ev, fr_mul(beta, s1_ev)), gamma);
    let perm_b = fr_add(fr_add(b_ev, fr_mul(beta, s2_ev)), gamma);
    let z_permutation = fr_mul(
        fr_mul(
            fr_mul(alpha, fr_add(fr_add(a_ev, fr_mul(beta, zeta)), gamma)),
            fr_add(fr_add(b_ev, fr_mul(fr_mul(beta, trapdoor.k1), zeta)), gamma),
        ),
        fr_add(fr_add(c_ev, fr_mul(fr_mul(beta, trapdoor.k2), zeta)), gamma),
    );
    let sigma_permutation = fr_neg(fr_mul(fr_mul(fr_mul(alpha, perm_a), perm_b), zw_ev));
    let mut r_poly = [
        poly_scale(&trapdoor.q_m, fr_mul(a_ev, b_ev)),
        poly_scale(&trapdoor.q_l, a_ev),
        poly_scale(&trapdoor.q_r, b_ev),
        poly_scale(&trapdoor.q_o, c_ev),
        trapdoor.q_c.clone(),
        vec![pi_ev],
        poly_scale(&z_poly, z_permutation),
        poly_scale(
            &poly_add(
                &poly_scale(&trapdoor.s_sigma_polys[2], beta),
                &[fr_add(c_ev, gamma)],
            ),
            sigma_permutation,
        ),
        poly_scale(
            &poly_sub(&z_poly, &[Fr::one()]),
            fr_mul(alpha.square(), l1_ev),
        ),
    ]
    .iter()
    .fold(Vec::new(), |acc, term| poly_add(&acc, term));
    let t_combined = poly_add(
        &poly_add(&t_poly[..N], &poly_scale(&t_poly[N..two_n], zeta_n)),
        &poly_scale(&t_poly[two_n..], zeta_n.square()),
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
        v_power.mul_assign(v);
    }
    let w_zeta = poly_divide_exact(&w_numerator, &[fr_neg(zeta), Fr::one()]);
    let w_zeta_omega = poly_divide_exact(
        &poly_sub(&z_poly, &[zw_ev]),
        &[fr_neg(fr_mul(zeta, omega)), Fr::one()],
    );
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
