//! Vanilla PLONK verifier, byte-compatible with snarkjs, built for minimal
//! compute on Solana. Uses only syscalls active on mainnet-beta: the
//! alt_bn128 group operations and keccak256.
//!
//! Three ideas carry the design. First, every elliptic-curve operation is a
//! flat-priced syscall, so the verifier is organized around the minimum the
//! snarkjs verification equation needs: 20 G1 scalar multiplications, 18
//! additions, and a single pairing call carrying both pairs. Second, the
//! one field inversion the protocol asks for (Lagrange denominators) is
//! never performed: the pairing check e(-A1, X2) * e(B1, G2) = 1 is
//! invariant under scaling both G1 arguments by any K != 0, because the
//! target group has prime order r. Scaling everything by
//! K = n * prod(xi - omega^i) clears every denominator, and the factor K
//! is absorbed into scalars that had to be multiplied anyway. Third, no
//! point is ever negated or subtracted: wherever a point enters with a
//! minus sign, its scalar is negated instead (r - s, one pass over the
//! digits), so -K*A1 and -K*E come out of their multiplications directly
//! and every combination is a plain addition.
//!
//! Scalar arithmetic is Montgomery multiplication in CIOS form over eight
//! base-2^32 digits, chosen so every partial product is a single native
//! 64-bit multiply on SBF. Each scalar lives in two forms: Montgomery
//! (x*R mod r, R = 2^256) for arithmetic, and raw (plain residue) - the
//! exact bytes the keccak transcript and the syscalls consume. The
//! identity mont_mul(x*R, y) = x*y lets any product chain END in raw form
//! for free, so serialization never costs a separate reduction. The
//! Montgomery residue matches the representation inside plonk_solana::Fr
//! bit for bit, so parsed values reinterpret at zero cost.
//!
//! Notation follows snarkjs plonk_verify.js: challenges beta, gamma,
//! alpha, xi, v, u; omega is the evaluation-domain generator, n = 2^power
//! the domain size, Z_H(xi) = xi^n - 1 the vanishing polynomial, L_i the
//! Lagrange basis at xi, PI the public-input polynomial, r0 the constant
//! part of the linearization, and D, F, E the batched commitments.
//! Security invariants: public inputs and proof scalars are rejected
//! unless < r (non-canonical encodings forge nothing - the Frozen Heart
//! bug class); K = 0, where Lagrange values are undefined, is rejected;
//! curve-point validation lives inside the alt_bn128 syscalls; the
//! Fiat-Shamir transcript is byte-identical to snarkjs. Negated scalars
//! are ordinary residues, so (r-s)*P = -s*P exactly.

use light_hasher::{Hasher, Keccak};
#[cfg(not(target_os = "solana"))]
use plonk_solana::syscalls::{g1_addition_be, g1_multiplication_be, pairing_be};
use plonk_solana::{Fr, G1, PlonkError, Proof, VerificationKey};

#[cfg(target_os = "solana")]
extern "C" {
    fn sol_alt_bn128_group_op(
        group_op: u64,
        input: *const u8,
        input_size: u64,
        result: *mut u8,
    ) -> u64;
    fn sol_alt_bn128_group_op_observed(
        group_op: u64,
        input: *const u8,
        input_size: u64,
        result: *mut u8,
    ) -> u64;
}

#[cfg(target_os = "solana")]
#[inline(always)]
fn observed_or_native_group_op(group_op: u64, input: &[u8], result: &mut [u8]) -> u64 {
    #[allow(unexpected_cfgs)]
    const OBSERVED: bool = cfg!(feature = "legacy-group-op-observer");
    unsafe {
        if OBSERVED {
            sol_alt_bn128_group_op_observed(
                group_op,
                input.as_ptr(),
                input.len() as u64,
                result.as_mut_ptr(),
            )
        } else {
            sol_alt_bn128_group_op(
                group_op,
                input.as_ptr(),
                input.len() as u64,
                result.as_mut_ptr(),
            )
        }
    }
}

#[cfg(target_os = "solana")]
fn g1_addition_be(input: &[u8; 128]) -> Result<[u8; 64], PlonkError> {
    let mut result = [0u8; 64];
    (observed_or_native_group_op(0, input, &mut result) == 0)
        .then_some(result)
        .ok_or(PlonkError::G1AdditionFailed)
}

#[cfg(target_os = "solana")]
fn g1_multiplication_be(input: &[u8; 96]) -> Result<[u8; 64], PlonkError> {
    let mut result = [0u8; 64];
    (observed_or_native_group_op(2, input, &mut result) == 0)
        .then_some(result)
        .ok_or(PlonkError::G1MulFailed)
}

#[cfg(target_os = "solana")]
fn pairing_be(input: &[u8]) -> Result<[u8; 32], PlonkError> {
    let mut result = [0u8; 32];
    (observed_or_native_group_op(3, input, &mut result) == 0)
        .then_some(result)
        .ok_or(PlonkError::PairingFailed)
}

/// Upper bound on public inputs, enforced before `verify` runs. Sizes the
/// fixed stack buffers (SBF stack frames are 4 KiB).
const MAX_PUBLIC_INPUTS: usize = 32;

/// Verifies a snarkjs vanilla PLONK proof.
/// 1. Check public inputs are canonical field elements.
/// 2. Derive the Fiat-Shamir challenges (keccak transcript, snarkjs order).
/// 3. Evaluate Z_H(xi) and the K-scaled Lagrange terms K*L_1..K*L_nPublic.
/// 4. Compute K*PI(xi) and the K-scaled linearization constant K*r0.
/// 5. Assemble the batched commitments D, F, E (all scalars carry K).
/// 6. Check the pairing equation e(-K*A1, X_2) * e(K*B1, G2) == 1.
#[inline(never)]
pub fn verify(
    vk: &VerificationKey,
    proof: &Proof,
    public_inputs: &[[u8; 32]],
) -> Result<(), PlonkError> {
    let operands = prepare_pairing_operands(vk, proof, public_inputs, BatchScalar::ONE)?;
    check_pairing(vk, &operands)
}

/// A nonzero scalar that multiplies a complete proof equation before any
/// curve point is constructed. This is the outer batching coefficient; the
/// private representation prevents callers from supplying zero or a
/// non-canonical field encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchScalar(F);

impl BatchScalar {
    pub const ONE: Self = Self(F::ONE);

    pub fn from_be_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let raw = Raw::from_be_bytes(bytes)?;
        if raw == Raw::ZERO {
            return None;
        }
        Some(Self(F(mont_mul(&raw.0, &R2))))
    }
}

/// The two G1 operands of one scaled PLONK pairing equation. The verifier
/// intentionally exposes only recomputed operands, never caller-provided
/// intermediate points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairingOperands {
    neg_a1: G1,
    b1: G1,
}

impl PairingOperands {
    pub fn neg_a1(&self) -> &G1 {
        &self.neg_a1
    }

    pub fn b1(&self) -> &G1 {
        &self.b1
    }
}

/// Number of direct G1 MSM terms emitted in the left and right streams of
/// one expanded proof equation. Batched callers concatenate these fixed
/// streams and execute exactly two MSM syscalls for the whole batch.
pub const P_CONTRIBUTIONS: usize = 2;
pub const Q_CONTRIBUTIONS: usize = 18;

/// Destination for the fully expanded G1 terms of a scaled proof equation.
/// A sink API avoids materializing a roughly 2 KiB return value on the SBF
/// stack while still exposing every source point and scalar directly.
pub trait PairingContributionSink {
    fn push_p(&mut self, point: G1, scalar: [u8; 32]);
    fn push_q(&mut self, point: G1, scalar: [u8; 32]);
}

/// Recompute the byte-identical snarkjs proof-local transcript and absorb a
/// nonzero outer coefficient into K before constructing any curve point.
/// The result is suitable for atomic multi-proof aggregation into exactly
/// two G1 streams.
#[inline(never)]
pub fn prepare_pairing_operands(
    vk: &VerificationKey,
    proof: &Proof,
    public_inputs: &[[u8; 32]],
    batch_scalar: BatchScalar,
) -> Result<PairingOperands, PlonkError> {
    // 1-4 run in `prepare`'s own stack frame: its two 1 KiB buffers die
    // there, which is what keeps every frame under the 4 KiB SBF limit.
    let p = prepare(vk, proof, public_inputs, batch_scalar.0)?;
    let challenges = &p.challenges;
    let evals = &p.evals;

    // 4b. Terms shared between r0 and D, the batching coefficients, K*r0.
    let shared = compute_shared(evals, challenges, p.scaled_l1);
    let kv = compute_kv(challenges);
    let r0 = compute_scaled_r0(evals, challenges, &shared, p.scaled_pi);

    // 5. Assemble the batched commitments D, F, E (all scalars carry K).
    let d = compute_d(vk, proof, evals, challenges, &shared, &kv)?;
    let f = compute_f(vk, proof, &kv, &d)?;
    let e = compute_e(evals, &kv, r0)?;

    // 6. Return the two scaled G1 operands. The caller chooses only the
    // final boolean, registry, or FP12 handler after aggregation.
    pairing_operands(vk, proof, challenges, &kv, &e, &f)
}

/// Recompute the byte-identical proof-local transcript, absorb the nonzero
/// outer coefficient into K, and expose the pairing equation as direct MSM
/// terms. Unlike `prepare_pairing_operands`, this function performs no G1
/// operations; the caller can concatenate all proofs and reduce them with
/// exactly two aggregate MSM calls.
#[inline(never)]
pub fn prepare_pairing_contributions<S: PairingContributionSink>(
    vk: &VerificationKey,
    proof: &Proof,
    public_inputs: &[[u8; 32]],
    batch_scalar: BatchScalar,
    sink: &mut S,
) -> Result<(), PlonkError> {
    let p = prepare(vk, proof, public_inputs, batch_scalar.0)?;
    let challenges = &p.challenges;
    let evals = &p.evals;
    let shared = compute_shared(evals, challenges, p.scaled_l1);
    let kv = compute_kv(challenges);
    let scaled_r0 = compute_scaled_r0(evals, challenges, &shared, p.scaled_pi);

    // -K*A1 = (-K)*Wxi + (-(K*u))*Wxiw.
    sink.push_p(proof.wxi, challenges.k_raw.neg().to_be_bytes());
    sink.push_p(proof.wxiw, kv.ku.neg().to_be_bytes());

    // K*B1, distributed all the way to its source commitments. This is the
    // exact scalar expansion of compute_d -> compute_f -> compute_e ->
    // pairing_operands, with rho already present in every K-derived scalar.
    let betaxi = challenges.beta.mul(challenges.xi);
    let d2a1 = evals.a.add(betaxi).add(challenges.gamma);
    let d2a2 = evals
        .b
        .add(betaxi.mul(F::from_fr(&vk.k1)))
        .add(challenges.gamma);
    let d2a3 = evals
        .c
        .add(betaxi.mul(F::from_fr(&vk.k2)))
        .add(challenges.gamma);
    let d2 = d2a1
        .mul(d2a2)
        .mul(d2a3)
        .mul_raw(shared.kalpha_raw)
        .add(kv.ku)
        .add(shared.l1a2_raw);
    let d3 = challenges.beta.mul_raw(shared.p_raw).neg();
    let neg_kzh = challenges.zh.mul_raw(challenges.k_raw).neg();

    sink.push_q(
        proof.wxi,
        challenges.xi.mul_raw(challenges.k_raw).to_be_bytes(),
    );
    sink.push_q(
        proof.wxiw,
        F::from_fr(&vk.w)
            .mul_raw(challenges.xi.mul_raw(kv.ku))
            .to_be_bytes(),
    );
    sink.push_q(
        vk.qm,
        evals
            .b
            .mul_raw(challenges.k.mul_raw(evals.a_raw))
            .to_be_bytes(),
    );
    sink.push_q(vk.ql, challenges.k.mul_raw(evals.a_raw).to_be_bytes());
    sink.push_q(vk.qr, challenges.k.mul_raw(evals.b_raw).to_be_bytes());
    sink.push_q(vk.qo, challenges.k.mul_raw(evals.c_raw).to_be_bytes());
    sink.push_q(vk.qc, challenges.k_raw.to_be_bytes());
    sink.push_q(proof.z, d2.to_be_bytes());
    sink.push_q(vk.s3, d3.to_be_bytes());
    sink.push_q(proof.t1, neg_kzh.to_be_bytes());
    sink.push_q(proof.t2, challenges.xin.mul_raw(neg_kzh).to_be_bytes());
    sink.push_q(
        proof.t3,
        challenges.xin.square().mul_raw(neg_kzh).to_be_bytes(),
    );
    sink.push_q(proof.a, kv.kv[0].to_be_bytes());
    sink.push_q(proof.b, kv.kv[1].to_be_bytes());
    sink.push_q(proof.c, kv.kv[2].to_be_bytes());
    sink.push_q(vk.s1, kv.kv[3].to_be_bytes());
    sink.push_q(vk.s2, kv.kv[4].to_be_bytes());
    sink.push_q(
        G1::GENERATOR,
        compute_e_scalar(evals, &kv, scaled_r0).to_be_bytes(),
    );

    Ok(())
}

/// Everything the commitment/pairing phase needs, with the 1 KiB buffers
/// already collapsed into two field elements.
struct Prepared {
    challenges: Challenges,
    evals: Evals,
    /// K*PI(xi), raw.
    scaled_pi: Raw,
    /// K*L_1(xi)
    scaled_l1: F,
}

/// Steps 1-4a of verification (own stack frame, see `verify`):
/// 1. Check the public input count binds to the verification key.
/// 2. Derive the Fiat-Shamir challenges (keccak transcript, snarkjs order).
/// 3. Evaluate Z_H(xi) and the K-scaled Lagrange terms K*L_1..K*L_nPublic.
/// 4. Fold public inputs into K*PI(xi).
#[inline(never)]
fn prepare(
    vk: &VerificationKey,
    proof: &Proof,
    public_inputs: &[[u8; 32]],
    batch_scale: F,
) -> Result<Prepared, PlonkError> {
    // 1. Check the public input count binds to the verification key.
    check_public_inputs_len(vk, public_inputs)?;

    // 2. Derive the Fiat-Shamir challenges (keccak transcript, snarkjs order).
    let evals = load_evals(proof);
    let mut challenges = compute_challenges(vk, proof, public_inputs, &evals)?;

    // 3. Evaluate Z_H(xi) and the K-scaled Lagrange terms K*L_1..K*L_nPublic.
    let mut lagrange_buf = [F::ZERO; MAX_PUBLIC_INPUTS];
    let n_lag = compute_scaled_lagrange(vk, &mut challenges, &mut lagrange_buf, batch_scale)?;

    // 4. Reject any public input >= r, then fold it into
    // K*PI(xi) = -sum(public_i * K*L_{i+1}) as it is read. The input bytes
    // ARE the raw form, so one mul_raw per input suffices - no Montgomery
    // conversion and no second buffer.
    let mut scaled_pi = Raw::ZERO;
    for (bytes, l) in public_inputs.iter().zip(&lagrange_buf[..n_lag]) {
        let public =
            Raw::from_be_bytes(bytes).ok_or(PlonkError::PublicInputGreaterThanFieldSize)?;
        scaled_pi = scaled_pi.sub(l.mul_raw(public));
    }
    let scaled_l1 = lagrange_buf[0];
    Ok(Prepared {
        challenges,
        evals,
        scaled_pi,
        scaled_l1,
    })
}

/// Checks:
/// 1. input count matches vk.n_public and fits the Lagrange buffer
///
/// (Canonicality of each input is checked where it is folded into PI.)
fn check_public_inputs_len(
    vk: &VerificationKey,
    public_inputs: &[[u8; 32]],
) -> Result<(), PlonkError> {
    // 1. input count matches vk.n_public and fits the Lagrange buffer
    let count = public_inputs.len();
    if count != vk.n_public as usize || count > MAX_PUBLIC_INPUTS {
        return Err(PlonkError::InvalidPublicInputsLength);
    }
    Ok(())
}

/// Fiat-Shamir challenges (snarkjs naming).
struct Challenges {
    beta: F,
    gamma: F,
    alpha: F,
    /// alpha as a raw residue, free from the hash reduction; it finishes
    /// the alpha^2 chains without a squaring of its own.
    alpha_raw: Raw,
    xi: F,
    /// xi^n where n = 2^power (domain size).
    xin: F,
    /// Z_H(xi) = xi^n - 1.
    zh: F,
    /// K = n * prod(xi - omega^i), the product of all Lagrange
    /// denominators. Every scalar in the pairing equation carries K, so no
    /// inversion is ever computed.
    k: F,
    /// K as a raw residue - the shared raw factor of the scalar chains.
    k_raw: Raw,
    /// v1; the higher powers of v only ever appear multiplied by K and
    /// live in `Kv` as raw values.
    v1: F,
    /// u, raw only: Wxiw's coefficient in A1 as-is; every arithmetic use
    /// goes through K*u in `Kv`.
    u_raw: Raw,
}

/// Keccak256 over the parts, reduced into both scalar forms (snarkjs
/// getChallenge semantics); the raw bytes feed the next transcript round.
fn challenge(parts: &[&[u8]]) -> Result<(F, Raw), PlonkError> {
    let hash = Keccak::hashv(parts).map_err(|_| PlonkError::KeccakFailed)?;
    Ok(F::from_hash(&hash))
}

/// Keccak256 reduced into Montgomery form only, for challenges whose raw
/// form is never consumed (v1). The unreduced 256-bit hash goes straight
/// into mont_mul: with the second operand < r the accumulator stays below
/// 2^256 + r < 2*2^256, and one final conditional subtraction suffices, so
/// the result equals hash * R mod r exactly - no reduction loop needed.
fn challenge_mont(parts: &[&[u8]]) -> Result<F, PlonkError> {
    let hash = Keccak::hashv(parts).map_err(|_| PlonkError::KeccakFailed)?;
    Ok(F(mont_mul(&digits_from_be_bytes(&hash), &R2)))
}

/// Derives beta, gamma, alpha, xi, v1, u - transcript order and encoding
/// (big-endian scalars, big-endian uncompressed points) exactly as snarkjs.
#[inline(never)]
fn compute_challenges(
    vk: &VerificationKey,
    proof: &Proof,
    public_inputs: &[[u8; 32]],
    evals: &Evals,
) -> Result<Challenges, PlonkError> {
    // 1. beta <- keccak(Qm,Ql,Qr,Qo,Qc,S1,S2,S3, publics..., A,B,C)
    // Fixed stack array of slice references, no heap: 8 selectors, up to
    // MAX_PUBLIC_INPUTS public inputs, 3 round-1 commitments.
    let mut parts: [&[u8]; 11 + MAX_PUBLIC_INPUTS] = [&[]; 11 + MAX_PUBLIC_INPUTS];
    parts[0] = vk.qm.as_bytes();
    parts[1] = vk.ql.as_bytes();
    parts[2] = vk.qr.as_bytes();
    parts[3] = vk.qo.as_bytes();
    parts[4] = vk.qc.as_bytes();
    parts[5] = vk.s1.as_bytes();
    parts[6] = vk.s2.as_bytes();
    parts[7] = vk.s3.as_bytes();
    let mut len = 8;
    for public in public_inputs {
        parts[len] = public.as_slice();
        len += 1;
    }
    parts[len] = proof.a.as_bytes();
    parts[len + 1] = proof.b.as_bytes();
    parts[len + 2] = proof.c.as_bytes();
    let (beta, beta_raw) = challenge(&parts[..len + 3])?;

    // 2. gamma <- keccak(beta). The transcript bytes come from the raw
    // form, so no Montgomery reduction is spent on serialization.
    let beta_be = beta_raw.to_be_bytes();
    let (gamma, gamma_raw) = challenge(&[&beta_be])?;

    // 3. alpha <- keccak(beta, gamma, Z)
    let gamma_be = gamma_raw.to_be_bytes();
    let (alpha, alpha_raw) = challenge(&[&beta_be, &gamma_be, proof.z.as_bytes()])?;

    // 4. xi <- keccak(alpha, T1, T2, T3)
    let alpha_be = alpha_raw.to_be_bytes();
    let (xi, xi_raw) = challenge(&[
        &alpha_be,
        proof.t1.as_bytes(),
        proof.t2.as_bytes(),
        proof.t3.as_bytes(),
    ])?;

    // 5. v1 <- keccak(xi, eval_a, eval_b, eval_c, eval_s1, eval_s2, eval_zw)
    // The canonical evaluation bytes come from the raw forms in `evals`;
    // their one reduction is shared with the scalar chains of D.
    let xi_be = xi_raw.to_be_bytes();
    let v1 = challenge_mont(&[
        &xi_be,
        &evals.a_raw.to_be_bytes(),
        &evals.b_raw.to_be_bytes(),
        &evals.c_raw.to_be_bytes(),
        &evals.s1_raw.to_be_bytes(),
        &evals.s2_raw.to_be_bytes(),
        &evals.zw_raw.to_be_bytes(),
    ])?;
    // (v^2..v^5 are formed directly as raw K*v^i in compute_kv.)

    // 6. u <- keccak(Wxi, Wxiw), raw only: u is consumed as a syscall
    // scalar and through K*u, so its Montgomery form is never built.
    let mut u_digits = digits_from_be_bytes(
        &Keccak::hashv(&[proof.wxi.as_bytes(), proof.wxiw.as_bytes()])
            .map_err(|_| PlonkError::KeccakFailed)?,
    );
    while !digits_lt(&u_digits, &MODULUS) {
        u_digits = digits_sub(&u_digits, &MODULUS).0;
    }
    let u_raw = Raw(u_digits);

    Ok(Challenges {
        beta,
        gamma,
        alpha,
        alpha_raw,
        xi,
        xin: F::ZERO,    // filled by compute_scaled_lagrange
        zh: F::ZERO,     // filled by compute_scaled_lagrange
        k: F::ZERO,      // filled by compute_scaled_lagrange
        k_raw: Raw::ONE, // filled by compute_scaled_lagrange
        v1,
        u_raw,
    })
}

/// Proof evaluations in both scalar forms. The raw forms cost exactly the
/// six reductions the transcript already needed (v1 hashes the canonical
/// evaluation bytes); the scalar chains of D then reuse them as free raw
/// factors.
struct Evals {
    a: F,
    b: F,
    c: F,
    s1: F,
    s2: F,
    zw: F,
    a_raw: Raw,
    b_raw: Raw,
    c_raw: Raw,
    s1_raw: Raw,
    s2_raw: Raw,
    zw_raw: Raw,
}

/// Reinterprets the parsed evaluations (free, same Montgomery residue as
/// plonk_solana::Fr) and derives their raw forms, one reduction each.
fn load_evals(proof: &Proof) -> Evals {
    let a = F::from_fr(&proof.eval_a);
    let b = F::from_fr(&proof.eval_b);
    let c = F::from_fr(&proof.eval_c);
    let s1 = F::from_fr(&proof.eval_s1);
    let s2 = F::from_fr(&proof.eval_s2);
    let zw = F::from_fr(&proof.eval_zw);
    Evals {
        a,
        b,
        c,
        s1,
        s2,
        zw,
        a_raw: a.to_raw(),
        b_raw: b.to_raw(),
        c_raw: c.to_raw(),
        s1_raw: s1.to_raw(),
        s2_raw: s2.to_raw(),
        zw_raw: zw.to_raw(),
    }
}

/// Computes xi^n, Z_H(xi), K, and the K-scaled Lagrange terms - with no
/// inversion anywhere. Write d_j = xi - omega^j. With
/// K = n * prod_j(d_j), the n inside L_i = omega^i * zh / (n * d_i)
/// cancels:
///     K*L_i = omega^i * zh * prod_{j != i}(d_j)
/// so each term is a product of everything EXCEPT its own denominator.
/// Those are built with one prefix pass and one suffix pass; zh rides as
/// the suffix's initial value, and K's factor n = 2^power arrives as
/// `power` doublings (additions, not multiplications).
#[inline(never)]
fn compute_scaled_lagrange(
    vk: &VerificationKey,
    challenges: &mut Challenges,
    lagrange: &mut [F; MAX_PUBLIC_INPUTS],
    batch_scale: F,
) -> Result<usize, PlonkError> {
    // 1. xi^n by repeated squaring; n = 2^power.
    let mut xin = challenges.xi;
    for _ in 0..vk.power {
        xin = xin.square();
    }
    challenges.xin = xin;
    challenges.zh = xin.sub(F::ONE);

    let count = (vk.n_public as usize).clamp(1, MAX_PUBLIC_INPUTS);
    let vk_w = F::from_fr(&vk.w);

    // 2.1. Prefix pass. Only omega^i is stored (one array; the frame is
    // 4 KiB); the denominator d_i is recomputed in the suffix pass by a
    // free subtraction. lagrange[i] stashes the prefix product
    // d_0 * .. * d_{i-1}. Lane 0 is peeled: omega^0 = 1 and its prefix is
    // empty, so its "products" are assignments.
    let mut wpow = [F::ZERO; MAX_PUBLIC_INPUTS];
    wpow[0] = F::ONE;
    let mut w = F::ONE;
    let mut running = challenges.xi.sub(F::ONE); // d_0
    for i in 1..count {
        w = w.mul(vk_w);
        wpow[i] = w;
        lagrange[i] = running; // prefix product for the suffix pass
        running = running.mul(challenges.xi.sub(w));
    }

    // 2.2. K = n * prod(d_j), the n applied as doublings. K = 0 means xi
    // landed on a domain element and the Lagrange values are undefined -
    // reject before K is used anywhere.
    if running.is_zero() {
        return Err(PlonkError::LagrangeDivisionByZero);
    }
    let mut k = running;
    for _ in 0..vk.power {
        k = k.add(k);
    }
    // The outer rho is multiplied into K before any G1 construction. The
    // Lagrange and public-input terms below receive the same factor, so the
    // complete pairing equation -- not merely its final points -- is scaled.
    k = k.mul(batch_scale);
    challenges.k = k;
    challenges.k_raw = k.to_raw();

    // 2.3. Suffix pass, back to front: K*L_i = omega^i * prefix_i *
    // suffix_i with zh folded into the suffix's initial value. The lane-0
    // term IS the final suffix (both its other factors are 1).
    let mut suffix = challenges.zh.mul(batch_scale);
    for i in (1..count).rev() {
        let scaled = wpow[i].mul(lagrange[i]).mul(suffix);
        suffix = suffix.mul(challenges.xi.sub(wpow[i]));
        lagrange[i] = scaled;
    }
    lagrange[0] = suffix;
    Ok(count)
}

/// The batching coefficients K*v^1..K*v^5 and K*u, all raw. Chaining
/// kv_i = v1 * kv_{i-1} through mul_raw keeps every step in raw form for
/// free, so neither a Montgomery v-power chain nor per-coefficient K
/// multiplications exist. E reuses the same values, since
/// K*(sum v^i * e_i) = sum kv_i * e_i.
struct Kv {
    kv: [Raw; 5],
    ku: Raw,
}

fn compute_kv(challenges: &Challenges) -> Kv {
    let mut kv = [Raw::ONE; 5];
    kv[0] = challenges.v1.mul_raw(challenges.k_raw);
    for i in 1..5 {
        kv[i] = challenges.v1.mul_raw(kv[i - 1]);
    }
    Kv {
        kv,
        ku: challenges.k.mul_raw(challenges.u_raw),
    }
}

/// Terms shared by the linearization constant r0 and the commitment D
/// (they overlap on the permutation argument): computed once, used twice.
struct Shared {
    /// K*alpha, raw - shared factor of P and of Z's scalar in d2.
    kalpha_raw: Raw,
    /// P = (a+beta*s1+gamma)(b+beta*s2+gamma) * zw * (K*alpha), raw - the
    /// common prefix of e3 in r0 (times c+gamma) and of d3's scalar
    /// (times beta).
    p_raw: Raw,
    /// (K*L1) * alpha^2, raw - e2 in r0 and one summand of Z's scalar.
    l1a2_raw: Raw,
}

/// 1. K*alpha, raw
/// 2. d3a/d3b from the permutation argument
/// 3. shared prefix P, landing raw on K*alpha's raw form
/// 4. (K*L1)*alpha^2, finished by alpha's raw form so no squaring occurs
fn compute_shared(evals: &Evals, challenges: &Challenges, scaled_l1: F) -> Shared {
    // 1. K*alpha, raw
    let kalpha_raw = challenges.alpha.mul_raw(challenges.k_raw);
    // 2. d3a/d3b from the permutation argument
    let d3a = evals
        .a
        .add(challenges.beta.mul(evals.s1))
        .add(challenges.gamma);
    let d3b = evals
        .b
        .add(challenges.beta.mul(evals.s2))
        .add(challenges.gamma);
    // 3. shared prefix P, landing raw on K*alpha's raw form
    let p_raw = d3a.mul(d3b).mul(evals.zw).mul_raw(kalpha_raw);
    // 4. (K*L1)*alpha^2 = ((K*L1)*alpha) * alpha_raw - the second alpha
    // factor is the raw one from the hash, so alpha^2 is never formed.
    Shared {
        kalpha_raw,
        p_raw,
        l1a2_raw: scaled_l1
            .mul(challenges.alpha)
            .mul_raw(challenges.alpha_raw),
    }
}

/// K*r0 = K*PI(xi) - (K*L1)*alpha^2 - P*(c + gamma), all raw; e3 lands raw
/// off P's raw form, the other two terms are raw already.
fn compute_scaled_r0(
    evals: &Evals,
    challenges: &Challenges,
    shared: &Shared,
    scaled_pi: Raw,
) -> Raw {
    let e3 = evals.c.add(challenges.gamma).mul_raw(shared.p_raw);
    scaled_pi.sub(shared.l1a2_raw).sub(e3)
}

/// K*D = d1 + d2 - d3 - d4 (snarkjs calculateD, every scalar times K):
/// d1 = (K*a*b)Qm + (K*a)Ql + (K*b)Qr + (K*c)Qo + K*Qc
/// d2 = Z * [K*(a+beta*xi+gamma)(b+beta*k1*xi+gamma)(c+beta*k2*xi+gamma)*alpha
///           + (K*L1)*alpha^2 + K*u]
/// d3 = S3 * K*(a+beta*s1+gamma)(b+beta*s2+gamma)*alpha*beta*zw
/// d4 = (T1 + xi^n*T2 + xi^2n*T3) * (K*zh)
/// The d3 and d4 scalars are negated up front, so the combination in step
/// 5 is four plain additions.
#[inline(never)]
fn compute_d(
    vk: &VerificationKey,
    proof: &Proof,
    evals: &Evals,
    challenges: &Challenges,
    shared: &Shared,
    kv: &Kv,
) -> Result<G1, PlonkError> {
    let k = challenges.k;

    // 1. d1. Every scalar lands raw in ONE multiplication: Montgomery K
    // times a raw evaluation, then a Montgomery evaluation chained onto
    // the raw product. Qc's scalar is K itself, already raw.
    let ka = k.mul_raw(evals.a_raw);
    let kab = evals.b.mul_raw(ka);
    let mut d1 = g1_mul(&vk.qm, kab)?;
    d1 = g1_add(&d1, &g1_mul(&vk.ql, ka)?)?;
    d1 = g1_add(&d1, &g1_mul(&vk.qr, k.mul_raw(evals.b_raw))?)?;
    d1 = g1_add(&d1, &g1_mul(&vk.qo, k.mul_raw(evals.c_raw))?)?;
    d1 = g1_add(&d1, &g1_mul(&vk.qc, challenges.k_raw)?)?;

    // 2. d2. K*(d2a + u) = K*d2a + K*u: the raw K*u from the Kv chain
    // stands in for u's Montgomery form, and the whole scalar stays raw.
    let betaxi = challenges.beta.mul(challenges.xi);
    let d2a1 = evals.a.add(betaxi).add(challenges.gamma);
    let d2a2 = evals
        .b
        .add(betaxi.mul(F::from_fr(&vk.k1)))
        .add(challenges.gamma);
    let d2a3 = evals
        .c
        .add(betaxi.mul(F::from_fr(&vk.k2)))
        .add(challenges.gamma);
    let d2a = d2a1.mul(d2a2).mul(d2a3);
    let d2 = g1_mul(
        &proof.z,
        d2a.mul_raw(shared.kalpha_raw)
            .add(kv.ku)
            .add(shared.l1a2_raw),
    )?;

    // 3. -d3 = S3 * (-P*beta): the scalar is negated, so the point never is.
    let d3 = g1_mul(&vk.s3, challenges.beta.mul_raw(shared.p_raw).neg())?;

    // 4. -d4: xi^2n lands raw off xi^n's own raw form; the outer scalar
    // -(K*zh) is negated the same way.
    let xin_raw = challenges.xin.to_raw();
    let xin2_raw = challenges.xin.mul_raw(xin_raw);
    let mut d4 = g1_add(&proof.t1, &g1_mul(&proof.t2, xin_raw)?)?;
    d4 = g1_add(&d4, &g1_mul(&proof.t3, xin2_raw)?)?;
    d4 = g1_mul(&d4, challenges.zh.mul_raw(challenges.k_raw).neg())?;

    // 5. K*D = d1 + d2 + (-d3) + (-d4).
    let d = g1_add(&d1, &d2)?;
    let d = g1_add(&d, &d3)?;
    g1_add(&d, &d4)
}

/// K*F = K*D + (K*v)*A + (K*v^2)*B + (K*v^3)*C + (K*v^4)*S1 + (K*v^5)*S2.
#[inline(never)]
fn compute_f(vk: &VerificationKey, proof: &Proof, kv: &Kv, d: &G1) -> Result<G1, PlonkError> {
    let mut f = g1_add(d, &g1_mul(&proof.a, kv.kv[0])?)?;
    f = g1_add(&f, &g1_mul(&proof.b, kv.kv[1])?)?;
    f = g1_add(&f, &g1_mul(&proof.c, kv.kv[2])?)?;
    f = g1_add(&f, &g1_mul(&vk.s1, kv.kv[3])?)?;
    g1_add(&f, &g1_mul(&vk.s2, kv.kv[4])?)
}

/// -K*E = (K*r0 - kv_1*a - kv_2*b - kv_3*c - kv_4*s1 - kv_5*s2 - K*u*zw)
/// times the G1 generator. K distributes over the sum, every term reuses
/// the raw kv_i, and the sign is flipped by swapping one subtraction's
/// operands - free - so B1 later ADDS this point instead of subtracting.
#[inline(never)]
fn compute_e(evals: &Evals, kv: &Kv, scaled_r0: Raw) -> Result<G1, PlonkError> {
    g1_mul(&G1::GENERATOR, compute_e_scalar(evals, kv, scaled_r0))
}

/// Scalar of the generator contribution -K*E. Kept separate so the batch
/// path can feed it directly to its aggregate Q MSM without constructing a
/// proof-local generator multiple.
fn compute_e_scalar(evals: &Evals, kv: &Kv, scaled_r0: Raw) -> Raw {
    let mut e = evals.a.mul_raw(kv.kv[0]);
    e = e.add(evals.b.mul_raw(kv.kv[1]));
    e = e.add(evals.c.mul_raw(kv.kv[2]));
    e = e.add(evals.s1.mul_raw(kv.kv[3]));
    e = e.add(evals.s2.mul_raw(kv.kv[4]));
    e = e.add(evals.zw.mul_raw(kv.ku));
    scaled_r0.sub(e)
}

/// Pairing check (snarkjs isValidPairing, both sides scaled by K):
/// K*A1 = K*(Wxi + u*Wxiw)
/// K*B1 = (K*xi)*Wxi + (K*u*xi*omega)*Wxiw + K*F - K*E
/// accept iff e(-K*A1, X_2) * e(K*B1, G2_generator) == 1.
#[inline(never)]
fn pairing_operands(
    vk: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
    kv: &Kv,
    e: &G1,
    f: &G1,
) -> Result<PairingOperands, PlonkError> {
    // 1. -K*A1 comes straight out of its multiplication by negating the
    // scalar K. In B1, K*xi lands raw in one multiplication and
    // K*u*xi*omega = omega * (xi * K*u) reuses the raw K*u.
    let a1 = g1_add(&proof.wxi, &g1_mul(&proof.wxiw, challenges.u_raw)?)?;
    let neg_a1 = g1_mul(&a1, challenges.k_raw.neg())?;
    let kxi_raw = challenges.xi.mul_raw(challenges.k_raw);
    let kxiu = challenges.xi.mul_raw(kv.ku);
    let s = F::from_fr(&vk.w).mul_raw(kxiu);
    let mut b1 = g1_mul(&proof.wxi, kxi_raw)?;
    b1 = g1_add(&b1, &g1_mul(&proof.wxiw, s)?)?;
    b1 = g1_add(&b1, f)?;
    b1 = g1_add(&b1, e)?; // e arrives negated from compute_e

    Ok(PairingOperands { neg_a1, b1 })
}

/// Finalize one already prepared equation through the legacy boolean
/// pairing syscall. Batched callers use the same operands with their chosen
/// final handler instead.
#[inline(never)]
fn check_pairing(vk: &VerificationKey, operands: &PairingOperands) -> Result<(), PlonkError> {
    // 2. Pairing input: (-K*A1, X_2) || (K*B1, G2_generator).
    let mut input = [0u8; 384];
    input[0..64].copy_from_slice(operands.neg_a1.as_bytes());
    input[64..192].copy_from_slice(vk.x_2.as_bytes());
    input[192..256].copy_from_slice(operands.b1.as_bytes());
    input[256..384].copy_from_slice(&G2_GENERATOR_BE);
    let result = pairing_be(&input)?;

    // 3. Output is a 32-byte big-endian bool: 1 = product of pairings is 1.
    if result[31] == 1 {
        Ok(())
    } else {
        Err(PlonkError::ProofVerificationFailed)
    }
}

/// BN254 G2 generator, big-endian EIP-197 order (x1 || x0 || y1 || y0),
/// the layout the pairing syscall consumes.
pub const G2_GENERATOR_BE: [u8; 128] = [
    // x1 = 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
    0x19, 0x8e, 0x93, 0x93, 0x92, 0x0d, 0x48, 0x3a, 0x72, 0x60, 0xbf, 0xb7, 0x31, 0xfb, 0x5d, 0x25,
    0xf1, 0xaa, 0x49, 0x33, 0x35, 0xa9, 0xe7, 0x12, 0x97, 0xe4, 0x85, 0xb7, 0xae, 0xf3, 0x12, 0xc2,
    // x0 = 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
    0x18, 0x00, 0xde, 0xef, 0x12, 0x1f, 0x1e, 0x76, 0x42, 0x6a, 0x00, 0x66, 0x5e, 0x5c, 0x44, 0x79,
    0x67, 0x43, 0x22, 0xd4, 0xf7, 0x5e, 0xda, 0xdd, 0x46, 0xde, 0xbd, 0x5c, 0xd9, 0x92, 0xf6, 0xed,
    // y1 = 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
    0x09, 0x06, 0x89, 0xd0, 0x58, 0x5f, 0xf0, 0x75, 0xec, 0x9e, 0x99, 0xad, 0x69, 0x0c, 0x33, 0x95,
    0xbc, 0x4b, 0x31, 0x33, 0x70, 0xb3, 0x8e, 0xf3, 0x55, 0xac, 0xda, 0xdc, 0xd1, 0x22, 0x97, 0x5b,
    // y0 = 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
    0x12, 0xc8, 0x5e, 0xa5, 0xdb, 0x8c, 0x6d, 0xeb, 0x4a, 0xab, 0x71, 0x80, 0x8d, 0xcb, 0x40, 0x8f,
    0xe3, 0xd1, 0xe7, 0x69, 0x0c, 0x43, 0xd3, 0x7b, 0x4c, 0xe6, 0xcc, 0x01, 0x66, 0xfa, 0x7d, 0xaa,
];

// --- Scalar field kernel -------------------------------------------------
//
// BN254 scalar field, eight base-2^32 digits, little-endian digit order.
// Two forms, two types: F holds x*R mod r (Montgomery, R = 2^256), Raw
// holds the plain residue x. The types exist because mixing the forms in
// a product silently multiplies the result by a stray power of R^-1.

/// Number of base-2^32 digits in a scalar field element.
const N_DIGITS: usize = 8;

/// The scalar field modulus,
/// r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001.
const MODULUS: [u32; N_DIGITS] = [
    0xf000_0001,
    0x43e1_f593,
    0x79b9_7091,
    0x2833_e848,
    0x8181_585d,
    0xb850_45b6,
    0xe131_a029,
    0x3064_4e72,
];

/// R^2 mod r; mont_mul(x, R2) = x*R mod r converts raw to Montgomery.
const R2: [u32; N_DIGITS] = [
    0xae21_6da7,
    0x1bb8_e645,
    0xe35c_59e3,
    0x53fe_3ab1,
    0x53bb_8085,
    0x8c49_833d,
    0x7f4e_44a5,
    0x0216_d0b1,
];

/// R mod r - the Montgomery form of 1.
const ONE_MONT: [u32; N_DIGITS] = [
    0x4fff_fffb,
    0xac96_341c,
    0x9f60_cd29,
    0x36fc_7695,
    0x7879_462e,
    0x666e_a36f,
    0x9a07_df2f,
    0x0e0a_77c1,
];

/// -r^-1 mod 2^32, the Montgomery reduction constant.
const INV: u32 = 0xefff_ffff;

/// Scalar in Montgomery form (x*R mod r). The residue is bit-identical to
/// the one inside `plonk_solana::Fr`, so it reinterprets at zero cost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct F([u32; N_DIGITS]);

/// Scalar as a plain residue - exactly the bytes the alt_bn128 syscalls
/// and the keccak transcript consume. Produced either directly from a
/// reduced hash or by `F::mul_raw`/`F::to_raw`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Raw([u32; N_DIGITS]);

impl F {
    const ZERO: F = F([0; N_DIGITS]);
    const ONE: F = F(ONE_MONT);

    /// Reinterprets a `plonk_solana::Fr`: it stores the same Montgomery
    /// residue as four little-endian u64 words; split each into
    /// (low, high) u32 digits.
    fn from_fr(fr: &Fr) -> F {
        let words: [u64; 4] = fr.0.0.0;
        let mut out = [0u32; N_DIGITS];
        for (i, w) in words.iter().enumerate() {
            out[2 * i] = *w as u32;
            out[2 * i + 1] = (*w >> 32) as u32;
        }
        F(out)
    }

    /// Converts a 32-byte keccak output with silent modular reduction
    /// (snarkjs getChallenge semantics; at most a handful of subtractions
    /// since 2^256 / r < 6). Returns both forms: the raw one costs nothing
    /// extra here, and its bytes feed the next transcript round.
    fn from_hash(bytes: &[u8; 32]) -> (F, Raw) {
        let mut raw = digits_from_be_bytes(bytes);
        while !digits_lt(&raw, &MODULUS) {
            raw = digits_sub(&raw, &MODULUS).0;
        }
        (F(mont_mul(&raw, &R2)), Raw(raw))
    }

    /// Small-integer constructor, used only by the equivalence tests.
    #[cfg(test)]
    fn from_u64(v: u64) -> F {
        let mut raw = [0u32; N_DIGITS];
        raw[0] = v as u32;
        raw[1] = (v >> 32) as u32;
        F(mont_mul(&raw, &R2))
    }

    /// Canonical big-endian bytes; tests compare through here.
    #[cfg(test)]
    fn to_be_bytes(self) -> [u8; 32] {
        self.to_raw().to_be_bytes()
    }

    /// Strip the Montgomery factor: mont_mul(x*R, 1) = x.
    fn to_raw(self) -> Raw {
        Raw(mont_mul(&self.0, &Raw::ONE.0))
    }

    /// mont_mul(x*R, y) = x*y: multiply by a raw factor and land raw,
    /// merging the final reduction into the last multiplication of a chain.
    fn mul_raw(self, rhs: Raw) -> Raw {
        Raw(mont_mul(&self.0, &rhs.0))
    }

    fn is_zero(self) -> bool {
        self.0 == [0; N_DIGITS]
    }

    fn add(self, rhs: F) -> F {
        // a + b < 2r < 2^256: one conditional subtraction canonicalizes.
        let (sum, _) = digits_add(&self.0, &rhs.0);
        if digits_lt(&sum, &MODULUS) {
            F(sum)
        } else {
            F(digits_sub(&sum, &MODULUS).0)
        }
    }

    fn sub(self, rhs: F) -> F {
        let (diff, borrow) = digits_sub(&self.0, &rhs.0);
        if borrow == 0 {
            F(diff)
        } else {
            F(digits_add(&diff, &MODULUS).0)
        }
    }

    fn mul(self, rhs: F) -> F {
        F(mont_mul(&self.0, &rhs.0))
    }

    fn square(self) -> F {
        self.mul(self)
    }
}

impl Raw {
    /// The integer 0.
    const ZERO: Raw = Raw([0; N_DIGITS]);

    /// The integer 1 (as a mont_mul operand it strips one factor of R).
    const ONE: Raw = {
        let mut one = [0u32; N_DIGITS];
        one[0] = 1;
        Raw(one)
    };

    /// Big-endian bytes to raw form, rejecting values >= r. The strict
    /// bound closes the Frozen Heart class of forgeries via non-canonical
    /// encodings.
    fn from_be_bytes(bytes: &[u8; 32]) -> Option<Raw> {
        let raw = digits_from_be_bytes(bytes);
        if !digits_lt(&raw, &MODULUS) {
            return None;
        }
        Some(Raw(raw))
    }

    /// Big-endian bytes - a pure byte reshuffle, no reduction.
    fn to_be_bytes(self) -> [u8; 32] {
        digits_to_be_bytes(&self.0)
    }

    /// Modular addition; raw residues add like any residue.
    fn add(self, rhs: Raw) -> Raw {
        let (sum, _) = digits_add(&self.0, &rhs.0);
        if digits_lt(&sum, &MODULUS) {
            Raw(sum)
        } else {
            Raw(digits_sub(&sum, &MODULUS).0)
        }
    }

    /// Modular negation: r - x, zero fixed. Feeding a negated scalar to a
    /// G1 multiplication yields the negated point, which is why the
    /// verifier contains no point subtraction at all.
    fn neg(self) -> Raw {
        if self.0 == [0; N_DIGITS] {
            self
        } else {
            Raw(digits_sub(&MODULUS, &self.0).0)
        }
    }

    /// Modular subtraction.
    fn sub(self, rhs: Raw) -> Raw {
        let (diff, borrow) = digits_sub(&self.0, &rhs.0);
        if borrow == 0 {
            Raw(diff)
        } else {
            Raw(digits_add(&diff, &MODULUS).0)
        }
    }
}

/// Montgomery multiplication, CIOS (coarsely integrated operand scanning),
/// eight base-2^32 digits. The digit width is the point: every partial
/// product a[i]*b[j] fits one native 64-bit multiply on SBF, where wider
/// digits would lower to compiler-emulated 128-bit products. Inputs < r
/// (or < 2^256 for the first operand when the second is < r), output < r.
#[inline(always)]
fn mont_mul(a: &[u32; N_DIGITS], b: &[u32; N_DIGITS]) -> [u32; N_DIGITS] {
    // t holds N+2 digits: since r < 2^255, the pre-subtraction value stays
    // below 2r and the top digit never exceeds 1.
    let mut t = [0u32; N_DIGITS + 2];
    for i in 0..N_DIGITS {
        // 1. t += a[i] * b
        let ai = a[i] as u64;
        let mut carry = 0u64;
        for j in 0..N_DIGITS {
            let s = t[j] as u64 + ai * b[j] as u64 + carry;
            t[j] = s as u32;
            carry = s >> 32;
        }
        let s = t[N_DIGITS] as u64 + carry;
        t[N_DIGITS] = s as u32;
        t[N_DIGITS + 1] = (s >> 32) as u32;

        // 2. m = t[0] * (-r^-1) mod 2^32; t += m*r; t >>= 32. The shift is
        // fused into the store index.
        let m = t[0].wrapping_mul(INV) as u64;
        let s = t[0] as u64 + m * MODULUS[0] as u64;
        let mut carry = s >> 32;
        for j in 1..N_DIGITS {
            let s = t[j] as u64 + m * MODULUS[j] as u64 + carry;
            t[j - 1] = s as u32;
            carry = s >> 32;
        }
        let s = t[N_DIGITS] as u64 + carry;
        t[N_DIGITS - 1] = s as u32;
        t[N_DIGITS] = t[N_DIGITS + 1] + (s >> 32) as u32;
        t[N_DIGITS + 1] = 0;
    }
    // 3. One conditional subtraction canonicalizes.
    let mut out = [0u32; N_DIGITS];
    out.copy_from_slice(&t[..N_DIGITS]);
    if t[N_DIGITS] != 0 || !digits_lt(&out, &MODULUS) {
        out = digits_sub(&out, &MODULUS).0;
    }
    out
}

/// a + b with carry out (0 or 1).
#[inline(always)]
fn digits_add(a: &[u32; N_DIGITS], b: &[u32; N_DIGITS]) -> ([u32; N_DIGITS], u32) {
    let mut out = [0u32; N_DIGITS];
    let mut carry = 0u64;
    for i in 0..N_DIGITS {
        let s = a[i] as u64 + b[i] as u64 + carry;
        out[i] = s as u32;
        carry = s >> 32;
    }
    (out, carry as u32)
}

/// a - b with borrow out (0 or 1).
#[inline(always)]
fn digits_sub(a: &[u32; N_DIGITS], b: &[u32; N_DIGITS]) -> ([u32; N_DIGITS], u32) {
    let mut out = [0u32; N_DIGITS];
    let mut borrow = 0u64;
    for i in 0..N_DIGITS {
        // Two's-complement subtract: the top bit of the 64-bit difference
        // is the borrow flag (set iff a[i] < b[i] + borrow).
        let s = (a[i] as u64).wrapping_sub(b[i] as u64).wrapping_sub(borrow);
        out[i] = s as u32;
        borrow = (s >> 63) & 1;
    }
    (out, borrow as u32)
}

/// a < b over little-endian digits.
#[inline(always)]
fn digits_lt(a: &[u32; N_DIGITS], b: &[u32; N_DIGITS]) -> bool {
    for i in (0..N_DIGITS).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// 32 big-endian bytes to little-endian digits, one 64-bit word (two
/// digits) at a time: load, byte-swap (a single instruction on SBF), split.
#[inline(always)]
fn digits_from_be_bytes(bytes: &[u8; 32]) -> [u32; N_DIGITS] {
    let mut out = [0u32; N_DIGITS];
    for j in 0..N_DIGITS / 2 {
        let o = 32 - 8 * (j + 1);
        let word: [u8; 8] = bytes[o..o + 8].try_into().unwrap();
        let w = u64::from_be_bytes(word);
        out[2 * j] = w as u32;
        out[2 * j + 1] = (w >> 32) as u32;
    }
    out
}

/// Little-endian digits to 32 big-endian bytes, one 64-bit word at a time:
/// pack two digits, byte-swap, store.
#[inline(always)]
fn digits_to_be_bytes(digits: &[u32; N_DIGITS]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for j in 0..N_DIGITS / 2 {
        let o = 32 - 8 * (j + 1);
        let w = ((digits[2 * j + 1] as u64) << 32) | digits[2 * j] as u64;
        out[o..o + 8].copy_from_slice(&w.to_be_bytes());
    }
    out
}

// --- alt_bn128 syscall wrappers ------------------------------------------

/// a + b via the alt_bn128 addition syscall (which also validates that
/// both inputs are curve points).
#[inline(always)]
fn g1_add(a: &G1, b: &G1) -> Result<G1, PlonkError> {
    let mut input = [0u8; 128];
    input[..64].copy_from_slice(a.as_bytes());
    input[64..].copy_from_slice(b.as_bytes());
    Ok(G1(g1_addition_be(&input)?))
}

/// p * s via the alt_bn128 multiplication syscall. The scalar arrives in
/// raw form, so serializing it is a byte reshuffle, not a reduction.
#[inline(always)]
fn g1_mul(p: &G1, s: Raw) -> Result<G1, PlonkError> {
    let mut input = [0u8; 96];
    input[..64].copy_from_slice(p.as_bytes());
    input[64..].copy_from_slice(&s.to_be_bytes());
    Ok(G1(g1_multiplication_be(&input)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// xorshift64* - a deterministic byte stream without a rand dependency.
    struct Rng(u64);
    impl Rng {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
        fn bytes32(&mut self) -> [u8; 32] {
            let mut out = [0u8; 32];
            for chunk in out.chunks_exact_mut(8) {
                chunk.copy_from_slice(&self.next_u64().to_be_bytes());
            }
            out
        }
    }

    /// Every field operation matches the plonk_solana::Fr reference on
    /// seeded random values:
    /// 1. from_hash reduction matches Fr::from_be_bytes_unchecked (both forms)
    /// 2. add/sub/mul/square/to_be_bytes agree
    /// 3. the raw path: to_raw round-trips, mul_raw equals the reduced product
    /// 3b. scalar negation matches the reference, zero fixed
    /// 4. from_fr digit reinterpretation round-trips
    /// 5. from_u64 agrees
    #[test]
    fn field_ops_match_reference() {
        let seed = 0x5eed_cafe_f00d_beef_u64;
        println!("seed: {seed}");
        let mut rng = Rng(seed);
        for _ in 0..2000 {
            let (xb, yb) = (rng.bytes32(), rng.bytes32());
            // 1. from_hash reduction matches Fr::from_be_bytes_unchecked in
            //    both forms (raw bytes == canonical bytes)
            let ((x, x_raw), (y, _)) = (F::from_hash(&xb), F::from_hash(&yb));
            let (xr, yr) = (
                Fr::from_be_bytes_unchecked(&xb),
                Fr::from_be_bytes_unchecked(&yb),
            );
            assert_eq!(x.to_be_bytes(), xr.to_be_bytes());
            assert_eq!(x_raw.to_be_bytes(), xr.to_be_bytes());
            // 2. add/sub/mul/square/to_be_bytes agree
            assert_eq!(x.add(y).to_be_bytes(), (xr + yr).to_be_bytes());
            assert_eq!(x.sub(y).to_be_bytes(), (xr - yr).to_be_bytes());
            assert_eq!(x.mul(y).to_be_bytes(), (xr * yr).to_be_bytes());
            assert_eq!(x.square().to_be_bytes(), xr.square().to_be_bytes());
            // 3. the raw path: to_raw round-trips and mul_raw(mont, raw)
            //    equals the reduced product
            assert_eq!(x.to_raw().to_be_bytes(), x.to_be_bytes());
            assert_eq!(x.mul_raw(y.to_raw()).to_be_bytes(), (xr * yr).to_be_bytes());
            // 3b. scalar negation: (r - x) == -x, zero fixed
            assert_eq!(x.to_raw().neg().to_be_bytes(), (-xr).to_be_bytes());
            assert_eq!(Raw::ZERO.neg(), Raw::ZERO);
            // 4. from_fr digit reinterpretation round-trips
            assert_eq!(F::from_fr(&xr), x);
            // 5. from_u64 agrees
            let v = rng.next_u64();
            assert_eq!(F::from_u64(v).to_be_bytes(), Fr::from(v).to_be_bytes());
        }
    }

    /// mont_mul is exact for an unreduced 256-bit first operand: feeding
    /// raw hash bytes straight in equals reduce-then-convert.
    #[test]
    fn mont_mul_accepts_unreduced_input() {
        let seed = 0x0dd5_eed5_0dd5_eed5_u64;
        println!("seed: {seed}");
        let mut rng = Rng(seed);
        for _ in 0..2000 {
            let hb = rng.bytes32();
            let via_loop = F::from_hash(&hb).0;
            let direct = F(mont_mul(&digits_from_be_bytes(&hb), &R2));
            assert_eq!(direct, via_loop);
        }
        // Worst case: 2^256 - 1.
        let max = [0xffu8; 32];
        assert_eq!(
            F(mont_mul(&digits_from_be_bytes(&max), &R2)),
            F::from_hash(&max).0
        );
    }

    /// Canonicality boundary on Raw, the form public inputs enter through:
    /// 1. 0 and r-1 accepted
    /// 2. r, r+1 and 2^256-1 rejected
    #[test]
    fn raw_canonical_boundary() {
        let r_be: [u8; 32] = digits_to_be_bytes(&MODULUS);
        // 1. 0 and r-1 accepted
        assert_eq!(Raw::from_be_bytes(&[0u8; 32]), Some(Raw::ZERO));
        let mut r_minus_1 = r_be;
        r_minus_1[31] -= 1; // r ends in 0x01, no borrow
        assert!(Raw::from_be_bytes(&r_minus_1).is_some());
        // 2. r, r+1 and 2^256-1 rejected
        assert_eq!(Raw::from_be_bytes(&r_be), None);
        let mut r_plus_1 = r_be;
        r_plus_1[31] += 1;
        assert_eq!(Raw::from_be_bytes(&r_plus_1), None);
        assert_eq!(Raw::from_be_bytes(&[0xff; 32]), None);
    }

    #[test]
    fn batch_scalar_is_canonical_and_nonzero() {
        assert_eq!(BatchScalar::from_be_bytes(&[0u8; 32]), None);

        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(BatchScalar::from_be_bytes(&one), Some(BatchScalar::ONE));

        // The outer derivation's inclusive upper endpoint, 2^128, is valid.
        let mut two_to_128 = [0u8; 32];
        two_to_128[15] = 1;
        assert!(BatchScalar::from_be_bytes(&two_to_128).is_some());

        let modulus = digits_to_be_bytes(&MODULUS);
        assert_eq!(BatchScalar::from_be_bytes(&modulus), None);
    }
}
