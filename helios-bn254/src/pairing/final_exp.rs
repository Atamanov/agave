//! Final exponentiation for BN254.
//! Easy part + Fuentes-Castaneda hard part (arkworks / eprint 2011/506).

use crate::fp12::Fp12;

/// `f^{(p^12 - 1)/r}`: easy part, then the Fuentes-Castaneda hard part.
///
/// The `unwrap` is unreachable: the zero guard returns early, and Fp12 is a
/// field (`invert` is `None` only for zero, since each tower level's norm
/// vanishes only at zero), so every nonzero input is invertible. Miller-loop
/// outputs over validated pairs are nonzero anyway; the guard makes the
/// claim hold for arbitrary callers.
pub fn final_exponentiation(f: &Fp12) -> Fp12 {
    if f.is_zero() {
        return Fp12::ZERO;
    }

    // Easy: f^{(p^6-1)(p^2+1)}
    let mut f1 = f.conjugate(); // f^{p^6}
    let Some(f2) = f.invert() else {
        return Fp12::ZERO;
    };
    let mut r = f1 * f2; // f^{p^6-1}
    f1 = r;
    r = r.frobenius_map_squared(); // f^{(p^6-1)p^2}
    r *= f1; // f^{(p^6-1)(p^2+1)}

    // Hard part (Fuentes-Castaneda et al.)
    // X is positive for BN_SNARK1 => exp_by_neg_x = conjugate(f^x)
    let y0 = exp_by_neg_x(r);
    let y1 = y0.cyclotomic_square();
    let y2 = y1.cyclotomic_square();
    let mut y3 = y2 * y1;
    let y4 = exp_by_neg_x(y3);
    let y5 = y4.cyclotomic_square();
    let mut y6 = exp_by_neg_x(y5);
    y3 = y3.conjugate();
    y6 = y6.conjugate();
    let y7 = y6 * y4;
    let mut y8 = y7 * y3;
    let y9 = y8 * y1;
    let y10 = y8 * y4;
    let y11 = y10 * r;
    let mut y12 = y9;
    y12 = y12.frobenius_map();
    let y13 = y12 * y11;
    y8 = y8.frobenius_map_squared();
    let y14 = y8 * y13;
    let mut y15 = r.conjugate() * y9;
    y15 = y15.frobenius_map_cubed();
    y15 * y14
}

fn exp_by_neg_x(f: Fp12) -> Fp12 {
    // X_IS_NEGATIVE = false for BN_SNARK1, so this is unitary inverse of f^x
    f.pow_x().conjugate()
}

#[cfg(test)]
mod tests {
    use crate::batch::{G1Bytes, G2Bytes, PairBytes, pairing_product_is_one};
    use crate::{Fr, G1Affine, G2Affine};
    use core::ops::{Mul, Neg};

    /// Full validated path (bytes in, verdict out) over pair sets whose GT
    /// products cancel to one, with infinity pairs mixed in: the shapes most
    /// likely to degenerate an intermediate. Every non-short-circuited call
    /// runs the final-exponentiation inversion; correct verdicts prove its
    /// zero guard never fires on validated inputs.
    #[test]
    fn facade_pairing_handles_cancelling_and_identity_mixes() {
        let pair = |g1: &G1Affine, g2: &G2Affine| PairBytes {
            g1: G1Bytes::from_affine(g1),
            g2: G2Bytes::from_affine(g2),
        };
        let p = G1Affine::generator();
        let q = G2Affine::arkworks_generator();
        let minus_p = p.neg();
        let a = Fr::from_u64(0xdead_beef_cafe_f00d);
        let ap = p.to_curve().mul(a).to_affine();
        let aq = q.to_curve().mul(a).to_affine();
        let infinity = PairBytes {
            g1: G1Bytes([0; 64]),
            g2: G2Bytes([0; 128]),
        };

        // e(P, Q) * e(-P, Q) = 1; infinity pairs are validated but neutral.
        assert_eq!(
            pairing_product_is_one(&[pair(&p, &q), pair(&minus_p, &q)]),
            Ok(true)
        );
        assert_eq!(
            pairing_product_is_one(&[infinity, pair(&p, &q), infinity, pair(&minus_p, &q)]),
            Ok(true)
        );
        // Bilinearity shuffle: e([a]P, Q) * e(-P, [a]Q) = 1.
        assert_eq!(
            pairing_product_is_one(&[pair(&ap, &q), pair(&minus_p, &aq)]),
            Ok(true)
        );
        // Non-cancelling product: verdict false, no panic on the way there.
        assert_eq!(pairing_product_is_one(&[pair(&p, &q)]), Ok(false));
        // All-infinity batch short-circuits before any Miller loop.
        assert_eq!(pairing_product_is_one(&[infinity]), Ok(true));
        // Eight-plus live pairs take the 8-wide Miller path on IFMA builds;
        // the cancelling product must survive there too.
        let wide: alloc::vec::Vec<PairBytes> = core::iter::once(infinity)
            .chain((0..4).flat_map(|_| [pair(&p, &q), pair(&minus_p, &q)]))
            .collect();
        assert_eq!(pairing_product_is_one(&wide), Ok(true));
    }
}
