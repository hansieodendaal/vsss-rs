// Copyright Michael Lodder. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use ff::PrimeField;
use rand_core::{CryptoRng, RngCore, SeedableRng};

use crate::{curve25519::pseudo_random_scalar, lib::*};

/// The polynomial used for generating the shares
pub struct Polynomial<F: PrimeField + Copy + Default> {
    pub(crate) coefficients: Vec<F>,
}

impl<F: PrimeField + Copy + Default> Polynomial<F> {
    /// Construct a random polynomial with `N` degree using the specified intercept
    pub fn new(intercept: F, mut rng: impl RngCore + CryptoRng, length: usize) -> Self {
        let mut coefficients = Vec::with_capacity(length);

        // Ensure intercept is set
        coefficients.push(intercept);

        // Assign random coefficients to polynomial
        // Start at 1 since 0 is the intercept and not chosen at random
        for _ in 1..length {
            coefficients.push(F::random(&mut rng));
        }
        Self { coefficients }
    }

    /// Construct a deterministic polynomial with `N` degree using the specified intercept
    pub fn new_deterministic<R>(intercept: F, rng: &mut R, length: usize) -> Self
    where
        R: CryptoRng + RngCore + SeedableRng,
        <R as SeedableRng>::Seed: Clone,
        <F as PrimeField>::Repr: TryFrom<Vec<u8>>,
    {
        let mut coefficients = Vec::with_capacity(length);

        // Ensure intercept is set
        coefficients.push(intercept);

        // Assign random coefficients to polynomial
        // Start at 1 since 0 is the intercept and not chosen at random
        for _ in 1..length {
            let scalar_bytes = pseudo_random_scalar(rng).to_bytes().to_vec();
            if let Ok(repr) = F::Repr::try_from(scalar_bytes) {
                if F::from_repr(repr).is_some().into() {
                    coefficients.push(F::from_repr(repr).unwrap());
                }
            }
        }
        Self { coefficients }
    }

    /// Compute the value of the polynomial for the given `x`
    pub fn evaluate(&self, x: F, threshold: usize) -> F {
        // Compute the polynomial value using Horner's Method
        let degree = threshold - 1;
        // b_n = a_n
        let mut out = self.coefficients[degree];

        for i in (0..degree).rev() {
            // b_{n-1} = a_{n-1} + b_n*x
            out *= x;
            out += self.coefficients[i];
        }
        out
    }
}
