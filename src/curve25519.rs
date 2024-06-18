// Copyright Michael Lodder. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Curve25519 is not a prime order curve
//! Since this crate relies on the ff::PrimeField
//! and Curve25519 does work with secret sharing schemes
//! This code wraps the Ristretto points and scalars in a facade
//! to be compliant to work with this library.
//! The intent is the consumer will not have to use these directly since
//! the wrappers implement the [`From`] and [`Into`] traits.
use core::{
    borrow::Borrow,
    fmt,
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT, RISTRETTO_BASEPOINT_POINT},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity, MultiscalarMul},
};
use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};
use rand_core::{CryptoRng, OsRng, RngCore, SeedableRng};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

/// Wraps a ristretto25519 point
#[derive(Copy, Clone, Debug, Eq)]
pub struct WrappedRistretto(pub RistrettoPoint);

impl Group for WrappedRistretto {
    type Scalar = WrappedScalar;

    fn random(mut _rng: impl RngCore) -> Self {
        Self(RistrettoPoint::random(&mut OsRng))
    }

    fn identity() -> Self {
        Self(RistrettoPoint::identity())
    }

    fn generator() -> Self {
        Self(RISTRETTO_BASEPOINT_POINT)
    }

    fn is_identity(&self) -> Choice {
        Choice::from(u8::from(self.0.is_identity()))
    }

    fn double(&self) -> Self {
        Self(self.0 + self.0)
    }
}

impl<T> Sum<T> for WrappedRistretto
where
    T: Borrow<WrappedRistretto>,
{
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.fold(Self::identity(), |acc, item| acc + item.borrow())
    }
}

impl<'a> Neg for &'a WrappedRistretto {
    type Output = WrappedRistretto;

    #[inline]
    fn neg(self) -> Self::Output {
        WrappedRistretto(self.0.neg())
    }
}

impl Neg for WrappedRistretto {
    type Output = WrappedRistretto;

    #[inline]
    fn neg(self) -> Self::Output {
        -&self
    }
}

impl PartialEq for WrappedRistretto {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<'a, 'b> Add<&'b WrappedRistretto> for &'a WrappedRistretto {
    type Output = WrappedRistretto;

    #[inline]
    fn add(self, rhs: &'b WrappedRistretto) -> Self::Output {
        *self + *rhs
    }
}

impl<'b> Add<&'b WrappedRistretto> for WrappedRistretto {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &'b WrappedRistretto) -> Self::Output {
        self + *rhs
    }
}

impl<'a> Add<WrappedRistretto> for &'a WrappedRistretto {
    type Output = WrappedRistretto;

    #[inline]
    fn add(self, rhs: WrappedRistretto) -> Self::Output {
        *self + rhs
    }
}

impl Add for WrappedRistretto {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        WrappedRistretto(self.0 + rhs.0)
    }
}

impl AddAssign for WrappedRistretto {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<'b> AddAssign<&'b WrappedRistretto> for WrappedRistretto {
    #[inline]
    fn add_assign(&mut self, rhs: &'b WrappedRistretto) {
        *self = *self + *rhs;
    }
}

impl<'a, 'b> Sub<&'b WrappedRistretto> for &'a WrappedRistretto {
    type Output = WrappedRistretto;

    #[inline]
    fn sub(self, rhs: &'b WrappedRistretto) -> Self::Output {
        *self - *rhs
    }
}

impl<'b> Sub<&'b WrappedRistretto> for WrappedRistretto {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &'b WrappedRistretto) -> Self::Output {
        self - *rhs
    }
}

impl<'a> Sub<WrappedRistretto> for &'a WrappedRistretto {
    type Output = WrappedRistretto;

    #[inline]
    fn sub(self, rhs: WrappedRistretto) -> Self::Output {
        *self - rhs
    }
}

impl Sub for WrappedRistretto {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        WrappedRistretto(self.0 - rhs.0)
    }
}

impl SubAssign for WrappedRistretto {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<'b> SubAssign<&'b WrappedRistretto> for WrappedRistretto {
    #[inline]
    fn sub_assign(&mut self, rhs: &'b WrappedRistretto) {
        *self = *self - *rhs;
    }
}

impl<'a, 'b> Mul<&'b WrappedScalar> for &'a WrappedRistretto {
    type Output = WrappedRistretto;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        *self * *rhs
    }
}

impl<'b> Mul<&'b WrappedScalar> for WrappedRistretto {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        self * *rhs
    }
}

impl<'a> Mul<WrappedScalar> for &'a WrappedRistretto {
    type Output = WrappedRistretto;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        *self * rhs
    }
}

impl Mul<WrappedScalar> for WrappedRistretto {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        WrappedRistretto(self.0 * rhs.0)
    }
}

impl MulAssign<WrappedScalar> for WrappedRistretto {
    #[inline]
    fn mul_assign(&mut self, rhs: WrappedScalar) {
        *self = *self * rhs;
    }
}

impl<'b> MulAssign<&'b WrappedScalar> for WrappedRistretto {
    #[inline]
    fn mul_assign(&mut self, rhs: &'b WrappedScalar) {
        *self = *self * *rhs;
    }
}

impl GroupEncoding for WrappedRistretto {
    type Repr = [u8; 32];

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        let p = CompressedRistretto(*bytes);
        match p.decompress() {
            None => CtOption::new(Self(RistrettoPoint::identity()), Choice::from(0u8)),
            Some(rp) => CtOption::new(Self(rp), Choice::from(1u8)),
        }
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        self.0.compress().0
    }
}

impl Default for WrappedRistretto {
    fn default() -> Self {
        Self(RistrettoPoint::identity())
    }
}

impl From<WrappedRistretto> for RistrettoPoint {
    fn from(p: WrappedRistretto) -> RistrettoPoint {
        p.0
    }
}

impl From<RistrettoPoint> for WrappedRistretto {
    fn from(p: RistrettoPoint) -> Self {
        Self(p)
    }
}

impl Serialize for WrappedRistretto {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // convert to compressed ristretto format, then serialize
        serializer.serialize_bytes(self.0.compress().as_bytes())
    }
}

struct WrappedRistrettoVisitor;

impl<'de> Visitor<'de> for WrappedRistrettoVisitor {
    type Value = WrappedRistretto;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "an array of bytes")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        // deserialize compressed ristretto, then decompress
        if let Some(ep) = CompressedRistretto::from_slice(v)
            .map_err(|e| E::custom(e))?
            .decompress()
        {
            return Ok(WrappedRistretto(ep));
        }
        Err(de::Error::custom("failed to deserialize CompressedRistretto"))
    }
}

impl<'de> Deserialize<'de> for WrappedRistretto {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(WrappedRistrettoVisitor)
    }
}

/// Wraps an ed25519 point
#[derive(Copy, Clone, Debug, Eq)]
pub struct WrappedEdwards(pub EdwardsPoint);

impl Group for WrappedEdwards {
    type Scalar = WrappedScalar;

    fn random(mut rng: impl RngCore) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let scalar1 = Scalar::from_bytes_mod_order(seed);
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let scalar2 = Scalar::from_bytes_mod_order(seed);
        let scalars = [scalar1, scalar2];
        let points = [EdwardsPoint::identity(), EdwardsPoint::identity()];
        let edwards_point = EdwardsPoint::multiscalar_mul(&scalars, &points);
        Self(edwards_point)
    }

    fn identity() -> Self {
        Self(EdwardsPoint::identity())
    }

    fn generator() -> Self {
        Self(ED25519_BASEPOINT_POINT)
    }

    fn is_identity(&self) -> Choice {
        Choice::from(u8::from(self.0.is_identity()))
    }

    fn double(&self) -> Self {
        Self(self.0 + self.0)
    }
}

impl<T> Sum<T> for WrappedEdwards
where
    T: Borrow<WrappedEdwards>,
{
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.fold(Self::identity(), |acc, item| acc + item.borrow())
    }
}

impl<'a> Neg for &'a WrappedEdwards {
    type Output = WrappedEdwards;

    #[inline]
    fn neg(self) -> Self::Output {
        WrappedEdwards(self.0.neg())
    }
}

impl Neg for WrappedEdwards {
    type Output = WrappedEdwards;

    #[inline]
    fn neg(self) -> Self::Output {
        -&self
    }
}

impl PartialEq for WrappedEdwards {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<'a, 'b> Add<&'b WrappedEdwards> for &'a WrappedEdwards {
    type Output = WrappedEdwards;

    #[inline]
    fn add(self, rhs: &'b WrappedEdwards) -> Self::Output {
        *self + *rhs
    }
}

impl<'b> Add<&'b WrappedEdwards> for WrappedEdwards {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &'b WrappedEdwards) -> Self::Output {
        self + *rhs
    }
}

impl<'a> Add<WrappedEdwards> for &'a WrappedEdwards {
    type Output = WrappedEdwards;

    #[inline]
    fn add(self, rhs: WrappedEdwards) -> Self::Output {
        *self + rhs
    }
}

impl Add for WrappedEdwards {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        WrappedEdwards(self.0 + rhs.0)
    }
}

impl AddAssign for WrappedEdwards {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<'b> AddAssign<&'b WrappedEdwards> for WrappedEdwards {
    #[inline]
    fn add_assign(&mut self, rhs: &'b WrappedEdwards) {
        *self = *self + *rhs;
    }
}

impl<'a, 'b> Sub<&'b WrappedEdwards> for &'a WrappedEdwards {
    type Output = WrappedEdwards;

    #[inline]
    fn sub(self, rhs: &'b WrappedEdwards) -> Self::Output {
        *self - *rhs
    }
}

impl<'b> Sub<&'b WrappedEdwards> for WrappedEdwards {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &'b WrappedEdwards) -> Self::Output {
        self - *rhs
    }
}

impl<'a> Sub<WrappedEdwards> for &'a WrappedEdwards {
    type Output = WrappedEdwards;

    #[inline]
    fn sub(self, rhs: WrappedEdwards) -> Self::Output {
        *self - rhs
    }
}

impl Sub for WrappedEdwards {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        WrappedEdwards(self.0 - rhs.0)
    }
}

impl SubAssign for WrappedEdwards {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<'b> SubAssign<&'b WrappedEdwards> for WrappedEdwards {
    #[inline]
    fn sub_assign(&mut self, rhs: &'b WrappedEdwards) {
        *self = *self - *rhs;
    }
}

impl<'a, 'b> Mul<&'b WrappedScalar> for &'a WrappedEdwards {
    type Output = WrappedEdwards;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        *self * *rhs
    }
}

impl<'b> Mul<&'b WrappedScalar> for WrappedEdwards {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        self * *rhs
    }
}

impl<'a> Mul<WrappedScalar> for &'a WrappedEdwards {
    type Output = WrappedEdwards;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        *self * rhs
    }
}

impl Mul<WrappedScalar> for WrappedEdwards {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        WrappedEdwards(self.0 * rhs.0)
    }
}

impl MulAssign<WrappedScalar> for WrappedEdwards {
    #[inline]
    fn mul_assign(&mut self, rhs: WrappedScalar) {
        *self = *self * rhs;
    }
}

impl<'b> MulAssign<&'b WrappedScalar> for WrappedEdwards {
    #[inline]
    fn mul_assign(&mut self, rhs: &'b WrappedScalar) {
        *self = *self * *rhs;
    }
}

impl GroupEncoding for WrappedEdwards {
    type Repr = [u8; 32];

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        let p = CompressedEdwardsY(*bytes);
        match p.decompress() {
            None => CtOption::new(Self(EdwardsPoint::identity()), Choice::from(0u8)),
            Some(rp) => CtOption::new(Self(rp), Choice::from(1u8)),
        }
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        self.0.compress().0
    }
}

impl Default for WrappedEdwards {
    fn default() -> Self {
        Self(EdwardsPoint::identity())
    }
}

impl From<WrappedEdwards> for EdwardsPoint {
    fn from(p: WrappedEdwards) -> EdwardsPoint {
        p.0
    }
}

impl From<EdwardsPoint> for WrappedEdwards {
    fn from(p: EdwardsPoint) -> Self {
        Self(p)
    }
}

impl From<WrappedRistretto> for WrappedEdwards {
    fn from(p: WrappedRistretto) -> Self {
        struct Ed25519(EdwardsPoint);

        // can't just return the inner underlying point, since it may not be of order 8.
        // compute [8^{-1}][8]P to clear any cofactor
        // this is the byte representation of 8^{-1} mod q
        let eight_inv = Scalar::from_canonical_bytes([
            121, 47, 220, 226, 41, 229, 6, 97, 208, 218, 28, 125, 179, 157, 211, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 6,
        ])
        .unwrap();

        let r = unsafe { core::mem::transmute::<RistrettoPoint, Ed25519>(p.0) };

        WrappedEdwards(r.0.mul_by_cofactor() * eight_inv)
    }
}

impl Serialize for WrappedEdwards {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // convert to compressed edwards y format, then serialize
        serializer.serialize_bytes(self.0.compress().as_bytes())
    }
}

struct WrappedEdwardsVisitor;

impl<'de> Visitor<'de> for WrappedEdwardsVisitor {
    type Value = WrappedEdwards;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "an array of bytes")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        // deserialize compressed edwards y, then decompress
        if let Some(ep) = CompressedEdwardsY::from_slice(v)
            .map_err(|e| E::custom(e))?
            .decompress()
        {
            return Ok(WrappedEdwards(ep));
        }
        Err(de::Error::custom("failed to deserialize CompressedEdwardsY"))
    }
}

impl<'de> Deserialize<'de> for WrappedEdwards {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(WrappedEdwardsVisitor)
    }
}

/// Wraps a curve25519 scalar
#[derive(Copy, Clone, Debug, Eq, Default)]
pub struct WrappedScalar(pub Scalar);

impl PseudoRandom for WrappedScalar {
    fn pseudo_random<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + SeedableRng,
        <R as SeedableRng>::Seed: Clone,
    {
        Self(pseudo_random_scalar(rng))
    }
}

/// Produce a pseudo-random scalar from a seeded random number generator
pub fn pseudo_random_scalar<R>(rng: &mut R) -> Scalar
where
    R: CryptoRng + RngCore + SeedableRng,
    <R as SeedableRng>::Seed: Clone,
{
    let scalar_bytes_wide: [u8; 64] = pseudo_random_bytes(rng);
    Scalar::from_bytes_mod_order_wide(&scalar_bytes_wide)
}

// Produce pseudo-random mod order wide from a seeded random number generator
// Panics:
//   This function will panic if N > 128
fn pseudo_random_bytes<R, const N: usize>(rng: &mut R) -> [u8; N]
where
    R: CryptoRng + RngCore + SeedableRng,
    <R as SeedableRng>::Seed: Clone,
{
    let chunks = if N % 8 == 0 { N / 8 } else { N / 8 + 1 };
    let mut buffer = [0u8; 128];
    for i in 0..chunks {
        let mut random_bytes = [0u8; 8];
        let u64_bytes = rng.next_u64().to_le_bytes();
        u64_bytes
            .iter()
            .zip(random_bytes.iter_mut().take(u64_bytes.len()))
            .for_each(|(a, b)| *b = *a);
        random_bytes
            .iter()
            .zip(buffer.iter_mut().skip(i * 8).take(8))
            .for_each(|(a, b)| *b = *a);
    }
    let mut result_bytes = [0u8; N];
    result_bytes.copy_from_slice(&buffer[0..N]);
    result_bytes
}

/// Produce a pseudo-random value from a seeded random number generator
pub trait PseudoRandom {
    /// Produce a pseudo-random value from a seeded random number generator
    fn pseudo_random<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + SeedableRng,
        <R as SeedableRng>::Seed: Clone,
        Self: Sized;
}

impl Field for WrappedScalar {
    fn random(mut _rng: impl RngCore) -> Self {
        Self(Scalar::random(&mut OsRng))
    }

    fn zero() -> Self {
        Self(Scalar::ZERO)
    }

    fn one() -> Self {
        Self(Scalar::ONE)
    }

    fn is_zero(&self) -> Choice {
        Choice::from(u8::from(self.0 == Scalar::ZERO))
    }

    fn square(&self) -> Self {
        Self(self.0 * self.0)
    }

    fn double(&self) -> Self {
        Self(self.0 + self.0)
    }

    fn invert(&self) -> CtOption<Self> {
        CtOption::new(Self(self.0.invert()), Choice::from(1u8))
    }

    fn sqrt(&self) -> CtOption<Self> {
        // Not used for secret sharing
        unimplemented!()
    }
}

impl PrimeField for WrappedScalar {
    type Repr = [u8; 32];

    const CAPACITY: u32 = Self::NUM_BITS - 1;
    const NUM_BITS: u32 = 255;
    const S: u32 = 32;

    fn from_repr(bytes: Self::Repr) -> CtOption<Self> {
        CtOption::new(Self(Scalar::from_bytes_mod_order(bytes)), Choice::from(1u8))
    }

    fn to_repr(&self) -> Self::Repr {
        self.0.to_bytes()
    }

    fn is_odd(&self) -> Choice {
        Choice::from(self.0[0] & 1)
    }

    fn multiplicative_generator() -> Self {
        unimplemented!();
    }

    fn root_of_unity() -> Self {
        unimplemented!();
    }
}

impl From<u64> for WrappedScalar {
    fn from(d: u64) -> WrappedScalar {
        Self(Scalar::from(d))
    }
}

impl ConditionallySelectable for WrappedScalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(Scalar::conditional_select(&a.0, &b.0, choice))
    }
}

impl ConstantTimeEq for WrappedScalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for WrappedScalar {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<'a, 'b> Add<&'b WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn add(self, rhs: &'b WrappedScalar) -> Self::Output {
        *self + *rhs
    }
}

impl<'b> Add<&'b WrappedScalar> for WrappedScalar {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &'b WrappedScalar) -> Self::Output {
        self + *rhs
    }
}

impl<'a> Add<WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn add(self, rhs: WrappedScalar) -> Self::Output {
        *self + rhs
    }
}

impl Add for WrappedScalar {
    type Output = Self;

    #[inline]
    fn add(self, rhs: WrappedScalar) -> Self::Output {
        WrappedScalar(self.0 + rhs.0)
    }
}

impl AddAssign for WrappedScalar {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<'b> AddAssign<&'b WrappedScalar> for WrappedScalar {
    #[inline]
    fn add_assign(&mut self, rhs: &'b WrappedScalar) {
        *self = *self + rhs;
    }
}

impl<'a, 'b> Sub<&'b WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn sub(self, rhs: &'b WrappedScalar) -> Self::Output {
        *self - *rhs
    }
}

impl<'b> Sub<&'b WrappedScalar> for WrappedScalar {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &'b WrappedScalar) -> Self::Output {
        self - *rhs
    }
}

impl<'a> Sub<WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn sub(self, rhs: WrappedScalar) -> Self::Output {
        *self - rhs
    }
}

impl Sub for WrappedScalar {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: WrappedScalar) -> Self::Output {
        WrappedScalar(self.0 - rhs.0)
    }
}

impl SubAssign for WrappedScalar {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<'b> SubAssign<&'b WrappedScalar> for WrappedScalar {
    #[inline]
    fn sub_assign(&mut self, rhs: &'b WrappedScalar) {
        *self = *self - rhs;
    }
}

impl<'a, 'b> Mul<&'b WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        *self * *rhs
    }
}

impl<'b> Mul<&'b WrappedScalar> for WrappedScalar {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        self * *rhs
    }
}

impl<'a> Mul<WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        *self * rhs
    }
}

impl Mul for WrappedScalar {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        WrappedScalar(self.0 * rhs.0)
    }
}

impl MulAssign for WrappedScalar {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<'b> MulAssign<&'b WrappedScalar> for WrappedScalar {
    #[inline]
    fn mul_assign(&mut self, rhs: &'b WrappedScalar) {
        *self = *self * rhs;
    }
}

impl<'a> Neg for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn neg(self) -> Self::Output {
        WrappedScalar(self.0.neg())
    }
}

impl Neg for WrappedScalar {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        -&self
    }
}

impl From<WrappedScalar> for Scalar {
    fn from(s: WrappedScalar) -> Scalar {
        s.0
    }
}

impl From<Scalar> for WrappedScalar {
    fn from(s: Scalar) -> WrappedScalar {
        Self(s)
    }
}

impl zeroize::DefaultIsZeroes for WrappedScalar {}

impl Serialize for WrappedScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.0.as_bytes())
    }
}

struct WrappedScalarVisitor;

impl<'de> Visitor<'de> for WrappedScalarVisitor {
    type Value = WrappedScalar;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "an array of bytes")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let mut buf: [u8; 32] = Default::default();
        buf.copy_from_slice(v);
        Ok(WrappedScalar(Scalar::from_bytes_mod_order(buf)))
    }
}

impl<'de> Deserialize<'de> for WrappedScalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(WrappedScalarVisitor)
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
    use ff::Field;
    use group::Group;
    use rand::rngs::OsRng;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    use crate::curve25519::{
        pseudo_random_bytes, pseudo_random_scalar, WrappedEdwards, WrappedRistretto, WrappedScalar,
    };

    #[test]
    fn ristretto_to_edwards() {
        let sk = Scalar::random(&mut OsRng);
        let pk = RISTRETTO_BASEPOINT_POINT * sk;
        let ek = WrappedEdwards::from(WrappedRistretto(pk));
        assert!(ek.0.is_torsion_free());
    }

    #[test]
    fn serde_scalar() {
        let rng = OsRng;
        let ws1 = WrappedScalar::random(rng);
        // serialize
        let res = serde_bare::to_vec(&ws1);
        assert!(res.is_ok());
        let wsvec = res.unwrap();
        // deserialize
        let res = serde_bare::from_slice(&wsvec);
        assert!(res.is_ok());
        let ws2: WrappedScalar = res.unwrap();
        assert_eq!(ws1, ws2);
    }

    #[test]
    fn serde_edwards() {
        let rng = OsRng;
        let ed1 = WrappedEdwards::random(rng);
        // serialize
        let res = serde_bare::to_vec(&ed1);
        assert!(res.is_ok());
        let edvec = res.unwrap();
        // deserialize
        let res = serde_bare::from_slice(&edvec);
        assert!(res.is_ok());
        let ed2: WrappedEdwards = res.unwrap();
        assert_eq!(ed1, ed2);
    }

    #[test]
    fn test_pseudo_random_bytes() {
        let random_bytes_11: [u8; 5] = pseudo_random_bytes(&mut ChaCha12Rng::from_seed([0u8; 32]));
        let random_bytes_21: [u8; 5] = pseudo_random_bytes(&mut ChaCha12Rng::from_seed([1u8; 32]));
        let random_bytes_12: [u8; 32] = pseudo_random_bytes(&mut ChaCha12Rng::from_seed([0u8; 32]));
        let random_bytes_22: [u8; 32] = pseudo_random_bytes(&mut ChaCha12Rng::from_seed([1u8; 32]));
        let random_bytes_13: [u8; 103] = pseudo_random_bytes(&mut ChaCha12Rng::from_seed([0u8; 32]));
        let random_bytes_23: [u8; 103] = pseudo_random_bytes(&mut ChaCha12Rng::from_seed([1u8; 32]));
        let random_bytes_14: [u8; 128] = pseudo_random_bytes(&mut ChaCha12Rng::from_seed([0u8; 32]));
        let random_bytes_24: [u8; 128] = pseudo_random_bytes(&mut ChaCha12Rng::from_seed([1u8; 32]));

        assert_eq!(random_bytes_11, random_bytes_12[0..random_bytes_11.len()]);
        assert_eq!(random_bytes_12, random_bytes_13[0..random_bytes_12.len()]);
        assert_eq!(random_bytes_13, random_bytes_14[0..random_bytes_13.len()]);
        assert_eq!(
            random_bytes_14,
            [
                155, 244, 154, 106, 7, 85, 249, 83, 129, 31, 206, 18, 95, 38, 131, 213, 4, 41, 195, 187, 73, 224, 116,
                20, 126, 0, 137, 165, 46, 174, 21, 95, 5, 100, 248, 121, 210, 122, 227, 192, 44, 232, 40, 52, 172, 250,
                140, 121, 58, 98, 159, 44, 160, 222, 105, 25, 97, 11, 232, 47, 65, 19, 38, 190, 11, 213, 136, 65, 32,
                62, 116, 254, 134, 252, 113, 51, 140, 224, 23, 61, 198, 40, 235, 183, 25, 189, 203, 204, 21, 21, 133,
                33, 76, 192, 137, 180, 66, 37, 141, 205, 161, 76, 241, 17, 198, 2, 184, 151, 27, 140, 200, 67, 233, 30,
                70, 202, 144, 81, 81, 192, 39, 68, 166, 176, 23, 230, 147, 22
            ]
        );

        assert_eq!(random_bytes_21, random_bytes_22[0..random_bytes_21.len()]);
        assert_eq!(random_bytes_22, random_bytes_23[0..random_bytes_22.len()]);
        assert_eq!(random_bytes_23, random_bytes_24[0..random_bytes_23.len()]);
        assert_eq!(
            random_bytes_24,
            [
                51, 1, 232, 215, 231, 84, 219, 44, 245, 123, 10, 76, 167, 63, 37, 60, 112, 83, 173, 43, 197, 57, 135,
                119, 186, 3, 155, 37, 142, 89, 173, 157, 255, 14, 44, 118, 82, 24, 125, 173, 249, 90, 55, 182, 196, 67,
                39, 192, 210, 186, 181, 186, 56, 32, 240, 248, 152, 79, 191, 112, 111, 164, 53, 73, 59, 113, 62, 159,
                42, 255, 27, 88, 115, 20, 186, 50, 214, 91, 144, 253, 251, 88, 164, 180, 120, 59, 24, 192, 153, 239,
                42, 149, 57, 124, 67, 117, 97, 133, 43, 20, 102, 35, 82, 158, 14, 91, 92, 80, 100, 54, 114, 215, 201,
                162, 204, 249, 35, 197, 209, 240, 35, 42, 93, 155, 35, 226, 58, 251
            ]
        );

        let res = std::panic::catch_unwind(|| {
            let _ = pseudo_random_bytes::<ChaCha12Rng, 129>(&mut ChaCha12Rng::from_seed([0u8; 32]));
        });
        assert!(res.is_err());
    }

    #[test]
    fn test_pseudo_random_scalar() {
        let scalar_1a = pseudo_random_scalar(&mut ChaCha12Rng::from_seed([0u8; 32]));
        let scalar_1b = pseudo_random_scalar(&mut ChaCha12Rng::from_seed([0u8; 32]));
        let scalar_2a = pseudo_random_scalar(&mut ChaCha12Rng::from_seed([1u8; 32]));
        let scalar_2b = pseudo_random_scalar(&mut ChaCha12Rng::from_seed([1u8; 32]));
        assert_eq!(scalar_1a, scalar_1b);
        assert_eq!(scalar_2a, scalar_2b);
        assert_eq!(
            scalar_1a.to_bytes(),
            [
                22, 33, 188, 127, 243, 114, 222, 165, 177, 158, 212, 131, 122, 34, 112, 164, 230, 48, 112, 90, 14, 78,
                91, 42, 120, 206, 28, 215, 160, 190, 21, 0
            ]
        );
        assert_eq!(
            scalar_2a.to_bytes(),
            [
                55, 177, 57, 140, 215, 142, 37, 226, 81, 250, 70, 1, 156, 117, 25, 230, 177, 133, 156, 151, 166, 206,
                226, 135, 162, 141, 96, 226, 108, 78, 121, 6
            ]
        );
    }
}
