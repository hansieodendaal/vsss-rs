// Copyright Michael Lodder. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use core::{
    array::TryFromSliceError,
    convert::TryFrom,
    fmt::{self, Formatter},
};

use serde::{
    de::{self, SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};
use zeroize::Zeroize;
/// A Shamir simple secret share
/// provides no integrity checking
/// The first byte is the X-coordinate or identifier
/// The remaining bytes are the Y-coordinate
#[derive(Copy, Clone, Debug, PartialEq, Eq, Zeroize)]
pub struct Share<const N: usize>(pub [u8; N]);

impl<const N: usize> Default for Share<N> {
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> AsRef<[u8]> for Share<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> TryFrom<&[u8]> for Share<N> {
    type Error = TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(<[u8; N]>::try_from(bytes)?))
    }
}

impl<const N: usize> From<Share<N>> for [u8; N] {
    fn from(share: Share<N>) -> Self {
        share.0
    }
}

impl<const N: usize> Serialize for Share<N> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = s.serialize_tuple(N)?;
        for b in &self.0 {
            seq.serialize_element(b)?;
        }
        seq.end()
    }
}

impl<'de, const N: usize> Deserialize<'de> for Share<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ShareVisitor<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for ShareVisitor<N> {
            type Value = Share<N>;

            fn expecting(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "a byte sequence")
            }

            fn visit_seq<A>(self, mut s: A) -> Result<Share<N>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = [0u8; N];
                for (i, p) in arr.iter_mut().enumerate() {
                    *p = s.next_element()?.ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(Share(arr))
            }
        }

        deserializer.deserialize_tuple(N, ShareVisitor)
    }
}

impl<const N: usize> Share<N> {
    /// True if all value bytes are zero in constant time
    pub fn is_zero(&self) -> bool {
        let mut v = 0u8;
        for b in &self.0[1..] {
            v |= b;
        }
        v == 0
    }

    /// The identifier for this share
    pub fn identifier(&self) -> u8 {
        self.0[0]
    }

    /// The raw byte value of the share
    pub fn value(&self) -> &[u8] {
        &self.0[1..]
    }
}
