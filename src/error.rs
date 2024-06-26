// Copyright Michael Lodder. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Errors during secret sharing
#[derive(Error, Copy, Clone, Debug)]
pub enum Error {
    /// Error when threshold is less than 2
    #[error("Error when threshold is less than 2")]
    SharingMinThreshold,
    /// Error when limit is less than threshold
    #[error("Error when limit is less than threshold")]
    SharingLimitLessThanThreshold,
    /// Invalid share identifier
    #[error("Invalid share identifier")]
    SharingInvalidIdentifier,
    /// Duplicate identifier when combining
    #[error("Duplicate identifier when combining")]
    SharingDuplicateIdentifier,
    /// The maximum number of shares to be made when splitting
    #[error("The maximum number of shares to be made when splitting")]
    SharingMaxRequest,
    /// An invalid share was supplied for verification or combine
    #[error("An invalid share was supplied for verification or combine")]
    InvalidShare,
    /// An invalid secret was supplied for split
    #[error("An invalid secret was supplied for split")]
    InvalidSecret,
}
