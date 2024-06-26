// Copyright Michael Lodder. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SecretKey;
use rand_chacha::ChaCha12Rng;
use rand_core::OsRng;
use x25519_dalek::StaticSecret;

use super::{invalid::*, valid::*};
use crate::{
    curve25519::{WrappedEdwards, WrappedRistretto, WrappedScalar},
    Feldman, FeldmanVerifier, Pedersen, PedersenResult, PedersenVerifier, Shamir,
};

#[test]
fn invalid_tests() {
    split_invalid_args::<WrappedScalar, WrappedRistretto>();
    combine_invalid::<WrappedScalar>();
    split_invalid_args::<WrappedScalar, WrappedEdwards>();
    combine_invalid::<WrappedScalar>();
}

#[test]
fn valid_tests() {
    combine_single::<WrappedScalar, WrappedRistretto>();
    combine_all::<WrappedScalar, WrappedRistretto>();
    combine_single::<WrappedScalar, WrappedEdwards>();
    combine_all::<WrappedScalar, WrappedEdwards>();
}

#[test]
fn key_tests() {
    let sc = Scalar::random(&mut OsRng);
    let sk1 = StaticSecret::from(sc.to_bytes());
    let ske1 = SecretKey::from_bytes(&sc.to_bytes()).unwrap();
    let res = Shamir { t: 2, n: 3 }.split_secret::<WrappedScalar, OsRng>(sc.into(), &mut OsRng);
    assert!(res.is_ok());
    let shares = res.unwrap();
    let res = Shamir { t: 2, n: 3 }.combine_shares::<WrappedScalar>(&shares);
    assert!(res.is_ok());
    let scalar = res.unwrap();
    assert_eq!(scalar.0, sc);
    let sk2 = StaticSecret::from(scalar.0.to_bytes());
    let ske2 = SecretKey::from_bytes(&scalar.0.to_bytes()).unwrap();
    assert_eq!(sk2.to_bytes(), sk1.to_bytes());
    assert_eq!(ske1.to_bytes(), ske2.to_bytes());
}

#[test]
fn feldman_verifier_serde_test() {
    let sk = Scalar::random(&mut OsRng);
    let res =
        Feldman { t: 2, n: 3 }.split_secret::<WrappedScalar, WrappedRistretto, OsRng>(sk.into(), None, &mut OsRng);
    assert!(res.is_ok());
    let (shares, verifier) = res.unwrap();
    for s in &shares {
        assert!(verifier.verify(s));
    }
    let res = serde_cbor::to_vec(&verifier);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_cbor::from_slice::<FeldmanVerifier<WrappedScalar, WrappedRistretto>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    let res = serde_json::to_string(&verifier);
    assert!(res.is_ok());
    let v_str = res.unwrap();
    let res = serde_json::from_str::<FeldmanVerifier<WrappedScalar, WrappedRistretto>>(&v_str);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    let res = serde_bare::to_vec(&verifier);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_bare::from_slice::<FeldmanVerifier<WrappedScalar, WrappedRistretto>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);
}

#[test]
fn pedersen_verifier_serde_test() {
    let sk = Scalar::random(&mut OsRng);
    let res = Pedersen { t: 2, n: 3 }.split_secret::<WrappedScalar, WrappedEdwards, OsRng>(
        sk.into(),
        None,
        None,
        None,
        &mut OsRng,
    );
    assert!(res.is_ok());
    let ped_res = res.unwrap();
    let PedersenResult {
        blinding: _,
        blind_shares,
        secret_shares,
        verifier,
    } = ped_res;
    for (s, b) in secret_shares.iter().zip(blind_shares.iter()) {
        assert!(verifier.verify(s, b));
    }
    let res = serde_cbor::to_vec(&verifier);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_cbor::from_slice::<PedersenVerifier<WrappedScalar, WrappedEdwards>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    let res = serde_json::to_string(&verifier);
    assert!(res.is_ok());
    let v_str = res.unwrap();
    let res = serde_json::from_str::<PedersenVerifier<WrappedScalar, WrappedEdwards>>(&v_str);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    let res = serde_bare::to_vec(&verifier);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_bare::from_slice::<PedersenVerifier<WrappedScalar, WrappedEdwards>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    // Test non-deterministic split
    let res_2 = Pedersen { t: 2, n: 3 }.split_secret::<WrappedScalar, WrappedEdwards, OsRng>(
        sk.into(),
        None,
        None,
        None,
        &mut OsRng,
    );
    assert!(res_2.is_ok());
    let ped_res_2 = res_2.unwrap();
    let PedersenResult {
        blinding: _,
        blind_shares: blind_shares_2,
        secret_shares: secret_shares_2,
        verifier: verifier_2,
    } = ped_res_2;
    assert_ne!(blind_shares, blind_shares_2);
    assert_ne!(secret_shares, secret_shares_2);
    assert_ne!(verifier, verifier_2);
}

#[test]
#[allow(clippy::too_many_lines)]
fn pedersen_verifier_serde_deterministic_test() {
    let sk = Scalar::random(&mut OsRng);
    let mut seed = [0u8; 32];
    let res = Pedersen { t: 2, n: 3 }.split_secret_deterministic::<WrappedScalar, WrappedEdwards, ChaCha12Rng>(
        sk.into(),
        None,
        None,
        None,
        seed,
    );
    assert!(res.is_ok());
    let ped_res = res.unwrap();
    let PedersenResult {
        blinding: _,
        blind_shares,
        secret_shares,
        verifier,
    } = ped_res;
    for (s, b) in secret_shares.iter().zip(blind_shares.iter()) {
        assert!(verifier.verify(s, b));
    }
    let res = serde_cbor::to_vec(&verifier);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_cbor::from_slice::<PedersenVerifier<WrappedScalar, WrappedEdwards>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    let res = serde_json::to_string(&verifier);
    assert!(res.is_ok());
    let v_str = res.unwrap();
    let res = serde_json::from_str::<PedersenVerifier<WrappedScalar, WrappedEdwards>>(&v_str);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    let res = serde_bare::to_vec(&verifier);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_bare::from_slice::<PedersenVerifier<WrappedScalar, WrappedEdwards>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier.generator, verifier2.generator);

    // Test deterministic split with same seed
    let res_2 = Pedersen { t: 2, n: 3 }.split_secret_deterministic::<WrappedScalar, WrappedEdwards, ChaCha12Rng>(
        sk.into(),
        None,
        None,
        None,
        seed,
    );
    assert!(res_2.is_ok());
    let ped_res_2 = res_2.unwrap();
    let PedersenResult {
        blinding: _,
        blind_shares: blind_shares_2,
        secret_shares: secret_shares_2,
        verifier: verifier_2,
    } = ped_res_2;
    assert_eq!(blind_shares, blind_shares_2);
    assert_eq!(secret_shares, secret_shares_2);
    assert_eq!(verifier, verifier_2);

    // Test deterministic split with different seed
    seed[0] = 1;
    let res_3 = Pedersen { t: 2, n: 3 }.split_secret_deterministic::<WrappedScalar, WrappedEdwards, ChaCha12Rng>(
        sk.into(),
        None,
        None,
        None,
        seed,
    );
    assert!(res_3.is_ok());
    let ped_res_3 = res_3.unwrap();
    let PedersenResult {
        blinding: _,
        blind_shares: blind_shares_3,
        secret_shares: secret_shares_3,
        verifier: verifier_3,
    } = ped_res_3;
    assert_ne!(blind_shares, blind_shares_3);
    assert_ne!(secret_shares, secret_shares_3);
    assert_ne!(verifier, verifier_3);

    for (s, b) in secret_shares_3.iter().zip(blind_shares_3.iter()) {
        assert!(verifier_3.verify(s, b));
    }
    let res = serde_cbor::to_vec(&verifier_3);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_cbor::from_slice::<PedersenVerifier<WrappedScalar, WrappedEdwards>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier_3.generator, verifier2.generator);

    let res = serde_json::to_string(&verifier_3);
    assert!(res.is_ok());
    let v_str = res.unwrap();
    let res = serde_json::from_str::<PedersenVerifier<WrappedScalar, WrappedEdwards>>(&v_str);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier_3.generator, verifier2.generator);

    let res = serde_bare::to_vec(&verifier_3);
    assert!(res.is_ok());
    let v_bytes = res.unwrap();
    let res = serde_bare::from_slice::<PedersenVerifier<WrappedScalar, WrappedEdwards>>(&v_bytes);
    assert!(res.is_ok());
    let verifier2 = res.unwrap();
    assert_eq!(verifier_3.generator, verifier2.generator);
}
