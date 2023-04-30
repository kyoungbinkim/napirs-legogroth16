#![deny(clippy::all)]

use std::collections::HashMap;

use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;

use napi_derive::napi;

mod setup;

mod keys;

mod prover;

#[napi]
pub fn plus_100(input: u32) -> u32 {
  input + 100
}

#[napi]
pub fn setup_from_circom_r1cs_bn128(
  r1cs_file_path : String,
  commit_witness_count : u32,
  seed:u32,
  path : String
) {
  let(_, proving_key) = setup::setup_from_circom_r1cs_bn128(
    r1cs_file_path,
    commit_witness_count as usize,
    seed as u64
  );

  keys::write_bn128_proving_key(proving_key.clone(), &path.as_str()).unwrap();
}

#[napi]
pub fn setup_from_circom_r1cs_bls12_381(
  r1cs_file_path : String,
  commit_witness_count : u32,
  seed : u32,
  path : String
) {
  let(_, proving_key) = setup::setup_from_circom_r1cs_bls12_381(
    r1cs_file_path,
    commit_witness_count as usize,
    seed as u64
  );

  keys::write_bls12_381_proving_key(proving_key.clone(), &path.as_str()).unwrap();
}

#[napi]
pub fn prove_range_bn128(
  r1cs_file_path : String,
  key_file_path : String,
  wasm_file_path : String,
  proof_file_path : String,
  input_string: String,
  seed : u32
) {


  let value = prover::make_range_inputs::<Bn254>(input_string);
  let mut inputs= HashMap ::new();
  inputs.insert("value".to_string(), vec![value]);

  prover::prove::<Bn254, _>(
    r1cs_file_path.as_str(), 
    key_file_path.as_str(), 
    wasm_file_path.as_str(), 
    proof_file_path.as_str(),
    1usize,
    inputs.clone(), 
    seed as u64
  );
}

