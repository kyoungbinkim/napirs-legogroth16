#![deny(clippy::all)]
#![allow(dead_code)]

use std::collections::HashMap;

use ark_bn254::Bn254;
use ark_bls12_381::Bls12_381;
use std::{
  fs::{write}
};

use napi_derive::napi;

mod setup;

mod keys;

mod prover;

mod verifier;

// path : pk, vk ans saving
// pk   : circuit_bn128_pk.bin
// vk   : circuit_bn128_vk.bin
// proof: circuit_bn128_proof.bin
#[napi]
pub fn setup_from_circom_r1cs_bn128(
  r1cs_file_path : String,
  commit_witness_count : u32,
  seed:u32,
  path_pk : String,
  path_vk : String,
) {
  let(_, proving_key, _) = setup::setup_from_circom_r1cs_bn128(
    r1cs_file_path,
    commit_witness_count as usize,
    seed as u64
  );

  keys::write_bn128_proving_key(proving_key.clone(), &path_pk.as_str(),&path_vk.as_str()).unwrap();
}

#[napi]
pub fn setup_from_circom_r1cs_bls12_381(
  r1cs_file_path : String,
  commit_witness_count : u32,
  seed : u32,
  path_pk : String,
  path_vk : String,
) {
  let(_, proving_key, _) = setup::setup_from_circom_r1cs_bls12_381(
    r1cs_file_path,
    commit_witness_count as usize,
    seed as u64
  );

  keys::write_bls12_381_proving_key(proving_key.clone(), &path_pk.as_str(),&path_vk.as_str()).unwrap();
}

#[napi]
pub fn prove_range_bn128(
  r1cs_file_path : String,
  wasm_file_path : String,
  pk_file_path : String,
  proof_file_path : String,
  input_string: String,
  seed : u32
) {
  let value = prover::make_range_inputs::<Bn254>(input_string);
  let mut inputs= HashMap::new();
  inputs.insert("value".to_string(), vec![value]);

  let opening_key = prover::prove::<Bn254, _>(
    r1cs_file_path.as_str(), 
    pk_file_path.as_str(), 
    wasm_file_path.as_str(), 
    proof_file_path.as_str(),
    1usize,
    inputs.clone(), 
    seed as u64
  );
  let opening_key_path = format!("{}{}",proof_file_path.as_str().trim_end_matches(".bin"), "_opening_key.json");

  write(
    keys::abs_path(opening_key_path.as_str()),
    opening_key.as_bytes()
  ).unwrap();
}

#[napi]
pub fn prove_range_bls12_381(
  r1cs_file_path : String,
  wasm_file_path : String,
  pk_file_path : String,
  proof_file_path : String,
  input_string: String,
  seed : u32
) {
  let value = prover::make_range_inputs::<Bls12_381>(input_string);
  let mut inputs= HashMap ::new();
  inputs.insert("value".to_string(), vec![value]);

  let opening_key = prover::prove::<Bls12_381, _>(
    r1cs_file_path.as_str(), 
    pk_file_path.as_str(), 
    wasm_file_path.as_str(), 
    proof_file_path.as_str(),
    1usize,
    inputs.clone(), 
    seed as u64
  );
  println!("opening_key: {}", opening_key);
  let opening_key_path = format!("{}{}",proof_file_path.as_str().trim_end_matches(".bin"), "_opening_key.bin");
  println!("opening_key_path : {}", opening_key_path);
}

#[napi]
pub fn verify_range_bn128(
  vk_path : String,
  proof_file_path : String,
) {
  verifier::verify::<Bn254>(
    vk_path.as_str(), 
    proof_file_path.as_str(), 
    vec![]
  );
}

#[napi]
pub fn get_proof_bn128(
  proof_file_path : String
) -> String {
  prover::proof_to_string_from_file::<Bn254>(proof_file_path.as_str())
}

#[napi] 
pub fn aggregate_proof_commitment_bn128(
  proof_file_paths : Vec<String>,
  save_file_path : String
){
  prover::aggregate_proof_commitment::<Bn254>(proof_file_paths, &save_file_path.as_str());
}

#[napi]
pub fn aggregate_proof_commitment_bls12_381(
  proof_file_paths : Vec<String>,
  save_file_path : String
){
  prover::aggregate_proof_commitment::<Bls12_381>(proof_file_paths, &save_file_path.as_str());
}

#[napi]
pub fn get_aggregated_commitment_bn128(
  aggregated_commitment_file_path : String
) -> String {
  prover::get_aggregated_commitment::<Bn254>(aggregated_commitment_file_path.as_str())
}

#[napi]
pub fn get_aggregated_commitment_bls12_381(
  aggregated_commitment_file_path : String
) -> String {
  prover::get_aggregated_commitment::<Bls12_381>(aggregated_commitment_file_path.as_str())
}

#[napi]
pub fn aggregate_opening_keys_bn128(
  opening_key_file_paths : Vec<String>,
  save_file_path : String
){
  prover::aggregated_pedersen_commitment_opening_keys::<Bn254>(opening_key_file_paths, &save_file_path.as_str());
}

#[napi]
pub fn aggregate_opening_keys_bls12_381(
  opening_key_file_paths : Vec<String>,
  save_file_path : String
){
  prover::aggregated_pedersen_commitment_opening_keys::<Bls12_381>(opening_key_file_paths, &save_file_path.as_str());
}

#[napi]
pub fn calculate_pedersen_commitment_bn128(
  proving_file_path: String,
  m : String,
  v : String
) -> String {
  let proving_key = keys::read_compressed_proving_key_from_file::<Bn254>(&proving_file_path.as_str());
  let m = prover::hex_string_to_scalar_field::<Bn254>(m);
  let v = prover::hex_string_to_scalar_field::<Bn254>(v);

  let commitment = prover::calculate_pedersen_commitment::<Bn254>(proving_key, m, v);
  format!("{:#?}", commitment)
}
