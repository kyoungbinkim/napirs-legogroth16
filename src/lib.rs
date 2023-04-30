#![deny(clippy::all)]

use napi_derive::napi;

mod setup;

mod keys;

#[napi]
pub fn plus_100(input: u32) -> u32 {
  input + 100
}

#[napi]
pub fn setup_from_circom_r1cs_bn128(
  r1cs_file_path : String,
  commit_witness_count : u32,
  seed:u32
) {
  let(proving_key_with_link, proving_key) = setup::setup_from_circom_r1cs_bn128(
    r1cs_file_path,
    commit_witness_count as usize,
    seed as u64
  );
}