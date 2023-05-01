use ark_ec::{pairing::Pairing, AffineRepr};
use ark_std::{rand::{
    prelude::StdRng,
    SeedableRng},
    UniformRand
};
use ark_serialize::{
    CanonicalSerialize, 
};
use legogroth16::{
    ProvingKey,
    circom::{
        circuit::CircomCircuit,
        witness::WitnessCalculator
    }, create_random_proof,
};
use std::fs::write;

use crate::keys::{read_compressed_proving_key_from_file, abs_path};


pub fn prove<
    E: Pairing,
    I: IntoIterator<Item = (String, Vec<E::ScalarField>)>
> (
    r1cs_file_path : &str,
    key_file_path : &str,
    wasm_file_path : &str,
    proof_file_path: &str,
    commit_witness_count : usize,
    inputs : I,
    seed : u64,
) {
    let mut circuit: CircomCircuit<E> = CircomCircuit::<E>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();

    let proving_key:ProvingKey<E> = read_compressed_proving_key_from_file::<E>(
        key_file_path
    );
    let mut wits_calc = WitnessCalculator::<E>::from_wasm_file(wasm_file_path).unwrap();
    let all_wires = wits_calc.calculate_witnesses::<I>(inputs, true).unwrap();

    circuit.set_wires(all_wires);

    let public_inputs = circuit.get_public_inputs().unwrap();
    let committed_witnesses = circuit
        .wires
        .clone()
        .unwrap()
        .into_iter()
        .skip(1 + public_inputs.len())
        .take(commit_witness_count)
        .collect::<Vec<_>>();

    let mut rng = StdRng::seed_from_u64(seed);
    let v = E::ScalarField::rand(&mut rng);

    let proof = create_random_proof(circuit, v, &proving_key, &mut rng).unwrap();
    println!("committed wit : {:?}", committed_witnesses);
    println!("proof.d : {}", proof.d.into_group());

    let mut compressed_bytes:Vec<u8> = Vec::new();
    proof.serialize_compressed(&mut compressed_bytes).unwrap();
    write(
        abs_path(proof_file_path),
        compressed_bytes
    ).unwrap();
}

pub fn make_range_inputs<E:Pairing> (
    input_string: String
) -> E::ScalarField {
    let mut input_str = input_string.as_str();
    input_str = input_str.trim_start_matches("0x");

    E::ScalarField::from(u64::from_str_radix(input_str, 16).unwrap())
}