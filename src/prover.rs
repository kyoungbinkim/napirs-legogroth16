use ark_ec::{pairing::{Pairing}, AffineRepr};
use ark_ff::{PrimeField};
use ark_std::{rand::{
    prelude::StdRng,
    SeedableRng},
    UniformRand
};
use ark_serialize::{
    CanonicalSerialize, 
    CanonicalDeserialize
};
use legogroth16::{
    ProvingKey,
    circom::{
        circuit::CircomCircuit,
        witness::WitnessCalculator
    }, create_random_proof, Proof,
};
use std::{fs::{write, read}};

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
    println!("proof.d : {}", proof.d);
    println!("calculated pedersen commitment: {}", proving_key.vk.gamma_abc_g1[1] * committed_witnesses[0] + &(proving_key.vk.eta_gamma_inv_g1.mul_bigint(v.into_bigint())));
    println!("calculated pedersen commitment: {}", proving_key.vk.gamma_abc_g1[1] * committed_witnesses[0] + (proving_key.vk.eta_gamma_inv_g1.mul_bigint(v.into_bigint())));

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

pub fn hex_string_to_scalar_field<E:Pairing> (
    hex_string: String
) -> E::ScalarField {
    make_range_inputs::<E>(hex_string).into()
}

pub fn proof_to_string_from_file<E:Pairing> (
    proof_file_path: &str
) -> String {
    let proof_bin = read(abs_path(proof_file_path)).unwrap();
    let proof = Proof::<E>::deserialize_compressed(&*proof_bin).unwrap();
    proof_to_string(proof)
}

pub fn proof_to_string<E:Pairing> (
    proof : Proof<E>
) -> String {
    // serde_json::json!({
    //     "a" : format!("{:#?}", proof.a),
    //     "b" : format!("{:#?}", proof.b),
    //     "c" : format!("{:#?}", proof.c),
    //     "d" : format!("{:#?}", proof.d),
    // }).to_string();
    serde_json::json!({
        "a" : format!("{:#?}", proof.a),
        "b" : format!("{:#?}", proof.b),
        "c" : format!("{:#?}", proof.c),
        "d" : format!("{:#?}", proof.d),
    }).to_string()
}

// to calculate g*m + h*v, originally m and g are vector
// m : message
// v : random
// g : proving_key.vk.gamma_abc_g1
// h : proving_key.vk.eta_gamma_inv_g1
pub fn calculate_pedersen_commitment<E:Pairing>(
    proving_key : ProvingKey<E>,
    m : E::ScalarField,
    v : E::ScalarField
) -> E::G1Affine {
    (proving_key.vk.gamma_abc_g1[1] * m + proving_key.vk.eta_gamma_inv_g1 * v).into()
}

pub fn aggregate_proof_commitment<E:Pairing>(
    proof_file_paths : Vec<String>,
    save_file_path : &str
) {
    assert!(proof_file_paths.len() == 0);
    let mut result = Proof::<E>::deserialize_compressed(
        &*read(abs_path(&proof_file_paths[0])).unwrap()
    ).unwrap().d;

    for proof_file_path in proof_file_paths.iter().skip(1) {
        let proof = Proof::<E>::deserialize_compressed(
            &*read(abs_path(proof_file_path)).unwrap()
        ).unwrap().d;
        result = add_pedersen_commitment::<E>(result, proof);
    }
    
    let mut compressed_bytes:Vec<u8> = Vec::new();
    result.serialize_compressed(&mut compressed_bytes).unwrap();
    write(
        abs_path(save_file_path),
        compressed_bytes
    ).unwrap();
}

pub fn add_pedersen_commitment_from_proof_file<E:Pairing>(
    proof_one_file_path:&str,
    proof_two_file_path:&str,
) -> E::G1Affine {
    let proof_one: Proof<E> = Proof::<E>::deserialize_compressed(&*read(proof_one_file_path).unwrap()).unwrap();
    let proof_two: Proof<E> = Proof::<E>::deserialize_compressed(&*read(proof_two_file_path).unwrap()).unwrap();
    add_pedersen_commitment_from_proof(proof_one, proof_two)
}

pub fn add_pedersen_commitment_from_proof<E : Pairing>(
    proof_one : Proof<E>,
    proof_two : Proof<E>
) -> E::G1Affine {
    add_pedersen_commitment::<E>(proof_one.d.clone(), proof_two.d.clone())
}

pub fn add_pedersen_commitment<E : Pairing> (
    commitment_one : E::G1Affine,
    commitment_two : E::G1Affine
) -> E::G1Affine {
    (commitment_one + commitment_two).into()
}

pub fn add_pedersen_commitment_and_proof<E:Pairing>(
    proof : Proof<E>,
    commitment : E::G1Affine
) -> E::G1Affine {
    add_pedersen_commitment::<E>(proof.d, commitment)
}

