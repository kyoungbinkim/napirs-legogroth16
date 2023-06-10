use ark_ec::{pairing::{Pairing}, AffineRepr};
use ark_ff::{PrimeField,BigInteger };
use ark_std::{
    rand::
    {
        prelude::StdRng,
        SeedableRng
    },
    UniformRand,
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
use std::{
    fs::{write, read},
    collections::HashMap,
    time::SystemTime
};
use hex::ToHex;


use crate::keys::{read_compressed_proving_key_from_file, abs_path};

// return pedersen commitment opening keys (m, v)
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
)  -> String {
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
    let v: <E as Pairing>::ScalarField = E::ScalarField::rand(&mut rng);
    
    let prove_start_time= SystemTime::now();
    let proof = create_random_proof(circuit, v, &proving_key, &mut rng).unwrap();
    let prove_end_time = SystemTime::now();
    let prove_duration = prove_end_time.duration_since(prove_start_time)
        .expect("SystemTime::duration_since failed");
    println!("prove time: {:?}", prove_duration);
    
    // to debug
    // println!("committed wit : {:?}", committed_witnesses);
    // println!("proof.d : {}", proof.d);
    // println!("calculated pedersen commitment: {}", proving_key.vk.gamma_abc_g1[1] * committed_witnesses[0] + &(proving_key.vk.eta_gamma_inv_g1.mul_bigint(v.into_bigint())));
    // println!("calculated pedersen commitment: {}", proving_key.vk.gamma_abc_g1[1] * committed_witnesses[0] + (proving_key.vk.eta_gamma_inv_g1.mul_bigint(v.into_bigint())));
    println!("v : {:?}", v.to_string());

    let mut compressed_bytes:Vec<u8> = Vec::new();
    proof.serialize_compressed(&mut compressed_bytes).unwrap();
    write(
        abs_path(proof_file_path),
        compressed_bytes
    ).unwrap();

    // to debug
    // println!("test to_bytes_le : {:?}", v.into_bigint().to_bytes_le());
    // println!("test to_bytes_be : {:?}", v.into_bigint().to_bytes_be());
    // println!("test from bytes_be : {:?}", E::ScalarField::from_be_bytes_mod_order(&v.into_bigint().to_bytes_be()).to_string());
    // println!("test to hex string : {}", v.into_bigint().to_bytes_be().encode_hex::<String>());åå
    // println!("test commited : {}", committed_witnesses[0].into_bigint());

    serde_json::to_string(&serde_json::json!({
        "m" : committed_witnesses[0].into_bigint().to_bytes_be().encode_hex::<String>(),
        "v" : v.into_bigint().to_bytes_be().encode_hex::<String>()
    })).unwrap()
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
) ->  E::ScalarField {
    let mut hex_string = hex_string.as_str();
    hex_string = hex_string.trim_start_matches("0x");
    let bytes = hex::decode(format!("{:0>64}", hex_string)).unwrap();

    E::ScalarField::from_be_bytes_mod_order(
        &bytes
    )
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
    println!("==== calculate_pedersen_commitment ====");
    println!("m : {}", m);
    println!("v : {}", v);

    (proving_key.vk.gamma_abc_g1[1] * m + proving_key.vk.eta_gamma_inv_g1 * v).into()
}

pub fn aggregate_proof_commitment<E:Pairing>(
    proof_file_paths : Vec<String>,
    save_file_path : &str
) {
    println!("==== aggregate_proof_commitment ====");

    assert!(proof_file_paths.len() != 0);
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

pub fn get_aggregated_commitment<E:Pairing>(
    aggregated_commitment_file_path : &str
) -> String {
    let aggregated_commitment_bin = read(abs_path(aggregated_commitment_file_path)).unwrap();
    let aggregated_commitment = E::G1Affine::deserialize_compressed(&*aggregated_commitment_bin).unwrap();
    format!("{:#?}", aggregated_commitment)
}

// save as json
pub fn aggregated_pedersen_commitment_opening_keys<E:Pairing>(
    opening_key_paths : Vec<String>,
    save_file_path : &str
) {
    assert!(opening_key_paths.len() != 0);
    
    let opening_key_json : serde_json::Value = serde_json::from_str(
        std::str::from_utf8(
            &(read(abs_path(&opening_key_paths[0])).unwrap())
        ).unwrap()
    ).unwrap();
    println!("{}", std::str::from_utf8(
        &(read(abs_path(&opening_key_paths[0])).unwrap())
    ).unwrap());

    let mut aggregated_v = hex_string_to_scalar_field::<E>(
        opening_key_json["v"].as_str().unwrap().to_string()
    );
    let mut aggregated_m = hex_string_to_scalar_field::<E>(
        opening_key_json["m"].as_str().unwrap().to_string()
    );

    for opening_key_path in opening_key_paths.iter().skip(1) {
        let opening_key_json : serde_json::Value = serde_json::from_str(
            std::str::from_utf8(
                &(read(abs_path(&opening_key_path)).unwrap())
            ).unwrap()
        ).unwrap();
        let v = hex_string_to_scalar_field::<E>(
            opening_key_json["v"].as_str().unwrap().to_string()
        );
        let m = hex_string_to_scalar_field::<E>(
            opening_key_json["m"].as_str().unwrap().to_string()
        );

        aggregated_v = aggregated_v + v;
        aggregated_m = aggregated_m + m;
    }

    println!("aggregated_v : {}", aggregated_v);
    println!("aggregated_m : {}", aggregated_m);

    let aggregated_opening_key =  serde_json::to_string(&serde_json::json!({
        "m" : aggregated_m.into_bigint().to_bytes_be().encode_hex::<String>(),
        "v" : aggregated_v.into_bigint().to_bytes_be().encode_hex::<String>()
    })).unwrap();

    write(
        save_file_path, 
        aggregated_opening_key
    ).unwrap();
}

// 너무 코드가 드러움....... 고치기는 귀찮아 ..................
// 변수 리팩토링 해야함
// proof file path : updated user proof 
// aggregated_commitment_file_path : aggregated commitment
pub fn update_aggregated_commitment<E:Pairing>(
    r1cs_file_path : &str,
    key_file_path : &str,
    wasm_file_path : &str,
    proof_file_path : &str,
    aggregated_commitment_file_path : &str,
    aggregated_opening_key_file_path : &str,
    update_value : String,
    seed : u64
) {
    let opening_key_path = format!("{}{}",proof_file_path.trim_end_matches(".bin"), "_opening_key.json");
    let opening_key_json : serde_json::Value = serde_json::from_str(
        std::str::from_utf8(
            &(read(abs_path(&opening_key_path)).unwrap())
        ).unwrap()
    ).unwrap();

    let aggregated_opening_key_json : serde_json::Value = serde_json::from_str(
        std::str::from_utf8(
            &(read(abs_path(&aggregated_opening_key_file_path)).unwrap())
        ).unwrap()
    ).unwrap();

    let before_v = hex_string_to_scalar_field::<E>(
        opening_key_json["v"].as_str().unwrap().to_string()
    );
    let before_m = hex_string_to_scalar_field::<E>(
        opening_key_json["m"].as_str().unwrap().to_string()
    );
    let mut aggregated_v = hex_string_to_scalar_field::<E>(
        aggregated_opening_key_json["v"].as_str().unwrap().to_string()
    );
    let mut aggregated_m = hex_string_to_scalar_field::<E>(
        aggregated_opening_key_json["m"].as_str().unwrap().to_string()
    );

    // sub before opening keys
    aggregated_m = aggregated_m - before_m;
    aggregated_v = aggregated_v - before_v;

    let aggregated_commitment_bin = read(abs_path(aggregated_commitment_file_path)).unwrap();
    let mut aggregated_commitment = E::G1Affine::deserialize_compressed(&*aggregated_commitment_bin).unwrap();

    let mut proof_bin = read(abs_path(proof_file_path)).unwrap();
    let mut proof: Proof<E> = Proof::<E>::deserialize_compressed(&*proof_bin).unwrap();

    // aggregated commitment - update_proof_d
    aggregated_commitment = (aggregated_commitment.into_group() - proof.d.into_group()).into();
    
    let inputs_value = make_range_inputs::<E>(update_value);
    let mut inputs= HashMap ::new();
    inputs.insert("value".to_string(), vec![inputs_value]);
    let after_opening_key = prove::<E, _>(
        r1cs_file_path, 
        key_file_path, 
        wasm_file_path, 
        proof_file_path, 
        1, 
        inputs, 
        seed
    );
    proof_bin = read(abs_path(proof_file_path)).unwrap();
    proof = Proof::<E>::deserialize_compressed(&*proof_bin).unwrap();

    let after_opening_key_json : serde_json::Value = serde_json::from_str(&after_opening_key).unwrap();
    let after_v = hex_string_to_scalar_field::<E>(
        after_opening_key_json["v"].as_str().unwrap().to_string()
    );
    let after_m = hex_string_to_scalar_field::<E>(
        after_opening_key_json["m"].as_str().unwrap().to_string()
    );

    aggregated_v = aggregated_v + after_v;
    aggregated_m = aggregated_m + after_m;

    aggregated_commitment = (aggregated_commitment + proof.d).into();

    let aggregated_opening_key =  serde_json::to_string(&serde_json::json!({
        "m" : aggregated_m.into_bigint().to_bytes_be().encode_hex::<String>(),
        "v" : aggregated_v.into_bigint().to_bytes_be().encode_hex::<String>()
    })).unwrap();

    write(
        aggregated_opening_key_file_path, 
        aggregated_opening_key
    ).unwrap();

    let mut compressed_bytes:Vec<u8> = Vec::new();
    aggregated_commitment.serialize_compressed(&mut compressed_bytes).unwrap();
    write(
        aggregated_commitment_file_path,
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

