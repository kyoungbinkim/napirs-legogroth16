use std::path::PathBuf;
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand, 
    time::SystemTime
};
use ark_bn254::{Bn254};
use ark_bls12_381::Bls12_381;
use legogroth16::{circom::CircomCircuit, ProvingKeyWithLink, ProvingKey, LinkPublicGenerators, generate_random_parameters_incl_cp_link};

pub fn gen_params<E: Pairing>(
    commit_witness_count : usize,
    circuit : CircomCircuit<E>,
    seed:u64,
) -> (ProvingKeyWithLink<E>, ProvingKey<E>, Vec<E::G1Affine>) { 
    
    let mut rng = StdRng::seed_from_u64(seed);
    let pedersen_gens = (0..commit_witness_count+1)
        .map(|_| E::G1::rand(&mut rng).into_affine())
        .collect::<Vec<_>>();
    let g1 = E::G1::rand(&mut rng).into_affine();
    let g2 = E::G2::rand(&mut rng).into_affine();
    
    let link_gens: LinkPublicGenerators<E> = LinkPublicGenerators{
        pedersen_gens,
        g1,
        g2,
    };

    // to debug
    // println!("link gen : {:?}", link_gens);

    let params_link = generate_random_parameters_incl_cp_link(
        circuit.clone(), 
        link_gens.clone(), 
        commit_witness_count, 
        &mut rng
    )
    .unwrap();

    let params = circuit
        .generate_proving_key(commit_witness_count, &mut rng)
        .unwrap();

    (params_link, params, link_gens.pedersen_gens)
}

pub fn setup_from_circom_r1cs<E:Pairing>(
    r1cs_file_path : &str,
    commit_witness_count : usize,
    seed:u64
) -> (ProvingKeyWithLink<E>, ProvingKey<E>, Vec<E::G1Affine>){
    let circuit: CircomCircuit<E> = CircomCircuit::<E>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();

    let start_time = SystemTime::now();
    let tmp = gen_params::<E>(commit_witness_count, circuit.clone(), seed);
    let end_time = SystemTime::now();
    let duration = end_time.duration_since(start_time)
        .expect("SystemTime::duration_since failed");
    println!("setup time: {:?}", duration);
    tmp
}

pub fn setup_from_circom_r1cs_bn128(
    r1cs_file_path : String,
    commit_witness_count : usize,
    seed:u64
) -> (ProvingKeyWithLink<Bn254>, ProvingKey<Bn254>, Vec<ark_bn254::G1Affine>) {
    setup_from_circom_r1cs::<Bn254>(r1cs_file_path.as_str(), commit_witness_count, seed)
}

pub fn setup_from_circom_r1cs_bls12_381(
    r1cs_file_path : String,
    commit_witness_count : usize,
    seed:u64
) -> (ProvingKeyWithLink<Bls12_381>, ProvingKey<Bls12_381>, Vec<ark_bls12_381::G1Affine>) {
    setup_from_circom_r1cs::<Bls12_381>(r1cs_file_path.as_str(), commit_witness_count, seed)
}

pub fn abs_path(relative_path: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative_path);
    path.to_string_lossy().to_string()
}