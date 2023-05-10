use ark_ec::pairing::Pairing;
use legogroth16::{VerifyingKey, prepare_verifying_key, verify_proof, Proof};
use ark_serialize::CanonicalDeserialize;
use std::fs::read;

use crate::keys::abs_path;

pub fn verify<
    E : Pairing,
> (
    vk_path : &str,
    proof_path : &str,
    public_inputs : Vec<E::ScalarField>
) -> bool {
    let vk_bin = read(abs_path(vk_path)).unwrap();
    let pk_bin = read(abs_path(proof_path)).unwrap();

    let verifing_key = VerifyingKey::<E>::deserialize_compressed(&*vk_bin).unwrap();
    let prepared_vk = prepare_verifying_key::<E>(&verifing_key);

    let proof = Proof::<E>::deserialize_compressed(&*pk_bin).unwrap();

    let ver = verify_proof(&prepared_vk, &proof, &public_inputs);
    match ver {
        Ok(()) => return true,
        Err(_e) => return false
    };
}