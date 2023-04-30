use ark_ec::{pairing::Pairing};
use ark_serialize::{
    CanonicalSerialize, 
    CanonicalDeserialize  
};
use legogroth16::{ProvingKey};
use std::{
    fs::{write, read, File},
    io::Result,
    path::PathBuf,
};
use ark_bn254::Bn254;
use ark_bls12_381::Bls12_381;

pub fn write_bn128_proving_key(
    proving_key : ProvingKey<Bn254>,
    path : &str
) -> Result<()> {
    write_to_file_compresed_proving_key(proving_key, path)
}

pub fn

fn write_to_file_compresed_proving_key<E:Pairing>(
    proving_key : ProvingKey<E>,
    path : &str
) -> Result<()> {
    let mut compressed_bytes:Vec<u8> = Vec::new();
    proving_key.serialize_compressed(&mut compressed_bytes).unwrap();
    write(
        abs_path(path),
        compressed_bytes
    ).unwrap();
    Ok(())
}

fn read_compressed_proving_key_from_file<E:Pairing>(
    path : &str
) -> ProvingKey<E> {
    let readed_proving_key_file:Vec<u8> = read(abs_path(path)).unwrap();

    ProvingKey::<E>::deserialize_compressed(&*readed_proving_key_file).unwrap()
}

pub fn abs_path(relative_path: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative_path);
    path.to_string_lossy().to_string()
}