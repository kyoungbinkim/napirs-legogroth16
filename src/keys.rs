use ark_ec::{pairing::Pairing};
use ark_serialize::{
    CanonicalSerialize, 
    CanonicalDeserialize  
};
use legogroth16::{ProvingKey};
use std::{
    fs::{write, read},
    io::Result,
    path::PathBuf,
};
use ark_bn254::Bn254;
use ark_bls12_381::Bls12_381;


pub fn read_bn128_proving_key_from_file(
    path : &str
) -> ProvingKey<Bn254> {
    read_compressed_proving_key_from_file::<Bn254>(path)
}

pub fn read_bls12_381_proving_key_from_file (
    path : &str
) -> ProvingKey<Bls12_381> {
    read_compressed_proving_key_from_file::<Bls12_381>(path)
}

pub fn write_bn128_proving_key(
    proving_key : ProvingKey<Bn254>,
    pk_path : &str,
    vk_path : &str
) -> Result<()> {
    write_to_file_compresed_proving_key::<Bn254>(proving_key, pk_path,vk_path)
}

pub fn write_bls12_381_proving_key (
    proving_key : ProvingKey<Bls12_381>,
    pk_path : &str,
    vk_path : &str
) -> Result<()> {
    write_to_file_compresed_proving_key::<Bls12_381>(proving_key, pk_path, vk_path)
}

fn write_to_file_compresed_proving_key<E:Pairing>(
    proving_key : ProvingKey<E>,
    pk_path : &str,
    vk_path : &str
) -> Result<()> {
    let mut compressed_bytes:Vec<u8> = Vec::new();
    proving_key.serialize_compressed(&mut compressed_bytes).unwrap();
    write(
        abs_path(pk_path),
        &compressed_bytes
    ).unwrap();

    compressed_bytes.clear();
    proving_key.vk.serialize_compressed(&mut compressed_bytes).unwrap();
    write(
        abs_path(vk_path),
        &compressed_bytes
    ).unwrap();

    Ok(())
}

pub fn read_compressed_proving_key_from_file<E:Pairing>(
    path : &str
) -> ProvingKey<E> {
    let readed_proving_key_file:Vec<u8> = read(abs_path(path)).unwrap();

    ProvingKey::<E>::deserialize_compressed(&*readed_proving_key_file).unwrap()
}

pub fn proving_key_to_strng<E:Pairing>(
    proving_key : ProvingKey<E>
) -> String {
    format!("{:#?}", proving_key)
}

pub fn abs_path(relative_path: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative_path);
    path.to_string_lossy().to_string()
}

