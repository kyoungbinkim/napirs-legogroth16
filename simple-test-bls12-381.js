const fs = require('fs');
const {
    setupFromCircomR1CsBls12381,
    proveRangeBls12381,
    verifyRangeBls12381,
} = require('./index.js');

const seed =  Math.floor( Math.random() * 1000000 );

setupFromCircomR1CsBls12381(
    "./circom/bls12-381/range_proof.r1cs",
    1,
    seed+1,
    "./range_pk.bin",
    "./range_vk.bin"
)
setupFromCircomR1CsBls12381(
    "./circom/bls12-381/range_proof.r1cs",
    1,
    seed+2,
    "./range_pk.bin",
    "./range_vk.bin"
)
setupFromCircomR1CsBls12381(
    "./circom/bls12-381/range_proof.r1cs",
    1,
    seed+2,
    "./range_pk.bin",
    "./range_vk.bin"
)

proveRangeBls12381(
    "./circom/bls12-381/range_proof.r1cs",
    "./circom/bls12-381/range_proof.wasm",
    "./range_pk.bin",
    "./test_proof1.bin",
    "0xfffffffffffffff0",
    seed+2
)
proveRangeBls12381(
    "./circom/bls12-381/range_proof.r1cs",
    "./circom/bls12-381/range_proof.wasm",
    "./range_pk.bin",
    "./test_proof2.bin",
    "0xabc1234567ab",
    seed+3
)

proveRangeBls12381(
    "./circom/bls12-381/range_proof.r1cs",
    "./circom/bls12-381/range_proof.wasm",
    "./range_pk.bin",
    "./test_proof3.bin",
    "0xabc1234567ab",
    seed+4
)

console.log(
    "verify :\t", 
    verifyRangeBls12381(
        "./range_vk.bin",
        "./test_proof1.bin"
    )
)

console.log(
    "verify :\t", 
    verifyRangeBls12381(
        "./range_vk.bin",
        "./test_proof2.bin"
    )
)

console.log(
    "verify :\t", 
    verifyRangeBls12381(
        "./range_vk.bin",
        "./test_proof3.bin"
    )
)