const {
  setupFromCircomR1CsBn128,
  proveRangeBn128,
  verifyRangeBn128,
  getProofBn128,
  aggregateProofCommitmentBn128,
  aggregateOpeningKeysBn128,
  calculatePedersenCommitmentBn128
} = require('./index.js')

const fs = require('fs');

setupFromCircomR1CsBn128(
    "./circom/bn128/range_proof.r1cs",
    1,
    13323,
    "./range_pk.bin",
    "./range_vk.bin"
);

proveRangeBn128(
    "./circom/bn128/range_proof.r1cs",
    "./circom/bn128/range_proof.wasm",
    "./range_pk.bin",
    "./test_proof1.bin",
    "0xffffa",
    1223
);

proveRangeBn128(
    "./circom/bn128/range_proof.r1cs",
    "./circom/bn128/range_proof.wasm",
    "./range_pk.bin",
    "./test_proof2.bin",
    "0xffffa",
    1223
);

verifyRangeBn128(
    "./range_vk.bin",
    "./test_proof1.bin"
);

const proofString = getProofBn128("./test_proof1.bin");
console.log(proofString);
console.log(JSON.parse(proofString));

const test1Json = JSON.parse(fs.readFileSync("./test_proof1_opening_key.json"));
console.log(BigInt(test1Json["m"]).toString(16));
console.log(
    calculatePedersenCommitmentBn128(
        "./range_pk.bin", 
        BigInt(test1Json["m"]).toString(16), 
        BigInt(test1Json["v"]).toString(16)
    )
);

aggregateProofCommitmentBn128(
    [
        "./test_proof1.bin",
        "./test_proof2.bin"
    ],
    "./aggregated_proof.bin"
)


aggregateOpeningKeysBn128(
    [
        "./test_proof1_opening_key.json",
        "./test_proof2_opening_key.json"
    ],
    "./aggregated_opening_key.json"
)