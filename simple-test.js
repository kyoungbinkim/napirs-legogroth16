const fs = require('fs')
const {
  setupFromCircomR1CsBn128,
  proveRangeBn128,
  verifyRangeBn128,
  getProofBn128,
  aggregateProofCommitmentBn128,
  getAggregatedCommitmentBn128,
  aggregateOpeningKeysBn128,
  calculatePedersenCommitmentBn128,
  updateAggregatedCommitmentBn128,
} = require('./index.js')

const bn128FieldPrime = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617")
const seed =  Math.floor( Math.random() * 1000000 );

setupFromCircomR1CsBn128(
    "./circom/bn128/range_proof.r1cs",
    1,
    seed,
    "./range_pk.bin",
    "./range_vk.bin"
)

setupFromCircomR1CsBn128(
    "./circom/bn128/range_proof.r1cs",
    1,
    seed+12,
    "./range_pk.bin",
    "./range_vk.bin"
)

setupFromCircomR1CsBn128(
    "./circom/bn128/range_proof.r1cs",
    1,
    seed+23,
    "./range_pk.bin",
    "./range_vk.bin"
)

proveRangeBn128(
    "./circom/bn128/range_proof.r1cs",
    "./circom/bn128/range_proof.wasm",
    "./range_pk.bin",
    "./test_proof1.bin",
    "0xfffffffffffffff0",
    1223
)

proveRangeBn128(
    "./circom/bn128/range_proof.r1cs",
    "./circom/bn128/range_proof.wasm",
    "./range_pk.bin",
    "./test_proof2.bin",
    "0xffffa",
    1223
)

proveRangeBn128(
    "./circom/bn128/range_proof.r1cs",
    "./circom/bn128/range_proof.wasm",
    "./range_pk.bin",
    "./test_proof3.bin",
    "0x1111111111111111",
    1223
)

console.log(
    "verify : ", 
    verifyRangeBn128(
        "./range_vk.bin",
        "./test_proof1.bin"
    )
)
console.log(
    "verify : ", 
    verifyRangeBn128(
        "./range_vk.bin",
        "./test_proof2.bin"
    )
)
console.log(
    "verify : ", 
    verifyRangeBn128(
        "./range_vk.bin",
        "./test_proof3.bin"
    )
)

const proofString = getProofBn128("./test_proof1.bin")
console.log(proofString)
console.log(JSON.parse(proofString))

const test1Json = JSON.parse(fs.readFileSync("./test_proof1_opening_key.json"))
console.log(
    calculatePedersenCommitmentBn128(
        "./range_pk.bin", 
        test1Json["m"], 
        test1Json["v"]
    )
)

aggregateProofCommitmentBn128(
    [
        "./test_proof1.bin",
        "./test_proof2.bin",
        "./test_proof3.bin"
    ],
    "./aggregated_commitment.bin"
)


aggregateOpeningKeysBn128(
    [
        "./test_proof1_opening_key.json",
        "./test_proof2_opening_key.json",
        "./test_proof3_opening_key.json"
    ],
    "./aggregated_opening_key.json"
)

let aggregatedOpeningKeyJson = JSON.parse(fs.readFileSync("./aggregated_opening_key.json"));
console.log(
    "calculated aggregated commitment:",
    calculatePedersenCommitmentBn128(
        "./range_pk.bin", 
        aggregatedOpeningKeyJson["m"], 
        aggregatedOpeningKeyJson["v"]
    )
)

console.log(
    "from aggregated proof :",
    getAggregatedCommitmentBn128(
        "./aggregated_commitment.bin"
    )
)

updateAggregatedCommitmentBn128(
    "./circom/bn128/range_proof.r1cs",
    "./range_pk.bin",
    "./circom/bn128/range_proof.wasm",
    "./test_proof3.bin",
    "./aggregated_commitment.bin",
    "./aggregated_opening_key.json",
    "0xffffffffffffffff",
    333111
)

aggregatedOpeningKeyJson = JSON.parse(fs.readFileSync("./aggregated_opening_key.json"));
console.log(
    "calculated aggregated commitment:",
    calculatePedersenCommitmentBn128(
        "./range_pk.bin", 
        aggregatedOpeningKeyJson["m"], 
        aggregatedOpeningKeyJson["v"]
    )
)

console.log(
    "from aggregated proof :",
    getAggregatedCommitmentBn128(
        "./aggregated_commitment.bin"
    )
)