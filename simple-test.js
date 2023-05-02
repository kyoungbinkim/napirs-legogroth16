const {
  setupFromCircomR1CsBn128,
  proveRangeBn128,
  verifyRangeBn128,
  getProofBn128
} = require('./index.js')




setupFromCircomR1CsBn128(
    "./circom/bn128/range_proof.r1cs",
    1,
    13323,
    "./range_pk.bin",
    "./range_vk.bin"
);

proveRangeBn128(
    "./circom/bn128/range_proof.r1cs",
    "./range_pk.bin",
    "./circom/bn128/range_proof.wasm",
    "./test_proof.bin",
    "0xffffa",
    1223
);

verifyRangeBn128(
    "./range_vk.bin",
    "./test_proof.bin"
);

const proofString = getProofBn128("./test_proof.bin");
console.log(proofString);
console.log(JSON.parse(proofString));