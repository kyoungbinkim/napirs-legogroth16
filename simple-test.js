const {
  plus100,
  setupFromCircomR1CsBn128,
  proveRangeBn128,
  verifyRangeBn128
} = require('./index.js')


setupFromCircomR1CsBn128(
    "../legogro16/test-vectors/bn128/range_proof.r1cs",
    1,
    123,
    "./range_pk.bin",
    "./range_vk.bin"
);

proveRangeBn128(
    "../legogro16/test-vectors/bn128/range_proof.r1cs",
    "./range_pk.bin",
    "../legogro16/test-vectors/bn128/range_proof.wasm",
    "./test_proof.bin",
    "0xffffa",
    123
);

verifyRangeBn128(
    "./range_vk.bin",
    "./test_proof.bin"
);

console.assert(plus100(0) === 100, 'Simple test failed')



console.info('Simple test passed')
