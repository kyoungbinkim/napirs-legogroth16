const { plus100, setupFromCircomR1CsBn128 } = require('./test')


setupFromCircomR1CsBn128(
    "../legogro16/test-vectors/bn128/range_proof.r1cs",
    1,
    123,
    "./keys.bin"
);
console.assert(plus100(0) === 100, 'Simple test failed')



console.info('Simple test passed')
