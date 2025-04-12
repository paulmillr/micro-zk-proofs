./circom-wasm/target/release/circom -o output --r1cs --sym --wasm --json --wat circuit-v2/sum_test.circom
cd output/sum_test_js
mv witness_calculator.js witness_calculator.cjs