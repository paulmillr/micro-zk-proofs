# create circuit-v2
cd wasm-v2/circuit-v2
rm *.circom
prefix='https://raw.githubusercontent.com/iden3/circomlib/35e54ea21da3e8762557234298dbb553c175ea8d'
curl -O $prefix/circuits/aliascheck.circom
curl -O $prefix/circuits/binsum.circom
curl -O $prefix/circuits/bitify.circom
curl -O $prefix/circuits/comparators.circom
curl -O $prefix/circuits/compconstant.circom
curl -O $prefix/test/circuits/sum_test.circom
# fix paths
sed -ie 's/..\/..\/circuits\///g' sum_test.circom
# optional on macos
rm sum_test.circome

# create circuit-v1
cd ../../
cd js/circuit-v1
rm *.circom
cp ../../wasm-v2/circuit-v2/*.circom .
sed -ie 's/pragma circom 2.0.0;//' *.circom
# optional on macos
rm *.circome
cd ../../

rm js/sum-circuit.json
curl https://raw.githubusercontent.com/iden3/snarkjs/refs/tags/v0.2.0/test/circuit/sum.json > 'js/sum-circuit.json'
