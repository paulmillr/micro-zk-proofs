# micro-zkproofs

Create & verify zero-knowledge SNARK proofs in parallel, using noble cryptography.

- Supports Groth16. PLONK and others are planned
- Optional, fast proof generation using web workers
- Supports modern circom v2 and legacy circom v1 programs
- Parse R1CS, WTNS

## Usage

> npm install micro-zkproofs

```js
import * as zkp from 'micro-zkproofs';
// Basic usage. Check out examples below for details
const proof = await zkp.bn254.groth.proof(provingKey, witness);
const isValid = zkp.bn254.groth.verify(verificationKey, proof.proof, proof.publicSignals);
```

- [Prerequisites](#prerequisites)
  - [Circuit in circom language](#circuit-in-circom-language)
  - [Compiler (circom2, rust)](#compiler-circom2-rust)
  - [Old compiled js versions](#old-compiled-js-versions)
- [0. Compile](#0-compile)
- [1. Setup](#1-setup)
- [2.1: Generate witness](#21-generate-witness)
- [2.2: Generate proof](#22-generate-proof)
- [3: Validate proof](#3-validate-proof)
- [Bonus: use WebWorkers to improve performance of prove generation:](#bonus-use-webworkers-to-improve-performance-of-prove-generation)
- [Full example (example/example.js)](#full-example-exampleexamplejs)
- [Using existing circuit (example/old-circuit.js)](#using-an-existing-circuit-exampleold-circuitjs)

### Prerequisites

#### Circuit in circom language

- [aliascheck.circom](https://raw.githubusercontent.com/iden3/circomlib/refs/heads/35e54ea21da3e8762557234298dbb553c175ea8d/test/circuits/aliascheck.circom)
- [binsum.circom](https://raw.githubusercontent.com/iden3/circomlib/refs/heads/35e54ea21da3e8762557234298dbb553c175ea8d/test/circuits/binsum.circom)
- [bitify.circom](https://raw.githubusercontent.com/iden3/circomlib/refs/heads/35e54ea21da3e8762557234298dbb553c175ea8d/test/circuits/bitify.circom)
- [comparators.circom](https://raw.githubusercontent.com/iden3/circomlib/refs/heads/35e54ea21da3e8762557234298dbb553c175ea8d/test/circuits/comparators.circom)
- [sum_test.circom](https://raw.githubusercontent.com/iden3/circomlib/refs/heads/35e54ea21da3e8762557234298dbb553c175ea8d/test/circuits/sum_test.circom)
- NOTE: we fixed include paths in 'sum_test.circom' in this example
- This is basic circuit that takes 3 variables: 'a, b, sum' (where a is private) and verifies that
  'a + b = sum'. All variables are 32 bit. This allows us to prove that we know such 'a' that produces specific
  'sum' with publicly known 'b' without disclosing which a we know.
- This is a toy circuit and it is not hard to identify which 'a' was used, in real example there would be some hash.

#### Compiler (circom2, rust)

```sh
git clone https://github.com/iden3/circom
cd circom
git checkout v2.2.2
cargo build --release
```

#### Compiler (circom1, js)

Last version of sum.json: [sum_last.json from snarkjs v0.2.0](https://raw.githubusercontent.com/iden3/snarkjs/refs/tags/v0.2.0/test/circuit/sum.json)

### 0. Compile

- this is outside of scope of our library and depends on circuit language
  - we have some tools for circom, but there is no common serialization: https://github.com/orgs/arkworks-rs/discussions/8
  - however, groth16 proofs are generic, you just need to provide same information
- in these examples we will use circom, but library should interoperate with different languages easily.
- we will also cover usage of circom v2 compiler (rust) and old circom v1 compiler (js)
- NOTE: some old circuits won't compile with new compiler and also output may differ between old and new compiler,
  for this reason we have support of old circuits (circom_old, js version).
- first, we need to write circuit in circom language:
  - we will use test circuit for that:
    - [aliascheck.circom](https://raw.githubusercontent.com/iden3/circomlib/refs/heads/35e54ea21da3e8762557234298dbb553c175ea8d/test/circuits/aliascheck.circom)
    - [binsum.circom](https://raw.githubusercontent.com/iden3/circomlib/refs/heads/35e54ea21da3e8762557234298dbb553c175ea8d/test/circuits/binsum.circom)
    - [bitify.circom](https://raw.githubusercontent.com/iden3/circomlib/refs/heads/35e54ea21da3e8762557234298dbb553c175ea8d/test/circuits/bitify.circom)
    - [comparators.circom](https://raw.githubusercontent.com/iden3/circomlib/refs/heads/35e54ea21da3e8762557234298dbb553c175ea8d/test/circuits/comparators.circom)
    - [sum_test.circom](https://raw.githubusercontent.com/iden3/circomlib/refs/heads/35e54ea21da3e8762557234298dbb553c175ea8d/test/circuits/sum_test.circom)
    - NOTE: we fixed include paths in 'sum_test.circom' in this example
- Lets compile it using rust:
    - `./circom/target/release/circom -o rust_output --r1cs --sym --wasm --json --wat circuit/sum_test.circom`
- For compilation with old js compiler:
  - remove `"pragma circom 2.0.0;"` (circuit_old)
  - `cd js_output && ../circom_old/cli.js ../circuit_old/sum_test.circom`
  - this specific circuit compiles both with new compiler and old one, other circuits may not.
- Result of compilation:
  - constraints list/info:
    - json or r1cs format for circom2
    - embedded in circuit.json for old compiler
  - witness calculation program:
    - wasm/js for circom2
    - embedded in circuit.json for old compiler
- NOTE: when using with existing project, proving/verify keys, witness calculation program and circuit info should be provided
  by authors. Compiling same circuit with slightly different version of compiler will result in incompatible circuit which
  will generate invalid proofs.

#### Imports

```js
// NOTE: we use common js here, because generated wasm calculator is not esm (you need to build it into esm module)
const fs = require('node:fs');
const calc = require('./rust_output/sum_test_js/witness_calculator.js');
const zkp = require('micro-zkproofs');
const zkpWitness = require('micro-zkproofs/witness');
const zkpMsm = require('micro-zkproofs/msm');

const { bn254 } = require('@noble/curves/bn254');
const circuitSum = require('./sum_last.json');
const { deepStrictEqual } = require('assert');
```

#### Input

```js
const input = { a: '33', b: '34' }; // Small input which we will prove
```

### 1. Setup

- WARNING: `.setup` method is for tests only, in real production setup you need to do multi-party ceremony to
  avoid leaking of toxic scalars.

#### WASM

```js
const coders = zkpWitness.getCoders(bn254.fields.Fr);
const setupWasm = zkp.bn254.groth.setup(
  coders.getCircuitInfo(fs.readFileSync('./rust_output/sum_test.r1cs'))
);
```

#### JS

```js
const setupJs = zkp.bn254.groth.setup(circuitSum);
```

### 2.1: Generate witness

- This step depends on language, but we just need array of bigints.
- For wasm (circom2) there is nice zero-deps calculator generated by compiler itself
- there also 'circom_tester' package to run these wasm witness calculation programs

#### WASM

```js
// NOTE: circom generates zero-deps witness calculator from wasm.
// In theory we can do small wasm runtime for it, but it depends on compiler version and can change!
const c = await calc(fs.readFileSync('./rust_output/sum_test_js/sum_test.wasm'));
const binWitness = await c.calculateBinWitness(input, true);
const wtns = await c.calculateWTNSBin(input, true);
const witness0 = coders.binWitness.decode(binWitness);
const witness1 = coders.WTNS.decode(wtns).sections[1].data; // Or using WTNS circom format
deepStrictEqual(witness0, witness1);
```

#### JS

```js
const witnessJs = zkpWitness.generateWitness(circuitSum)(input);
//deepStrictEqual(witness0, witnessJs); // -> will fail, because we have different constrains!
```

### 2.2: Generate proof

#### WASM

```js
const proofWasm = await zkp.bn254.groth.proof(setupWasm.vk_proof, witness0);
```

#### JS

```js
const proofJs = await zkp.bn254.groth.proof(setupJs.vk_proof, witnessJs);
```

### 3: Validate proof

#### WASM

```js
deepStrictEqual(
  zkp.bn254.groth.verify(setupWasm.vk_verifier, proofWasm.proof, proofWasm.publicSignals),
  true
);
```

#### JS

```js
deepStrictEqual(
  zkp.bn254.groth.verify(setupJs.vk_verifier, proofJs.proof, proofJs.publicSignals),
  true
);
```

### Bonus: use WebWorkers to improve performance of prove generation:

```js
const msm = zkpMsm.initMSM();
const groth16 = zkp.buildSnark(bn254, {
  G1msm: msm.methods.bn254_msmG1,
  G2msm: msm.methods.bn254_msmG2,
}).groth;
// 2.2: generate proof
const proofJs2 = await groth16.proof(setupJs.vk_proof, witnessJs);
// 3: validate proof
deepStrictEqual(groth16.verify(setupJs.vk_verifier, proofJs2.proof, proofJs2.publicSignals), true);
msm.terminate();
```

### Full example (example/example.js)

```js
// NOTE: we use common js here, because generated wasm calculator is not esm (you need to build it into esm module)
const fs = require('node:fs');
const calc = require('./rust_output/sum_test_js/witness_calculator.js');
const zkp = require('micro-zkproofs');
const zkpWitness = require('micro-zkproofs/witness');
const zkpMsm = require('micro-zkproofs/msm');

const { bn254 } = require('@noble/curves/bn254');
const circuitSum = require('./sum_last.json');
const { deepStrictEqual } = require('assert');

(async () => {
  const input = { a: '33', b: '34' };
  // WASM (circom2)
  // 1. setup
  const coders = zkpWitness.getCoders(bn254.fields.Fr);
  const setupWasm = zkp.bn254.groth.setup(
    coders.getCircuitInfo(fs.readFileSync('./rust_output/sum_test.r1cs'))
  );
  // 2.1: generate witness
  // NOTE: circom generates zero-deps witness calculator from wasm.
  // In theory we can do small wasm runtime for it, but it depends on compiler version and can change!
  const c = await calc(fs.readFileSync('./rust_output/sum_test_js/sum_test.wasm'));
  const binWitness = await c.calculateBinWitness(input, true);
  const wtns = await c.calculateWTNSBin(input, true);
  const witness0 = coders.binWitness.decode(binWitness);
  const witness1 = coders.WTNS.decode(wtns).sections[1].data; // Or using WTNS circom format
  deepStrictEqual(witness0, witness1);
  // 2.2: generate proof
  const proofWasm = await zkp.bn254.groth.proof(setupWasm.vk_proof, witness0);
  // 3: validate proof
  deepStrictEqual(
    zkp.bn254.groth.verify(setupWasm.vk_verifier, proofWasm.proof, proofWasm.publicSignals),
    true
  );

  // JS (circom_old)
  // 1. setup
  const setupJs = zkp.bn254.groth.setup(circuitSum);
  // Generate using circom_old circuit
  // NOTE: we have this small util to remove dependencies on snarkjs for witness generation
  // 2.1: generate witness
  const witnessJs = zkpWitness.generateWitness(circuitSum)(input);
  //deepStrictEqual(witness0, witnessJs); // -> will fail, because we have different constrains!
  // 2.2: generate proof
  const proofJs = await zkp.bn254.groth.proof(setupJs.vk_proof, witnessJs);
  // 3: validate proof
  deepStrictEqual(
    zkp.bn254.groth.verify(setupJs.vk_verifier, proofJs.proof, proofJs.publicSignals),
    true
  );

  // bonus: use workers for performance
  const msm = zkpMsm.initMSM();
  const groth16 = zkp.buildSnark(bn254, {
    G1msm: msm.methods.bn254_msmG1,
    G2msm: msm.methods.bn254_msmG2,
  }).groth;
  // 2.2: generate proof
  const proofJs2 = await groth16.proof(setupJs.vk_proof, witnessJs);
  // 3: validate proof
  deepStrictEqual(
    groth16.verify(setupJs.vk_verifier, proofJs2.proof, proofJs2.publicSignals),
    true
  );
  msm.terminate();
})();
```

### Using an existing circuit (example/old-circuit.js)

- We will use example circuit from [wasmsnark v0.0.12](https://github.com/iden3/wasmsnark):
- `git clone https://github.com/iden3/wasmsnark.git && cd wasmsnark && git checkout v0.0.12`
- NOTE: we don't generate witness here because no witness generation program provided

```js
// NOTE: we use common js here, because generated wasm calculator is not esm (you need to build it into esm module)
const { deepStrictEqual } = require('node:assert');
const { readFileSync } = require('node:fs');
const zkp = require('micro-zkproofs');

(async () => {
  const bigjson = (path) => zkp.stringBigints.decode(
    JSON.parse(fs.readFileSync('./wasmsnark/example/bn128/' + path, 'utf8'))
  );
  const provingKey = bigjson('proving_key.json');
  const verificationKey = bigjson('verification_key.json');
  const witness = bigjson('witness.json');
  const oldProof = bigjson('proof.json');
  const oldProofGood = bigjson('proof_good.json');
  const oldProofGood0 = bigjson('proof_good0.json');
  const oldPublic = bigjson('public.json');
  // Generate proofs
  const proofNew = await zkp.bn254.groth.proof(provingKey, witness);
  deepStrictEqual(
    zkp.bn254.groth.verify(verificationKey, proofNew.proof, proofNew.publicSignals),
    true
  );
  // Verify proofs
  deepStrictEqual(zkp.bn254.groth.verify(verificationKey, oldProof, oldPublic), true);
  deepStrictEqual(zkp.bn254.groth.verify(verificationKey, oldProofGood, oldPublic), true);
  deepStrictEqual(zkp.bn254.groth.verify(verificationKey, oldProofGood0, oldPublic), true);
})();
```

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
