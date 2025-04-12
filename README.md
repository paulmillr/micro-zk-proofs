# micro-zk-proofs

Create & verify zero-knowledge SNARK proofs in parallel, using [noble cryptography](https://paulmillr.com/noble/).

- Supports Groth16. PLONK and others are planned
- Optional, fast proof generation using web workers
- Supports modern wasm and legacy js circom programs
- Parse R1CS, WTNS

## Usage

> npm install micro-zk-proofs

```js
import * as zkp from 'micro-zk-proofs';
// Basic usage. Check out examples below for details
const proof = await zkp.bn254.groth.createProof(provingKey, witness);
const isValid = zkp.bn254.groth.verifyProof(verificationKey, proof);
```

- [Prerequisites](#prerequisites)
  - [Circuit in circom language](#circuit-in-circom-language)
  - [Compiler](#compiler)
- [0. Compile](#0-compile)
- [1. Setup](#1-setup)
- [2.1: Generate witness](#21-generate-witness)
- [2.2: Generate proof](#22-generate-proof)
- [3: Validate proof](#3-validate-proof)
- [Extra: Use workers for faster proof generation](#extra-enable-workers-for-faster-proof-generation)
- [Full example (example/example.js)](#full-example-exampleexamplejs)
- [Using existing circuit (example/old-circuit.js)](#using-an-existing-circuit-exampleold-circuitjs)

### Prerequisites

We will need a circuit in circom language and a compiler.

### 0. Compile

Circuit compilation is outside of scope of our library and depends on a circuit language.
Groth16 proofs don't care about language. We use circom in examples below, but you can use anything.

There is [no common serialization format](https://github.com/orgs/arkworks-rs/discussions/8) for circom, but this is not a big deal.

#### Compiler

There are three circom compilers:

- WASM circom v2 v2.2.2 [(github)](https://github.com/iden3/circom/releases/tag/v2.2.2) - modern version
- WASM circom v1 v0.5.46 [(github)](https://github.com/iden3/circom_old/releases/tag/v0.5.46) - legacy rewrite of v0.0.35
- JS circom v1 v0.0.35 [(github)](https://github.com/iden3/circom_old/releases/tag/v0.0.35) - original JS version

We support all versions for backwards-compatibility reasons:
v2 programs are different from circom v1, old circuits won't always compile with new compiler, and their output may differ between each other.

WASM circom v2:

```sh
git clone https://github.com/iden3/circom
cd circom
git checkout v2.2.2
cargo build --release
```

JS circom v1:

```sh
git clone https://github.com/iden3/circom_old
cd circom_old
git checkout v0.0.35
npm install
```

#### Circuit

- First, we need to write circuit in circom language:
  - we will use test circuit for that:
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
    - Last version of sum.json: [sum_last.json from snarkjs v0.2.0](https://raw.githubusercontent.com/iden3/snarkjs/refs/tags/v0.2.0/test/circuit/sum.json)
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

> [!NOTE]
> When using with existing project, proving/verify keys, witness calculation program and circuit info
> should be provided by authors. Compiling same circuit with slightly different version of compiler
> will result in incompatible circuit which will generate invalid proofs.

#### Imports

```js
// NOTE: we use common js here, because generated wasm calculator is not esm (you need to build it into esm module)
const fs = require('node:fs');
const calc = require('./rust_output/sum_test_js/witness_calculator.js');
const zkp = require('micro-zk-proofs');
const zkpWitness = require('micro-zk-proofs/witness');
const zkpMsm = require('micro-zk-proofs/msm');

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

### 2.2: Create proof

#### WASM

```js
const proofWasm = await zkp.bn254.groth.createProof(setupWasm.pkey, witness0);
```

#### JS

```js
const proofJs = await zkp.bn254.groth.createProof(setupJs.pkey, witnessJs);
```

### 3: Verify proof

#### WASM

```js
deepStrictEqual(
  zkp.bn254.groth.verifyProof(setupWasm.vkey, proofWasm),
  true
);
```

#### JS

```js
deepStrictEqual(
  zkp.bn254.groth.verifyProof(setupJs.vkey, proofJs),
  true
);
```

### Extra: Use workers for faster proof generation

```js
const msm = zkpMsm.initMSM();
const groth16 = zkp.buildSnark(bn254, {
  G1msm: msm.methods.bn254_msmG1,
  G2msm: msm.methods.bn254_msmG2,
}).groth;
// 2.2: generate proof
const proofJs2 = await groth16.createProof(setupJs.pkey, witnessJs);
// 3: validate proof
deepStrictEqual(groth16.verifyProof(setupJs.vkey, proofJs2), true);
msm.terminate();
```

### Full example (example/example.js)

```js
// NOTE: we use common js here, because generated wasm calculator is not esm (you need to build it into esm module)
const fs = require('node:fs');
const calc = require('./rust_output/sum_test_js/witness_calculator.js');
const zkp = require('micro-zk-proofs');
const zkpWitness = require('micro-zk-proofs/witness');
const zkpMsm = require('micro-zk-proofs/msm');

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
  const proofWasm = await zkp.bn254.groth.createProof(setupWasm.pkey, witness0);
  // 3: validate proof
  deepStrictEqual(
    zkp.bn254.groth.verifyProof(setupWasm.vkey, proofWasm),
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
  const proofJs = await zkp.bn254.groth.createProof(setupJs.pkey, witnessJs);
  // 3: validate proof
  deepStrictEqual(
    zkp.bn254.groth.verifyProof(setupJs.vkey, proofJs),
    true
  );

  // bonus: use workers for performance
  const msm = zkpMsm.initMSM();
  const groth16 = zkp.buildSnark(bn254, {
    G1msm: msm.methods.bn254_msmG1,
    G2msm: msm.methods.bn254_msmG2,
  }).groth;
  // 2.2: generate proof
  const proofJs2 = await groth16.createProof(setupJs.pkey, witnessJs);
  // 3: validate proof
  deepStrictEqual(
    groth16.verifyProof(setupJs.vkey, proofJs2),
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
const zkp = require('micro-zk-proofs');

(async () => {
  const bigjson = (path) => zkp.stringBigints.decode(
    JSON.parse(fs.readFileSync('./wasmsnark/example/bn128/' + path, 'utf8'))
  );
  const provingKey = bigjson('proving_key.json');
  const vkey = bigjson('verification_key.json');
  const witness = bigjson('witness.json');
  const oldProof = bigjson('proof.json');
  const oldProofGood = bigjson('proof_good.json');
  const oldProofGood0 = bigjson('proof_good0.json');
  const oldPublic = bigjson('public.json');
  // Generate proofs
  const proofNew = await zkp.bn254.groth.createProof(provingKey, witness);
  deepStrictEqual(
    zkp.bn254.groth.verifyProof(vkey, proofNew),
    true
  );
  // Verify proofs
  const publicSignals = oldPublic;
  deepStrictEqual(zkp.bn254.groth.verifyProof(vkey, { proof: oldProof, publicSignals }), true);
  deepStrictEqual(zkp.bn254.groth.verifyProof(vkey, { proof: oldProofGood, publicSignals }), true);
  deepStrictEqual(zkp.bn254.groth.verifyProof(vkey, { proof: oldProofGood0, publicSignals }), true);
})();
```

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
