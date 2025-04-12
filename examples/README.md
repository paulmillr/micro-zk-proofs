# zk-proofs examples

There are three circom compilers:

- WASM circom v2 v2.2.2 [(github)](https://github.com/iden3/circom/releases/tag/v2.2.2) - modern version
- WASM circom v1 v0.5.46 [(github)](https://github.com/iden3/circom_old/releases/tag/v0.5.46) - legacy rewrite of v0.0.35
- JS circom v1 v0.0.35 [(github)](https://github.com/iden3/circom_old/releases/tag/v0.0.35) - original JS version

We support all versions for backwards-compatibility reasons.

To run:

```sh
npm run all
```

## Sources

Circuits were copied from circomlib: `sh init-circuits.sh`.
Check out its source code.


File `js/sum-circuit.json` taken from [snarkjs v0.2.0](https://raw.githubusercontent.com/iden3/snarkjs/refs/tags/v0.2.0/test/circuit/sum.json):

```sh
curl https://raw.githubusercontent.com/iden3/snarkjs/refs/tags/v0.2.0/test/circuit/sum.json > 'sum-circuit.json'
```

