# zk-proofs examples

```sh
npm run all
```

## Compilers

There are three circom compilers:

- WASM circom v2 v2.2.2 [(github)](https://github.com/iden3/circom/releases/tag/v2.2.2) - modern version
- WASM circom v1 v0.5.46 [(github)](https://github.com/iden3/circom_old/releases/tag/v0.5.46) - legacy rewrite of v0.0.35
- JS circom v1 v0.0.35 [(github)](https://github.com/iden3/circom_old/releases/tag/v0.0.35) - original JS version

We support all versions for backwards-compatibility reasons.

## Circuits

Circuits were copied from circomlib. Check out its source code of init-circuits:

```sh
sh init-circuits.sh
```
