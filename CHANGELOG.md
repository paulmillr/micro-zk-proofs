# Changelog for micro-zk-proofs

## Unreleased (2026-08-27)

- Made legacy circom-js circuits (which execute JavaScript via `eval`) require an explicit `unsafeAllowJsEvalCircuit` option in `generateWitness()`
- Added default resource limits to R1CS / ZKey parsing, setup, and proving: 64 MiB artifacts, 65,536 variables / constraints, 131,072-element domain; trusted larger circuits can override via `getCoders()` and the `limits` option of `buildSnark()`
- Added witness input validation: sparse arrays are rejected, and traversal depth / node counts are bounded with a configurable `inputLimits` option
- Added optional `hardenSideChannel` option to `buildSnark()`, keeping MSM workload shape independent of witness sparsity
- Hardened bigint-to-string conversion in `stringBigints`: bounded depth, cycle detection, and canonical base-10 decoding
- Documented that proving-key points and proof commitments must come from authenticated sources

## 0.3.1 (2026-06-14)

- Add support for unbounded recursion circuits

## 0.3.0 (2026-04-28)

- Upgrade deps to noble v2.2
- Minor security improvements

## 0.2.0 (2025-08-20)

- Upgrade deps to noble v2 beta

## 0.1.3 (2025-04-24)

- Fix failed JSR publish

## 0.1.2 (2025-04-24)

- Bump deps

## 0.1.1 (2025-04-17)

- Add gnark support: commitments in verify

## 0.1.0 (2025-04-12)

- Initial release
