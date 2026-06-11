/**
 * Subprocess entry point for the stack-overflow regression test.
 *
 * Run via:
 *   node --stack-size=256 test/helpers/deep-chain-runner.js
 *
 * With --stack-size=256 (256 kB) the old synchronous-recursion approach inside
 * generateWitness would crash with "Maximum call stack size exceeded" for N=1000
 * components.  The queue-based drain introduced by the snarkjs patch handles this
 * depth iteratively and must exit 0.
 *
 * Exit codes:
 *   0  success — witness computed and output matched
 *   1  unhandled exception (e.g. RangeError: Maximum call stack size exceeded)
 *   2  wrong output value
 */
import { generateWitness } from '../../witness.js';
import { buildDeepChainCircuit } from './chain-circuit.js';

const N = 1000;
const INPUT_VALUE = '7';

const circuit = buildDeepChainCircuit(N);
const result = generateWitness(circuit)({ in: INPUT_VALUE });

// result[1] is the main.out slot — should equal the input value after passing
// through all N relay components unchanged.
if (result[1] !== BigInt(INPUT_VALUE)) {
  process.stderr.write(`Wrong output: expected ${INPUT_VALUE}n, got ${result[1]}\n`);
  process.exit(2);
}

process.exit(0);
