/**
 * Subprocess entry point for a nested direct-child stack regression.
 *
 * Run via:
 *   node --stack-size=256 test/helpers/nested-direct-runner.js
 */
import { generateWitness } from '../../witness.js';
import { buildNestedDirectChildCircuit } from './chain-circuit.js';

const N = 200;
const INPUT_VALUE = '7';

const circuit = buildNestedDirectChildCircuit(N);
const result = generateWitness(circuit)({ in: INPUT_VALUE });

if (result[1] !== BigInt(INPUT_VALUE)) {
  process.stderr.write(`Wrong output: expected ${INPUT_VALUE}n, got ${result[1]}\n`);
  process.exit(2);
}

process.exit(0);
