/**
 * Subprocess entry point for a function-triggered child stack regression.
 *
 * Run via:
 *   node --stack-size=256 test/helpers/function-trigger-runner.js
 */
import { generateWitness } from '../../witness.js';
import { buildFunctionTriggeredChildCircuit } from './chain-circuit.js';

const N = 500;
const INPUT_VALUE = '7';

const circuit = buildFunctionTriggeredChildCircuit(N);
const result = generateWitness(circuit)({ in: INPUT_VALUE });

if (result[1] !== BigInt(INPUT_VALUE)) {
  process.stderr.write(`Wrong output: expected ${INPUT_VALUE}n, got ${result[1]}\n`);
  process.exit(2);
}

process.exit(0);
