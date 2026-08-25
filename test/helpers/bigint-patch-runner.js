import { parentPort } from 'node:worker_threads';
import { generateWitness } from '../../witness.js';

const methods = [
  'eq',
  'neq',
  'greaterOrEquals',
  'greater',
  'gt',
  'lesserOrEquals',
  'lesser',
  'lt',
  'sub',
  'add',
  'mul',
  'div',
  'mod',
  'inverse',
  'modPow',
  'and',
  'shl',
  'shr',
];
const circuit = {
  nVars: 2,
  nInputs: 0,
  nOutputs: 1,
  nSignals: 2,
  templates: { Main: 'function(ctx) { ctx.setSignal("out", [], "1"); }' },
  functions: {},
  components: [{ name: 'main', params: {}, template: 'Main', inputSignals: 0 }],
  signals: [
    { names: ['one'], triggerComponents: [] },
    { names: ['main.out'], triggerComponents: [] },
  ],
  signalName2Idx: { one: 0, 'main.out': 1 },
};
const same = (a, b) =>
  (!a && !b) ||
  (a &&
    b &&
    a.configurable === b.configurable &&
    a.enumerable === b.enumerable &&
    a.writable === b.writable &&
    a.value === b.value &&
    a.get === b.get &&
    a.set === b.set);
const before = Object.fromEntries(
  methods.map((name) => [name, Object.getOwnPropertyDescriptor(BigInt.prototype, name)])
);

Object.defineProperty(BigInt.prototype, 'shl', {
  configurable: false,
  value() {
    return 123n;
  },
});
try {
  generateWitness(circuit, { unsafeAllowJsEvalCircuit: true })({});
  console.error('unexpected success');
  process.exit(1);
} catch (err) {
  if (!String(err && err.message).includes('shl')) {
    console.error(String(err && err.stack ? err.stack : err));
    process.exit(1);
  }
}
for (const name of methods) {
  if (name === 'shl') continue;
  if (!same(before[name], Object.getOwnPropertyDescriptor(BigInt.prototype, name))) {
    throw new Error('leaked ' + name);
  }
}
parentPort.postMessage('ok');
process.exit(0);
