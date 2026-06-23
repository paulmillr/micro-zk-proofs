import { bn254 } from '@noble/curves/bn254.js';
import { hexToBytes } from '@noble/curves/utils.js';
import { keccakprg } from '@noble/hashes/sha3-addons.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, throws } from 'node:assert';
import { readFileSync } from 'node:fs';
import { dirname, join as joinPath } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Worker } from 'node:worker_threads';
import * as zkp from '../index.js';
import * as witness from '../witness.js';
import { buildDeepChainCircuit, buildDuplicateTriggerCircuit } from './helpers/chain-circuit.js';
import sumCircuit from './vectors/sum-circuit.json' with { type: 'json' };
import sumConstraints from './vectors/sum_test_constraints.json' with { type: 'json' };
const DATA_1 =
  '01000000000000000000000000000000000000000000000000000000000000004300000000000000000000000000000000000000000000000000000000000000210000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';

const DATA_2 =
  '77746e73020000000200000001000000280000000000000020000000010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e64306500000002000000a00c00000000000001000000000000000000000000000000000000000000000000000000000000004300000000000000000000000000000000000000000000000000000000000000210000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';

const _dirname = dirname(fileURLToPath(import.meta.url));

const prg = (seed) => {
  const p = keccakprg();
  p.addEntropy(utf8ToBytes(seed));
  const randomBytes = (len) => p.randomBytes(len);
  return randomBytes;
};

const bigintPatchNames = [
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
const bigintProto = BigInt.prototype;
const snapBigInt = () =>
  bigintPatchNames.map((name) => [name, Object.getOwnPropertyDescriptor(bigintProto, name)]);
const restoreBigInt = (state) => {
  for (const [name, desc] of state) {
    if (!desc) delete bigintProto[name];
    else Object.defineProperty(bigintProto, name, desc);
  }
};
const runWorker = (filename, options = {}) =>
  new Promise((resolve) => {
    const worker = new Worker(filename, { execArgv: [], ...options });
    let message;
    let error;
    const timeout = setTimeout(() => {
      error = 'worker timed out';
      worker.terminate();
    }, 30_000);
    worker.once('message', (msg) => {
      message = msg;
    });
    worker.once('error', (err) => {
      error = String(err && err.stack ? err.stack : err);
    });
    worker.once('exit', (status) => {
      clearTimeout(timeout);
      resolve({ status, message, error });
    });
  });
const runHelperWorker = (name) =>
  runWorker(pathToFileURL(joinPath(_dirname, 'helpers', name)), {
    resourceLimits: { stackSizeMb: 0.5 },
  });

const siblingCircuit = {
  nVars: 6,
  nInputs: 1,
  nOutputs: 1,
  nSignals: 6,
  templates: {
    Main: `function(ctx) {
      ctx.setPin("a", [], "in", [], ctx.getSignal("in", []));
      ctx.setSignal("out", [], ctx.getPin("b", [], "out", []));
    }`,
    A: `function(ctx) {
      ctx.setSignal("out", [], bigInt(ctx.getSignal("in", [])).add(bigInt(1)).mod(__P__));
    }`,
    B: `function(ctx) {
      ctx.setSignal("out", [], bigInt(ctx.getSignal("in", [])).add(bigInt(1)).mod(__P__));
    }`,
  },
  functions: {},
  components: [
    { name: 'main', params: {}, template: 'Main', inputSignals: 1 },
    { name: 'main.a', params: {}, template: 'A', inputSignals: 1 },
    { name: 'main.b', params: {}, template: 'B', inputSignals: 1 },
  ],
  signals: [
    { names: ['one'], triggerComponents: [] },
    { names: ['main.out'], triggerComponents: [] },
    { names: ['main.in'], triggerComponents: [0] },
    { names: ['main.a.in'], triggerComponents: [1] },
    { names: ['main.a.out', 'main.b.in'], triggerComponents: [2] },
    { names: ['main.b.out'], triggerComponents: [] },
  ],
  signalName2Idx: {
    one: 0,
    'main.out': 1,
    'main.in': 2,
    'main.a.in': 3,
    'main.a.out': 4,
    'main.b.in': 4,
    'main.b.out': 5,
  },
};

/*
Generated by circom 0.0.35 from:

template A() {
    signal input in;
    signal output out;
    signal output back;
    signal output final;

    out <== in + 1;
    final <== back;
}

template B() {
    signal input in;
    signal output out;

    out <== in + 1;
}

template Main() {
    signal input in;
    signal output out;

    component a = A();
    component b = B();

    a.in <== in;
    a.out ==> b.in;
    b.out ==> a.back;
    a.final ==> out;
}

component main = Main();

main.a.out aliases main.b.in, so A makes B ready while A is still running.
Old recursion runs B before A reads back; a deferred queue must demand-drain
when A reads the uninitialized back signal.
*/
const generatedOutputBackedgeCircuit = {
  nVars: 3,
  nInputs: 1,
  nOutputs: 1,
  nSignals: 4,
  templates: {
    A: `function(ctx) {
    ctx.setSignal("out", [], bigInt(ctx.getSignal("in", [])).add(bigInt("1")).mod(__P__));
    ctx.setSignal("final", [], ctx.getSignal("back", []));
}
`,
    B: `function(ctx) {
    ctx.setSignal("out", [], bigInt(ctx.getSignal("in", [])).add(bigInt("1")).mod(__P__));
}
`,
    Main: `function(ctx) {
    ctx.setPin("a", [], "in", [], ctx.getSignal("in", []));
    ctx.setPin("b", [], "in", [], ctx.getPin("a", [], "out", []));
    ctx.setPin("a", [], "back", [], ctx.getPin("b", [], "out", []));
    ctx.setSignal("out", [], ctx.getPin("a", [], "final", []));
}
`,
  },
  functions: {},
  components: [
    { name: 'main', params: {}, template: 'Main', inputSignals: 1 },
    { name: 'main.a', params: {}, template: 'A', inputSignals: 1 },
    { name: 'main.b', params: {}, template: 'B', inputSignals: 1 },
  ],
  signals: [
    { names: ['one'], triggerComponents: [] },
    { names: ['main.out', 'main.a.back', 'main.a.final', 'main.b.out'], triggerComponents: [] },
    { names: ['main.in', 'main.a.in'], triggerComponents: [0, 1] },
    { names: ['main.a.out', 'main.b.in'], triggerComponents: [2] },
  ],
  signalName2Idx: {
    one: 0,
    'main.in': 2,
    'main.out': 1,
    'main.a.in': 2,
    'main.a.out': 3,
    'main.a.back': 1,
    'main.a.final': 1,
    'main.b.in': 3,
    'main.b.out': 1,
  },
};

/*
Generated by circom 0.0.35 from:

template C() {
    signal input in;
    signal output back;
    signal output final;

    final <== back + in;
}

template Main() {
    signal input in;
    signal output out;

    component c = C();

    in + 5 ==> c.back;
    c.in <== in;
    c.final ==> out;
}

component main = Main();

main.in aliases main.c.in, so input assignment makes both main and c ready.
Old recursion runs main first and lets it initialize c.back before c runs.
An eager queue drain at ctx entry runs c before main initializes c.back.
*/
const generatedParentFirstBackedgeCircuit = {
  nVars: 3,
  nInputs: 1,
  nOutputs: 1,
  nSignals: 4,
  templates: {
    C: `function(ctx) {
    ctx.setSignal("final", [], bigInt(ctx.getSignal("back", [])).add(bigInt(ctx.getSignal("in", []))).mod(__P__));
}
`,
    Main: `function(ctx) {
    ctx.setPin("c", [], "back", [], bigInt(ctx.getSignal("in", [])).add(bigInt("5")).mod(__P__));
    ctx.setPin("c", [], "in", [], ctx.getSignal("in", []));
    ctx.setSignal("out", [], ctx.getPin("c", [], "final", []));
}
`,
  },
  functions: {},
  components: [
    { name: 'main', params: {}, template: 'Main', inputSignals: 1 },
    { name: 'main.c', params: {}, template: 'C', inputSignals: 1 },
  ],
  signals: [
    { names: ['one'], triggerComponents: [] },
    { names: ['main.out', 'main.c.final'], triggerComponents: [] },
    { names: ['main.in', 'main.c.in'], triggerComponents: [0, 1] },
    { names: ['main.c.back'], triggerComponents: [] },
  ],
  signalName2Idx: {
    one: 0,
    'main.in': 2,
    'main.out': 1,
    'main.c.in': 2,
    'main.c.back': 3,
    'main.c.final': 1,
  },
};

/*
Generated by circom 0.0.35 from:

template C() {
    signal input in;
    signal output out;

    out <== in + 1;
}

template D() {
    signal input in;
    signal output out;

    out <== in + 2;
}

template Main() {
    signal input in;
    signal output out;

    component c = C();
    component d = D();

    d.in <== in + 5;
    c.in <== in;
    c.out ==> out;
    d.out ==> out;
}

component main = Main();

main.in aliases main.c.in, so input assignment makes both main and c ready.
Old recursion runs d inside main, then c on the later c.in write, so c's
write wins the shared output slot. A FIFO queue leaves c pending before d, so
the later demand-drain runs c then d and d's write wins instead.
*/
const generatedDepthBreadthOverwriteCircuit = {
  nVars: 3,
  nInputs: 1,
  nOutputs: 1,
  nSignals: 4,
  templates: {
    C: `function(ctx) {
    ctx.setSignal("out", [], bigInt(ctx.getSignal("in", [])).add(bigInt("1")).mod(__P__));
}
`,
    D: `function(ctx) {
    ctx.setSignal("out", [], bigInt(ctx.getSignal("in", [])).add(bigInt("2")).mod(__P__));
}
`,
    Main: `function(ctx) {
    ctx.setPin("d", [], "in", [], bigInt(ctx.getSignal("in", [])).add(bigInt("5")).mod(__P__));
    ctx.setPin("c", [], "in", [], ctx.getSignal("in", []));
    ctx.setSignal("out", [], ctx.getPin("c", [], "out", []));
    ctx.setSignal("out", [], ctx.getPin("d", [], "out", []));
}
`,
  },
  functions: {},
  components: [
    { name: 'main', params: {}, template: 'Main', inputSignals: 1 },
    { name: 'main.c', params: {}, template: 'C', inputSignals: 1 },
    { name: 'main.d', params: {}, template: 'D', inputSignals: 1 },
  ],
  signals: [
    { names: ['one'], triggerComponents: [] },
    { names: ['main.out', 'main.c.out', 'main.d.out'], triggerComponents: [] },
    { names: ['main.in', 'main.c.in'], triggerComponents: [0, 1] },
    { names: ['main.d.in'], triggerComponents: [2] },
  ],
  signalName2Idx: {
    one: 0,
    'main.in': 2,
    'main.out': 1,
    'main.c.in': 2,
    'main.c.out': 1,
    'main.d.in': 3,
    'main.d.out': 1,
  },
};

/*
Generated by circom 0.0.35 from:

template C() {
    signal input in;
    signal output out;

    out <== in + 1;
}

template Main() {
    signal input in;
    signal output out;

    component c = C();

    c.in <== in;
    out <== in;
    c.out ==> out;
}

component main = Main();

main.in aliases main.c.in, so c is ready when main starts. Old recursion runs c
on the first c.in write, then main's later out write overwrites the shared
main.out/main.c.out slot. A queued scheduler that waits until getPin("c.out")
runs c too late and returns c's value instead.
*/
const generatedParentOverwriteChildOutputCircuit = {
  nVars: 3,
  nInputs: 1,
  nOutputs: 1,
  nSignals: 3,
  templates: {
    C: `function(ctx) {
    ctx.setSignal("out", [], bigInt(ctx.getSignal("in", [])).add(bigInt("1")).mod(__P__));
}
`,
    Main: `function(ctx) {
    ctx.setPin("c", [], "in", [], ctx.getSignal("in", []));
    ctx.setSignal("out", [], ctx.getSignal("in", []));
    ctx.setSignal("out", [], ctx.getPin("c", [], "out", []));
}
`,
  },
  functions: {},
  components: [
    { name: 'main', params: {}, template: 'Main', inputSignals: 1 },
    { name: 'main.c', params: {}, template: 'C', inputSignals: 1 },
  ],
  signals: [
    { names: ['one'], triggerComponents: [] },
    { names: ['main.out', 'main.c.out'], triggerComponents: [] },
    { names: ['main.in', 'main.c.in'], triggerComponents: [0, 1] },
  ],
  signalName2Idx: {
    one: 0,
    'main.in': 2,
    'main.out': 1,
    'main.c.in': 2,
    'main.c.out': 1,
  },
};

/*
Generated by circom 0.0.35 from:

template C() {
    signal input in;
    signal output out;

    out <== in + 1;
}

template Main() {
    signal input in;
    signal output out;
    component c = C();
    var i;

    for (i = 0; i < 1; c.in <== in) {
        i++;
    }

    out <== in;
    c.out ==> out;
}

component main = Main();

Old circom can emit a signal assignment in the for-step clause:
`for (...; ...; ctx.setPin("c", ...))`. A line-start-only generator transform
does not yield there, so the parent can continue to the later `out <== in`
before the queued child runs. Old recursion runs the child from the for-step
assignment before the parent continuation.
*/
const generatedForStepChildTriggerCircuit = {
  nVars: 3,
  nInputs: 1,
  nOutputs: 1,
  nSignals: 3,
  templates: {
    C: `function(ctx) {
    ctx.setSignal("out", [], bigInt(ctx.getSignal("in", [])).add(bigInt("1")).mod(__P__));
}
`,
    Main: `function(ctx) {
    for (ctx.setVar("i", [], "0");bigInt(bigInt(ctx.getVar("i",[])).lt(bigInt("1")) ? 1 : 0).neq(bigInt(0));ctx.setPin("c", [], "in", [], ctx.getSignal("in", []))) {
    {
        (ctx.setVar("i", [], bigInt(ctx.getVar("i",[])).add(bigInt("1")).mod(__P__))).add(__P__).sub(bigInt(1)).mod(__P__);
    }

     }
    ctx.setSignal("out", [], ctx.getSignal("in", []));
    ctx.setSignal("out", [], ctx.getPin("c", [], "out", []));
}
`,
  },
  functions: {},
  components: [
    { name: 'main', params: {}, template: 'Main', inputSignals: 1 },
    { name: 'main.c', params: {}, template: 'C', inputSignals: 1 },
  ],
  signals: [
    { names: ['one'], triggerComponents: [] },
    { names: ['main.out', 'main.c.out'], triggerComponents: [] },
    { names: ['main.in', 'main.c.in'], triggerComponents: [0, 1] },
  ],
  signalName2Idx: {
    one: 0,
    'main.in': 2,
    'main.out': 1,
    'main.c.in': 2,
    'main.c.out': 1,
  },
};

/*
Generated by circom 0.0.35 from:

template C(k) {
    signal input in;
    signal output out;
    out <== in + k;
}

template Main() {
    signal input in;
    signal output out;
    component c[3];
    var i;
    for (i = 0; i < 3; i++) {
        c[i] = C(i + 1);
    }
    c[0].in <== in;
    c[1].in <== in + 1;
    out <== in;
    c[0].out ==> out;
    c[2].in <== c[1].out;
    c[2].out ==> out;
}

component main = Main();

main.in aliases main.c[0].in, and main.out aliases main.c[0].out and
main.c[2].out. Old recursion runs c[0] immediately when main writes c[0].in,
then main overwrites the shared output slot with `out <== in`. PR2 defers c[0]
until the later read, so c[0] overwrites the parent value too late.
*/
const generatedArrayParentOverwriteCircuit = {
  nVars: 5,
  nInputs: 1,
  nOutputs: 1,
  nSignals: 5,
  templates: {
    C: `function(ctx) {
    ctx.setSignal("out", [], bigInt(ctx.getSignal("in", [])).add(bigInt(ctx.getVar("k",[]))).mod(__P__));
}
`,
    Main: `function(ctx) {
    for (ctx.setVar("i", [], "0");bigInt(bigInt(ctx.getVar("i",[])).lt(bigInt("3")) ? 1 : 0).neq(bigInt(0));(ctx.setVar("i", [], bigInt(ctx.getVar("i",[])).add(bigInt("1")).mod(__P__))).add(__P__).sub(bigInt(1)).mod(__P__)) {
    {
    }

     }
    ctx.setPin("c", ["0"], "in", [], ctx.getSignal("in", []));
    ctx.setPin("c", ["1"], "in", [], bigInt(ctx.getSignal("in", [])).add(bigInt("1")).mod(__P__));
    ctx.setSignal("out", [], ctx.getSignal("in", []));
    ctx.setSignal("out", [], ctx.getPin("c", ["0"], "out", []));
    ctx.setPin("c", ["2"], "in", [], ctx.getPin("c", ["1"], "out", []));
    ctx.setSignal("out", [], ctx.getPin("c", ["2"], "out", []));
}
`,
  },
  functions: {},
  components: [
    { name: 'main', params: {}, template: 'Main', inputSignals: 1 },
    { name: 'main.c[0]', params: { k: '1' }, template: 'C', inputSignals: 1 },
    { name: 'main.c[1]', params: { k: '2' }, template: 'C', inputSignals: 1 },
    { name: 'main.c[2]', params: { k: '3' }, template: 'C', inputSignals: 1 },
  ],
  signals: [
    { names: ['one'], triggerComponents: [] },
    { names: ['main.out', 'main.c[0].out', 'main.c[2].out'], triggerComponents: [] },
    { names: ['main.in', 'main.c[0].in'], triggerComponents: [0, 1] },
    { names: ['main.c[1].in'], triggerComponents: [2] },
    { names: ['main.c[1].out', 'main.c[2].in'], triggerComponents: [3] },
  ],
  signalName2Idx: {
    one: 0,
    'main.in': 2,
    'main.out': 1,
    'main.c[0].in': 2,
    'main.c[0].out': 1,
    'main.c[1].in': 3,
    'main.c[1].out': 4,
    'main.c[2].in': 4,
    'main.c[2].out': 1,
  },
};

/*
Generated by circom 0.0.35 from:

function setChild(v) {
    signal output childIn;

    childIn <== v;
    return v;
}

template C() {
    signal input in;
    signal output out;

    out <== in + 1;
}

template Main() {
    signal input in;
    signal output out;
    signal childIn;
    component c = C();
    var x;

    x = setChild(in);
    out <== in;
    c.out ==> out;
    childIn ==> c.in;
}

component main = Main();

Old circom allows functions to emit `ctx.setSignal`. Functions are not
templates, so a template-only generator transform does not yield when setChild
writes childIn. Old recursion runs c from inside the function before main's
later out write; the prototype queues c and only drains at the next template
yield, after main has already written out.
*/
const generatedFunctionChildTriggerLateAliasCircuit = {
  nVars: 4,
  nInputs: 1,
  nOutputs: 2,
  nSignals: 4,
  templates: {
    C: `function(ctx) {
    ctx.setSignal("out", [], bigInt(ctx.getSignal("in", [])).add(bigInt("1")).mod(__P__));
}
`,
    Main: `function(ctx) {
    ctx.setVar("x", [], ctx.callFunction("setChild", [ctx.getSignal("in", [])]));
    ctx.setSignal("out", [], ctx.getSignal("in", []));
    ctx.setSignal("out", [], ctx.getPin("c", [], "out", []));
    ctx.setPin("c", [], "in", [], ctx.getSignal("childIn", []));
}
`,
  },
  functions: {
    setChild: {
      params: ['v'],
      func: `function(ctx) {
    ctx.setSignal("childIn", [], ctx.getVar("v",[]));
    return ctx.getVar("v",[]);;
}
`,
    },
  },
  components: [
    { name: 'main', params: {}, template: 'Main', inputSignals: 1 },
    { name: 'main.c', params: {}, template: 'C', inputSignals: 1 },
  ],
  signals: [
    { names: ['one'], triggerComponents: [] },
    { names: ['main.out', 'main.c.out'], triggerComponents: [] },
    { names: ['main.childIn', 'main.c.in'], triggerComponents: [1] },
    { names: ['main.in'], triggerComponents: [0] },
  ],
  signalName2Idx: {
    one: 0,
    'main.in': 3,
    'main.out': 1,
    'main.childIn': 2,
    'main.c.in': 2,
    'main.c.out': 1,
  },
};

/*
Generated by circom 0.0.35 from:

template Main() {
    signal input in;
    signal output out;

    out <-- in << 3;
}

component main = Main();

Old circom emits `<<` as a BigInt-like `.shl(...)` method call in the
serialized witness program.
*/
const generatedShiftLeftCircuit = {
  nVars: 3,
  nInputs: 1,
  nOutputs: 1,
  nSignals: 3,
  templates: {
    Main: `function(ctx) {
    ctx.setSignal("out", [], bigInt("3").greater(bigInt(256)) ? 0 : bigInt(ctx.getSignal("in", [])).shl(bigInt("3")).and(__MASK__));
}
`,
  },
  functions: {},
  components: [{ name: 'main', params: {}, template: 'Main', inputSignals: 1 }],
  signals: [
    { names: ['one'], triggerComponents: [] },
    { names: ['main.out'], triggerComponents: [] },
    { names: ['main.in'], triggerComponents: [0] },
  ],
  signalName2Idx: {
    one: 0,
    'main.out': 1,
    'main.in': 2,
  },
};

const generatedAssertPathTokenCircuit = {
  nVars: 3,
  nInputs: 1,
  nOutputs: 1,
  nSignals: 3,
  templates: {
    Main: `function(ctx) {
    ctx.setSignal("out", [], ctx.getSignal("in", []));
    ctx.assert(ctx.getSignal("in", []), bigInt(ctx.getSignal("in", [])).add(bigInt("1")).mod(__P__), "/tmp/ctx.setSignal(/ctx.setPin(/ctx.callFunction(/case.circom:6:4");
}
`,
  },
  functions: {},
  components: [{ name: 'main', params: {}, template: 'Main', inputSignals: 1 }],
  signals: [
    { names: ['one'], triggerComponents: [] },
    { names: ['main.out'], triggerComponents: [] },
    { names: ['main.in'], triggerComponents: [0] },
  ],
  signalName2Idx: {
    one: 0,
    'main.out': 1,
    'main.in': 2,
  },
};

//const groth16 = zkp.buildSnark(bn254, { unsafePreserveToxic: true }).groth;

describe('Witness', () => {
  should('generateWitness restores BigInt prototype patches', () => {
    const before = snapBigInt();
    const preserved = function preservedAdd() {};
    try {
      const gen = witness.generateWitness(sumCircuit);
      for (const value of [preserved, undefined, { get: () => undefined, configurable: true }]) {
        if (typeof value === 'object') Object.defineProperty(bigintProto, 'add', value);
        else bigintProto.add = value;
        const expected = snapBigInt();
        gen({ a: '33', b: '34' });
        deepStrictEqual(snapBigInt(), expected);
        throws(() => gen({ a: '33' }), /Input Signal not assigned:/);
        deepStrictEqual(snapBigInt(), expected);
      }
    } finally {
      restoreBigInt(before);
    }
  });
  should('generateWitness fails cleanly when BigInt patching is impossible', async () => {
    const script = `
      import { parentPort } from 'node:worker_threads';
      import { generateWitness } from ${JSON.stringify(
        pathToFileURL(joinPath(_dirname, '..', 'witness.js')).href
      )};
      const methods = ${JSON.stringify(bigintPatchNames)};
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
        generateWitness(circuit)({});
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
    `;
    deepStrictEqual(
      await runWorker(script, { eval: true, type: 'module' }),
      {
        status: 0,
        message: 'ok',
        error: undefined,
      }
    );
  });
  should('yieldCtxCalls yields only executable scheduler ctx calls', () => {
    deepStrictEqual(
      witness.__TESTS.yieldCtxCalls(`function(ctx) {
    ctx.setSignal("out", [], ctx.getSignal("in", []));
    ctx.setPin("c", [], "in", [], ctx.callFunction("id", [ctx.getSignal("in", [])]));
    ctx.setVar("x", [], ctx.setSignal("tmp", [], "1"));
}
`),
      `function(ctx) {
    yield ctx.setSignal("out", [], ctx.getSignal("in", []));
    yield ctx.setPin("c", [], "in", [], yield ctx.callFunction("id", [ctx.getSignal("in", [])]));
    ctx.setVar("x", [], yield ctx.setSignal("tmp", [], "1"));
}
`
    );
  });
  should('yieldCtxCalls leaves strings and comments unchanged', () => {
    deepStrictEqual(
      witness.__TESTS.yieldCtxCalls(`function(ctx) {
    const quoted = "ctx.setSignal('x') and ctx.callFunction(\\"f\\")";
    const single = 'ctx.setPin("c")';
    const templ = \`ctx.setSignal("templ")\`;
    // ctx.setSignal("line")
    /* ctx.setPin("block")
       ctx.callFunction("block") */
    throw new Error("/tmp/ctx.setSignal(/ctx.setPin(/ctx.callFunction(/case.circom:6:4");
    ctx.setSignal("out", [], "1");
}
`),
      `function(ctx) {
    const quoted = "ctx.setSignal('x') and ctx.callFunction(\\"f\\")";
    const single = 'ctx.setPin("c")';
    const templ = \`ctx.setSignal("templ")\`;
    // ctx.setSignal("line")
    /* ctx.setPin("block")
       ctx.callFunction("block") */
    throw new Error("/tmp/ctx.setSignal(/ctx.setPin(/ctx.callFunction(/case.circom:6:4");
    yield ctx.setSignal("out", [], "1");
}
`
    );
  });
  should('yieldCtxCalls requires real ctx identifier boundaries', () => {
    deepStrictEqual(
      witness.__TESTS.yieldCtxCalls(`function(ctx) {
    myctx.setSignal("out", [], "1");
    obj.ctx.setPin("c", [], "in", [], "1");
    $ctx.callFunction("id", []);
    ctx.setSignal("out", [], "2");
}
`),
      `function(ctx) {
    myctx.setSignal("out", [], "1");
    obj.ctx.setPin("c", [], "in", [], "1");
    $ctx.callFunction("id", []);
    yield ctx.setSignal("out", [], "2");
}
`
    );
  });
  should('generateWitness reads own input fields only', () => {
    const gen = witness.generateWitness(sumCircuit);
    const expected = [1n, 67n, 34n, 33n];
    deepStrictEqual(gen({ a: '33', b: '34' }).slice(0, 4), expected);
    const inheritedExtra = Object.assign(Object.create({ extra: '99' }), { a: '33', b: '34' });
    deepStrictEqual(gen(inheritedExtra).slice(0, 4), expected);
    const inheritedRequired = Object.assign(Object.create({ b: '34' }), { a: '33' });
    throws(() => gen(inheritedRequired), /Input Signal not assigned:/);
  });
  should('generateWitness preserves sibling component reads after setPin', () => {
    const gen = witness.generateWitness(siblingCircuit);
    deepStrictEqual(gen({ in: '10' }), [1n, 12n, 10n, 10n, 11n, 12n]);
  });
  should('generateWitness preserves circom 0.0.35 output-backedge ordering', () => {
    const gen = witness.generateWitness(generatedOutputBackedgeCircuit);
    deepStrictEqual(gen({ in: '10' }), [1n, 12n, 10n]);
  });
  should('generateWitness preserves circom 0.0.35 parent-first backedge ordering', () => {
    const gen = witness.generateWitness(generatedParentFirstBackedgeCircuit);
    deepStrictEqual(gen({ in: '10' }), [1n, 25n, 10n]);
  });
  should('generateWitness preserves circom 0.0.35 depth-first overwrite ordering', () => {
    const gen = witness.generateWitness(generatedDepthBreadthOverwriteCircuit);
    deepStrictEqual(gen({ in: '10' }), [1n, 11n, 10n]);
  });
  should('generateWitness preserves circom 0.0.35 parent overwrite after child ordering', () => {
    const gen = witness.generateWitness(generatedParentOverwriteChildOutputCircuit);
    deepStrictEqual(gen({ in: '10' }), [1n, 10n, 10n]);
  });
  should('generateWitness preserves circom 0.0.35 array parent overwrite ordering', () => {
    const gen = witness.generateWitness(generatedArrayParentOverwriteCircuit);
    deepStrictEqual(gen({ in: '10' }), [1n, 10n, 10n, 11n, 13n]);
  });
  should('generateWitness preserves circom 0.0.35 for-step child trigger ordering', () => {
    const gen = witness.generateWitness(generatedForStepChildTriggerCircuit);
    deepStrictEqual(gen({ in: '10' }), [1n, 10n, 10n]);
  });
  should('generateWitness preserves circom 0.0.35 function child trigger ordering', () => {
    const gen = witness.generateWitness(generatedFunctionChildTriggerLateAliasCircuit);
    deepStrictEqual(gen({ in: '10' }), [1n, 10n, 10n, 10n]);
  });
  should('generateWitness supports circom 0.0.35 shift-left output', () => {
    const gen = witness.generateWitness(generatedShiftLeftCircuit);
    deepStrictEqual(gen({ in: '5' }), [1n, 40n, 5n]);
  });
  should('generateWitness preserves circom 0.0.35 assertion path strings', () => {
    const gen = witness.generateWitness(generatedAssertPathTokenCircuit);
    throws(
      () => gen({ in: '10' }),
      /^Error: Constraint doesn't match main: \/tmp\/ctx\.setSignal\(\/ctx\.setPin\(\/ctx\.callFunction\(\/case\.circom:6:4 -> 10 != 11$/
    );
  });
  should('generateWitness handles duplicate aliased trigger components once', () => {
    const circuit = buildDuplicateTriggerCircuit(5, 4);
    deepStrictEqual(
      circuit.signals[3].triggerComponents,
      [1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5]
    );
    const gen = witness.generateWitness(circuit);
    deepStrictEqual(gen({ in: '7' }), [1n, 7n, 7n, 7n]);
  });
  should('R1CS', () => {
    const data = Uint8Array.from(readFileSync(joinPath(_dirname, './vectors/sum_test.r1cs')));
    const coder = witness.getCoders(bn254).R1CS; // We need to pass fields because it depends on bytesize of order
    const decoded = coder.decode(data);
    deepStrictEqual(decoded.version, 1);
    deepStrictEqual(decoded.sections[1], {
      TAG: 'header',
      data: {
        prime: bn254.fields.Fr.ORDER,
        nWires: 101,
        nPubOut: 1,
        nPubIn: 0,
        nPrvIn: 2,
        nLables: 200n,
        mConstraints: 101, // == nSignals? nVars?
      },
    });

    /*

       "nPrvInputs": 1,
    "nPubInputs": 1,
    "nInputs": 2,
    "nOutputs": 1,
    "nVars": 101,
    "nConstants": 0,
    "nSignals": 101
    */
    deepStrictEqual(decoded.sections[0].data, zkp.stringBigints.decode(sumConstraints).constraints);
    deepStrictEqual(coder.encode(decoded), data);
    const invalidKeyR1CS = (key) => ({
      magic: undefined,
      version: 1,
      sections: [
        decoded.sections[1],
        { TAG: 'constraint', data: [[{ [key]: 1n }, {}, {}]] },
        { TAG: 'wire2label', data: [0n, 1n] },
      ],
    });
    for (const key of ['', '01', '1.0', '0x10', ' 1', '1e2', '4294967296'])
      throws(() => coder.encode(invalidKeyR1CS(key)), /expected uint32 constraint key/);
  });
  should('binary witness', () => {
    const data = hexToBytes(DATA_1);

    const coder = witness.getCoders(bn254).binWitness;
    const decoded =
      '1,67,33,34,1,1,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0';
    deepStrictEqual(
      coder.decode(data),
      decoded.split(',').map((n) => BigInt(n))
    );
  });
  should('WTNS', () => {
    const data = hexToBytes(DATA_2);
    const decoded2 =
      '1,67,33,34,1,1,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0';
    const coder = witness.getCoders(bn254).WTNS;
    deepStrictEqual(coder.decode(data), {
      magic: undefined,
      version: 2,
      sections: [
        {
          TAG: 'header',
          data: {
            prime: bn254.fields.Fr.ORDER,
            size: 101, // winess size
          },
        },
        {
          TAG: 'witness',
          data: decoded2.split(',').map((n) => BigInt(n)),
        },
      ],
    });
  });
  should('section length encoders', () => {
    const { R1CS, WTNS, ZKeyRaw } = witness.getCoders(bn254);
    const wtns = hexToBytes(DATA_2);
    deepStrictEqual(WTNS.encode(WTNS.decode(wtns)), wtns);
    const zkey = Uint8Array.from(readFileSync(joinPath(_dirname, './vectors/keys/zkey0.zkey')));
    deepStrictEqual(ZKeyRaw.encode(ZKeyRaw.decode(zkey)), zkey);
    const emptyR1CS = {
      magic: undefined,
      version: 1,
      sections: [
        {
          TAG: 'header',
          data: {
            prime: bn254.fields.Fr.ORDER,
            nWires: 1,
            nPubOut: 0,
            nPubIn: 0,
            nPrvIn: 0,
            nLables: 1n,
            mConstraints: 0,
          },
        },
        { TAG: 'constraint', data: [] },
        { TAG: 'wire2label', data: [0n] },
      ],
    };
    deepStrictEqual(R1CS.decode(R1CS.encode(emptyR1CS)), emptyR1CS);
  });
  should('ZKey', () => {
    // NOTE: keys extracted from deterministic tests in snarkjs v0.7.5 (fullproccess.js)
    const data = Uint8Array.from(readFileSync(joinPath(_dirname, './vectors/keys/zkey0.zkey')));
    // json exported via 'snarkjs zkey export json' to verify we are parsing correctly
    const json = zkp.stringBigints.decode(
      JSON.parse(readFileSync(joinPath(_dirname, './vectors/keys/zkey0.json'), 'utf8'))
    );
    const coder = witness.getCoders(bn254).ZKeyRaw;
    const decoded = coder.decode(data);
    deepStrictEqual(json.protocol, decoded.sections[0].data);
    // power = log2(domainSize)
    for (const k of ['q', 'r', 'n8q', 'n8r', 'nPublic', 'nVars', 'domainSize']) {
      deepStrictEqual(decoded.sections[1].data[k], json[k]);
    }
    const { Fr, Fp } = bn254.fields;
    const fieldFromMont = (f, is1) => {
      const Rr = f.pow(BigInt(2), BigInt(f.BYTES * 8));
      const RRi = f.inv(Rr);
      const RRi2 = f.mul(RRi, RRi);
      return (x) => f.mul(x, is1 ? RRi : RRi2);
    };
    const convFr2 = fieldFromMont(Fr, false);
    const convFp = fieldFromMont(Fp, true);
    const convG1 = ([x, y]) =>
      x == 0 && y == 0 ? [BigInt(0), BigInt(1), BigInt(0)] : [convFp(x), convFp(y), BigInt(1)];

    //     [ [ 0n, 0n ], [ 0n, 0n ], [ 1n, 0n ] ], ->     [ [ 0n, 0n ], [ 1n, 0n ], [ 0n, 0n ] ],
    const convG2 = ([xc0, xc1, yc0, yc1]) =>
      xc0 == 0 && xc1 == 0 && yc0 == 0 && yc1 == 0
        ? [
            [BigInt(0), BigInt(0)],
            [BigInt(1), BigInt(0)],
            [BigInt(0), BigInt(0)],
          ]
        : [
            [convFp(xc0), convFp(xc1)],
            [convFp(yc0), convFp(yc1)],
            [BigInt(1), BigInt(0)],
          ];

    deepStrictEqual(json.q, bn254.fields.Fp.ORDER);
    deepStrictEqual(json.r, bn254.fields.Fr.ORDER);

    deepStrictEqual(convG1(decoded.sections[1].data.vk_alpha_1), json.vk_alpha_1);
    deepStrictEqual(convG1(decoded.sections[1].data.vk_beta_1), json.vk_beta_1);
    deepStrictEqual(convG1(decoded.sections[1].data.vk_delta_1), json.vk_delta_1);
    deepStrictEqual(convG2(decoded.sections[1].data.vk_beta_2), json.vk_beta_2);
    deepStrictEqual(convG2(decoded.sections[1].data.vk_delta_2), json.vk_delta_2);
    // coefficients
    deepStrictEqual(
      decoded.sections[2].data.map((i) => ({ ...i, value: convFr2(i.value) })),
      json.ccoefs
    );
    deepStrictEqual(decoded.sections[6].data.map(convG1), json.A);
    deepStrictEqual(decoded.sections[7].data.map(convG1), json.B1);
    deepStrictEqual(
      new Array(json.nPublic + 1).fill(null).concat(decoded.sections[5].data.map(convG1)),
      json.C
    );
    deepStrictEqual(decoded.sections[8].data.map(convG2), json.B2);
    deepStrictEqual(decoded.sections[4].data.map(convG1), json.hExps);
    deepStrictEqual(decoded.sections[3].data.map(convG1), json.IC);

    const parsed = witness.getCoders(bn254).parseZKey(data);
    deepStrictEqual(parsed.json, json);
  });

  should('ZKey process', async () => {
    const groth16 = zkp.buildSnark(bn254, { unsafePreserveToxic: true }).groth;
    const { parseZKey, WTNS, ZKeyRaw, ZKeyRaw2 } = witness.getCoders(bn254);
    const data = Uint8Array.from(
      readFileSync(joinPath(_dirname, './vectors/keys/zkey_final.zkey'))
    );
    const { pkey, vkey } = parseZKey(data);
    const vkeySnark = zkp.stringBigints.decode(
      JSON.parse(readFileSync(joinPath(_dirname, './vectors/keys/zkey_final.vkey.json'), 'utf8'))
    );
    // New format slightly changed
    const vkeySnarkFix = { ...vkeySnark };
    delete vkeySnarkFix.curve;
    delete vkeySnarkFix.vk_alphabeta_12;
    vkeySnarkFix.protocol = 'groth';
    vkeySnarkFix.vk_alfa_1 = vkeySnarkFix.vk_alpha_1;
    delete vkeySnarkFix.vk_alpha_1;

    deepStrictEqual(vkey, vkeySnarkFix);

    const witnessBytes = Uint8Array.from(
      readFileSync(joinPath(_dirname, './vectors/keys/witness.wtns'))
    );
    const wtns = WTNS.decode(witnessBytes);
    const witnessData = wtns.sections.find((i) => i.TAG === 'witness');
    if (!witnessData) throw new Error('WTNS: cannot find witness');

    const proof = await groth16.createProof(pkey, witnessData.data, prg('h stuff'));
    // this tested against snarkjs:
    // npx snarkjs zkey export verificationkey ../../test/vectors/keys/zkey_final.zkey ../../test/vectors/keys/zkey_final.vkey.json
    // npx snarkjs groth16 verify ../../test/vectors/keys/zkey_final.vkey.json ../../test/vectors/keys/public.json ../../test/vectors/keys/proof.json
    // [INFO]  snarkJS: OK!
    deepStrictEqual(zkp.stringBigints.encode(proof), {
      proof: JSON.parse(readFileSync(joinPath(_dirname, './vectors/keys/proof.json'), 'utf8')),
      publicSignals: JSON.parse(
        readFileSync(joinPath(_dirname, './vectors/keys/public.json'), 'utf8')
      ),
    });
    // console.log('PROOF', JSON.stringify(zkp.stringBigints.encode(proof)));
    deepStrictEqual(groth16.verifyProof(vkey, proof), true);
  });

  // ── deep relay-chain tests ────────────────────────────────────────────────────
  // These tests exercise the queue-based component-drain introduced to prevent
  // call-stack overflow on circuits with long inter-template chains.

  should('deep relay chain: correct output for small N', () => {
    // Functional sanity check: a 10-component relay chain passes the input value
    // through unchanged.  result[1] is the main.out slot.
    const gen = witness.generateWitness(buildDeepChainCircuit(10));
    deepStrictEqual(gen({ in: '42' })[1], 42n);
  });

  should(
    'deep relay chain: no stack overflow under reduced stack size (N=1000, stack=256kB)',
    async () => {
      // Use a worker isolate with a reduced stack. Under the old synchronous-recursion
      // approach 1000 triggerComponent frames would exceed this budget.
      const result = await runHelperWorker('deep-chain-runner.js');
      deepStrictEqual(
        result.status,
        0,
        `Worker crashed (status ${result.status}):\n${result.error}`
      );
    }
  );
  should(
    'nested direct-child chain: no stack overflow under reduced stack size (N=200, stack=256kB)',
    async () => {
      // Old circom 0.0.35 can emit direct nested child component hierarchies.
      // The scheduler must preserve immediate child-before-parent-continuation
      // ordering without implementing it as normal recursive JS calls.
      const result = await runHelperWorker('nested-direct-runner.js');
      deepStrictEqual(
        result.status,
        0,
        `Worker crashed (status ${result.status}):\n${result.error}`
      );
    }
  );
  should(
    'function-triggered child chain: no stack overflow under reduced stack size (N=500, stack=256kB)',
    async () => {
      // Old circom 0.0.35 can emit ctx.setSignal from generated functions. If
      // function-triggered child work is drained from inside the caller's active
      // generator step, a nested component hierarchy can still recurse through
      // JS calls even though template-level setPin/setSignal statements yield.
      const result = await runHelperWorker('function-trigger-runner.js');
      deepStrictEqual(
        result.status,
        0,
        `Worker crashed (status ${result.status}):\n${result.error}`
      );
    }
  );
});

should.runWhen(import.meta.url);
