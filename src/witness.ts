/**
 * The code is only used if you plan to run **legacy circom-js programs**. It is unused in WASM.
 * Minimal witness program executor for circom programs, based on websnark/wasmsnark/snarkjs.
 * Unsafe: it uses eval, better to be used inside worker threads.
 * Depends on **monkey-patched BigInt** prototypes due to how circom programs are serialized.
 * We only patch prototypes before execution. After finishing, patches are reverted.
 * @module
 */

import type { BlsCurvePair as BLSCurvePair } from '@noble/curves/abstract/bls.js';
import { invert, pow, type IField } from '@noble/curves/abstract/modular.js';
import { bn254 as nobleBn254 } from '@noble/curves/bn254.js';
import { bitMask } from '@noble/curves/utils.js';
import { abytes, type TArg, type TRet } from '@noble/hashes/utils.js';
import * as P from 'micro-packed';
import { resolveArtifactLimits, type ArtifactLimits } from './artifact-limits.js';
import {
  type CircuitInfo,
  type Constraint,
  type G1Point,
  type G2Point,
  type ProvingKey,
  type VerificationKey,
} from './index.ts';

/**
 * Checks if the provided value is object-like for option/schema bags.
 * This intentionally matches noble-curves and noble-hashes by using the
 * `[object Object]` tag instead of rejecting class/proxy/env objects by prototype;
 * stricter checks caused compatibility reports in proxied environments.
 * Array, Uint8Array and others are not plain objects.
 * @param obj - The value to be checked.
 */
function isPlainObject(obj: any): boolean {
  return Object.prototype.toString.call(obj) === '[object Object]';
}

function monkeyPatchBigInt() {
  const methods = {
    // Equality
    eq: (a: bigint, b: bigint) => a === b,
    neq: (a: bigint, b: bigint) => a !== b,
    greaterOrEquals: (a: bigint, b: bigint) => a >= b,
    greater: (a: bigint, b: bigint) => a > b,
    gt: (a: bigint, b: bigint) => a > b,
    lesserOrEquals: (a: bigint, b: bigint) => a <= b,
    lesser: (a: bigint, b: bigint) => a < b,
    lt: (a: bigint, b: bigint) => a < b,
    // Basic math
    sub: (a: bigint, b: bigint) => a - b,
    add: (a: bigint, b: bigint) => a + b,
    mul: (a: bigint, b: bigint) => a * b,
    div: (a: bigint, b: bigint) => a / b,
    mod: (a: bigint, b: any) => a % b,
    // Fields
    inverse: (n: bigint, modulo: bigint) => invert(n, modulo),
    modPow: (a: bigint, power: bigint, modulo: bigint) => pow(a, power, modulo),
    // Binary
    and: (a: bigint, b: bigint) => a & b,
    // Old circom serializes `<<` as `.shl(...)`, matching snarkjs v0.2.0's bigint shim.
    shl: (a: bigint, b: bigint) => a << BigInt(b),
    shr: (a: bigint, b: bigint) => a >> BigInt(b),
  };
  let patched = false;
  let orig: Record<string, PropertyDescriptor | undefined> = {};
  const proto = BigInt.prototype as any;
  const restoreOne = (name: string, desc: PropertyDescriptor | undefined) => {
    if (!desc) delete proto[name];
    else Object.defineProperty(proto, name, desc);
  };
  return {
    patch() {
      if (patched) throw new Error('bigint: already patched');
      const snap: Record<string, PropertyDescriptor | undefined> = {};
      for (const name in methods) {
        const desc = Object.getOwnPropertyDescriptor(proto, name);
        if (desc && !desc.configurable)
          throw new Error(`bigint: cannot patch non-configurable BigInt.prototype.${name}`);
        // Preserve descriptors: callers may have accessors or own undefined-valued properties here.
        snap[name] = desc;
      }
      try {
        for (const name in methods) {
          Object.defineProperty(proto, name, {
            configurable: true,
            enumerable: snap[name]?.enumerable || false,
            value: function (...args: any[]) {
              return (methods as any)[name](this, ...args);
            },
            writable: true,
          });
        }
      } catch (err) {
        for (const name in snap) restoreOne(name, snap[name]);
        throw err;
      }
      orig = snap;
      patched = true;
    },
    restore() {
      if (!patched) throw new Error('bigint: not patched');
      for (const name in methods) restoreOne(name, orig[name]);
      orig = {};
      patched = false;
    },
  };
}

const selectorStr = (lst: string[]) => lst.map((i) => `[${i}]`).join('');
const signalStr = (name: string, selectors: string[]) => name + selectorStr(selectors);
// Apply selectors
const select = (a: any, selectors: string[]): any => {
  for (const s of selectors) a = a[s];
  return a;
};
type Scope = Record<string, any>;
// Old circom can emit setPin/setSignal from templates and functions, including
// expression positions such as for headers. It can also emit nested function calls
// that trigger child components. Yielding those calls lets the scheduler
// trampoline recursive triggers before the caller continues.
const ctxYieldCall = /(^|[^\w$.])(ctx\.(?:callFunction|setPin|setSignal)\()/g;
const jsIgnored =
  /("(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])*'|`(?:\\[\s\S]|[^`\\])*`|\/\/[^\n\r]*(?:\r\n?|\n|$)|\/\*[\s\S]*?\*\/)/g;
const yieldCtxCalls = (src: string): string => {
  const code = (chunk: string): string => chunk.replace(ctxYieldCall, '$1yield $2');
  let out = '';
  let last = 0;
  for (const match of src.matchAll(jsIgnored)) {
    out += code(src.slice(last, match.index)) + match[0];
    last = match.index + match[0].length;
  }
  return out + code(src.slice(last));
};
const codeToGenerator = (src: string) =>
  yieldCtxCalls(src.replace(/function\s*\(\s*ctx\s*\)\s*\{/, 'function*(ctx) {'));
export const __TESTS: Readonly<{ yieldCtxCalls: (src: string) => string }> =
  /* @__PURE__ */ Object.freeze({
    yieldCtxCalls: yieldCtxCalls,
  });

/** Limits for the shape of an untrusted witness input value. */
export type WitnessInputLimits = {
  /** Maximum nested array depth. Defaults to 64. */
  maxDepth?: number;
  /**
   * Maximum roots, arrays, and scalar leaves traversed before rejection.
   * Defaults to `max(1024, circuit.nInputs * maxDepth)`.
   */
  maxNodes?: number;
};

/** Options for compiling a legacy circom-js circuit. */
export type GenerateWitnessOpts = {
  /**
   * Explicitly permits evaluating JavaScript embedded in the circuit artifact.
   * Only enable this for trusted circuits.
   */
  unsafeAllowJsEvalCircuit?: boolean;
  /** Override the default witness-input shape limits for exceptional trusted circuits. */
  inputLimits?: WitnessInputLimits;
};

/**
 * Builds a witness generator for a legacy circom-js circuit JSON.
 * The returned runner accepts each declared main input exactly once and rejects output or internal
 * signal names.
 * @param circJson - Circom circuit JSON artifact.
 * @param opts - Options controlling executable legacy circuit evaluation.
 * @returns Function that executes the circuit and returns the witness.
 * @throws Unless `unsafeAllowJsEvalCircuit` is explicitly enabled.
 * @example
 * Build a witness runner from a circom JSON circuit artifact.
 * ```ts
 * import { generateWitness } from 'micro-zk-proofs/witness.js';
 * // Addition circuit: witness output is one, a + b, b, a.
 * const circuitJson = {
 *   nVars: 4,
 *   nInputs: 2,
 *   nOutputs: 1,
 *   nSignals: 4,
 *   templates: {
 *     Main: `function(ctx) {
 *       ctx.setSignal(
 *         "out",
 *         [],
 *         bigInt(ctx.getSignal("a", [])).add(bigInt(ctx.getSignal("b", []))).mod(__P__)
 *       );
 *     }`,
 *   },
 *   functions: {},
 *   components: [{ name: 'main', params: {}, template: 'Main', inputSignals: 2 }],
 *   signals: [
 *     { names: ['one'], triggerComponents: [] },
 *     { names: ['main.out'], triggerComponents: [] },
 *     { names: ['main.b'], triggerComponents: [0] },
 *     { names: ['main.a'], triggerComponents: [0] },
 *   ],
 *   signalName2Idx: { one: 0, 'main.out': 1, 'main.b': 2, 'main.a': 3 },
 * };
 * const witness = generateWitness(circuitJson, { unsafeAllowJsEvalCircuit: true })({
 *   a: '33',
 *   b: '34',
 * });
 * // [1n, 67n, 34n, 33n]
 * ```
 */
export function generateWitness(
  circJson: any,
  opts: GenerateWitnessOpts = {}
): (input: any) => any {
  if (!isPlainObject(opts)) throw new TypeError('"opts" expected object, got type=' + typeof opts);
  if (opts.unsafeAllowJsEvalCircuit !== true)
    throw new Error(
      'legacy circuit JSON evaluates JavaScript; set unsafeAllowJsEvalCircuit: true only for trusted circuits'
    );
  const inputLimits = opts.inputLimits ?? {};
  if (!isPlainObject(inputLimits))
    throw new TypeError('"opts.inputLimits" expected object, got type=' + typeof inputLimits);
  const maxInputDepth = inputLimits.maxDepth ?? 64;
  if (!Number.isSafeInteger(maxInputDepth) || maxInputDepth < 0)
    throw new Error(
      `expected non-negative safe integer inputLimits.maxDepth, got ${maxInputDepth}`
    );
  if (!isPlainObject(circJson))
    throw new TypeError('"circJson" expected object, got type=' + typeof circJson);
  if (!Array.isArray(circJson.signals))
    throw new TypeError('"circJson.signals" expected array, got type=' + typeof circJson.signals);
  if (!Array.isArray(circJson.components))
    throw new TypeError(
      '"circJson.components" expected array, got type=' + typeof circJson.components
    );
  if (!isPlainObject(circJson.templates))
    throw new TypeError(
      '"circJson.templates" expected object, got type=' + typeof circJson.templates
    );
  if (!isPlainObject(circJson.functions))
    throw new TypeError(
      '"circJson.functions" expected object, got type=' + typeof circJson.functions
    );
  if (!Number.isSafeInteger(circJson.nInputs) || circJson.nInputs < 0)
    throw new Error(`expected non-negative safe integer circuit nInputs, got ${circJson.nInputs}`);
  const derivedInputNodes = circJson.nInputs * maxInputDepth;
  if (!Number.isSafeInteger(derivedInputNodes))
    throw new Error('default witness input node limit exceeds safe integer range');
  const maxInputNodes = inputLimits.maxNodes ?? Math.max(1024, derivedInputNodes);
  if (!Number.isSafeInteger(maxInputNodes) || maxInputNodes < 1)
    throw new Error(`expected positive safe integer inputLimits.maxNodes, got ${maxInputNodes}`);
  const P = nobleBn254.fields.Fr.ORDER;
  const MASK = bitMask(nobleBn254.fields.Fr.BITS);

  const signals = circJson.signals;
  const components = circJson.components;
  const templates: Record<string, Function> = {};
  // Bind P & MASK directly into templates/functions, so we see dependency
  for (let t in circJson.templates) {
    templates[t] = new Function(
      'bigInt',
      '__P__',
      '__MASK__',
      'return ' + codeToGenerator(circJson.templates[t])
    )(BigInt, P, MASK);
  }
  const functions: Record<string, { params: any[]; func: Function }> = {};
  for (let f in circJson.functions) {
    functions[f] = {
      params: circJson.functions[f].params,
      func: new Function(
        'bigInt',
        '__P__',
        '__MASK__',
        'return ' + codeToGenerator(circJson.functions[f].func)
      )(BigInt, P, MASK),
    };
  }
  function inputIdx(i: any) {
    if (i >= circJson.nInputs) throw new Error('Accessing an invalid input: ' + i);
    // Witness slot 0 is the constant one, so declared inputs start after the output slots.
    return circJson.nOutputs + 1 + i;
  }
  function getSignalIdx(name: any) {
    if (circJson.signalName2Idx[name] !== undefined) return circJson.signalName2Idx[name];
    // signalNames() also queries raw witness indices when building error messages.
    if (!isNaN(name)) return Number(name);
    throw new Error('Invalid signal identifier: ' + name);
  }
  const signalNames = (i: any) => signals[getSignalIdx(i)].names.join(', ');
  const patcher = monkeyPatchBigInt();

  return function (input: any): any {
    const firstInput = circJson.nOutputs + 1;
    const inputEnd = firstInput + circJson.nInputs;
    const assignedInputs = new Set<number>();
    const pendingInputs: { fullName: string; value: bigint }[] = [];
    const activeArrays = new WeakSet<any[]>();
    let inputNodes = 0;
    // Resolve and validate the complete input before executing components. Input aliases are
    // accepted only when they resolve to a declared main-input slot, and each slot is assigned once.
    for (const root of Object.keys(input)) {
      const selectors: string[] = [];
      const stack: {
        values: any;
        depth: number;
        entered: boolean;
        nextIndex: number;
        ownsSelector: boolean;
      }[] = [
        {
          values: input[root],
          depth: 0,
          entered: false,
          nextIndex: 0,
          ownsSelector: false,
        },
      ];
      const popFrame = () => {
        const frame = stack.pop()!;
        if (frame.ownsSelector) selectors.pop();
      };
      while (stack.length) {
        const frame = stack[stack.length - 1];
        if (!frame.entered) {
          frame.entered = true;
          inputNodes++;
          if (inputNodes > maxInputNodes)
            throw new Error(`Witness input exceeds configured node limit ${maxInputNodes}`);
          if (!Array.isArray(frame.values)) {
            if (frame.values === undefined) throw new Error('Signal not defined:' + root);
            const fullName = signalStr(`main.${root}`, selectors);
            let id: number;
            try {
              id = getSignalIdx(fullName);
            } catch {
              throw new Error(`Unknown input signal: ${fullName}`);
            }
            if (!Number.isSafeInteger(id) || id < firstInput || id >= inputEnd)
              throw new Error(`Unknown input signal: ${fullName}`);
            if (assignedInputs.has(id)) throw new Error(`Input assigned twice: ${fullName}`);
            assignedInputs.add(id);
            pendingInputs.push({ fullName, value: BigInt(frame.values) });
            popFrame();
            continue;
          }
          if (frame.depth >= maxInputDepth)
            throw new Error(`Witness input exceeds configured depth limit ${maxInputDepth}`);
          if (activeArrays.has(frame.values)) throw new Error('Cyclic witness input array');
          activeArrays.add(frame.values);
          if (frame.values.length > maxInputNodes - inputNodes)
            throw new Error(`Witness input exceeds configured node limit ${maxInputNodes}`);
        }
        if (frame.nextIndex >= frame.values.length) {
          activeArrays.delete(frame.values);
          popFrame();
          continue;
        }
        const index = frame.nextIndex++;
        if (!Object.hasOwn(frame.values, index)) throw new Error('Sparse witness input array');
        selectors.push(`${index}`);
        stack.push({
          values: frame.values[index],
          depth: frame.depth + 1,
          entered: false,
          nextIndex: 0,
          ownsSelector: true,
        });
      }
    }
    for (let i = 0; i < circJson.nInputs; i++) {
      const idx = inputIdx(i);
      if (!assignedInputs.has(idx))
        throw new Error('Input Signal not assigned: ' + signalNames(idx));
    }

    const witness = new Array(circJson.nSignals);
    let currentComponent: string | undefined;
    let scopes: Scope[] = []; // scope stack
    const notInitSignals = {} as any;
    const callFrameTag = Symbol('callFrame');
    // Ready component frames preserve old depth-first trigger order without growing
    // the JS call stack on long generated chains.
    const pendingComponents: any[] = [];
    type ExecFrame = {
      name: string | undefined;
      scope: Scope;
      iter: any;
      ready: any[];
      resume: any;
      hasResume: boolean;
      done: boolean;
      value: any;
      returnTo?: ExecFrame;
    };
    const execFrames: ExecFrame[] = [];
    let draining = false;
    let stepping = false;
    const isCallFrame = (value: any): value is { tag: typeof callFrameTag; frame: ExecFrame } =>
      value !== undefined && value.tag === callFrameTag;

    function triggerComponent(c: any) {
      notInitSignals[c]--;
      const oldComponent = currentComponent;
      currentComponent = components[c].name;
      const template = components[c].template;
      const newScope: any = {};
      for (let p in components[c].params) newScope[p] = components[c].params[p];
      execFrames.push({
        name: components[c].name,
        scope: newScope,
        iter: templates[template](ctx),
        ready: [],
        resume: undefined,
        hasResume: false,
        done: false,
        value: undefined,
      });
      currentComponent = oldComponent;
    }
    function activeReady() {
      return execFrames.length > 0 ? execFrames[execFrames.length - 1].ready : pendingComponents;
    }
    function removeQueued(c: any) {
      let pendingIdx = pendingComponents.indexOf(c);
      while (pendingIdx >= 0) {
        pendingComponents.splice(pendingIdx, 1);
        pendingIdx = pendingComponents.indexOf(c);
      }
      for (const frame of execFrames) {
        let idx = frame.ready.indexOf(c);
        while (idx >= 0) {
          frame.ready.splice(idx, 1);
          idx = frame.ready.indexOf(c);
        }
      }
    }
    function queueReady(c: any) {
      // A generated parent can re-trigger a component already queued by an input
      // alias. Old recursion runs it at the later trigger point, so move it there.
      removeQueued(c);
      activeReady().push(c);
    }
    function stepFrame() {
      const frame = execFrames[execFrames.length - 1];
      const oldComponent = currentComponent;
      const oldScope = scopes;
      const wasStepping = stepping;
      currentComponent = frame.name;
      scopes = [scopes[0], frame.scope];
      stepping = true;
      try {
        const res = frame.hasResume ? frame.iter.next(frame.resume) : frame.iter.next();
        frame.hasResume = false;
        if (!res.done) {
          if (isCallFrame(res.value)) {
            res.value.frame.returnTo = frame;
            execFrames.push(res.value.frame);
            return;
          }
          frame.resume = res.value;
          frame.hasResume = true;
          return;
        }
        frame.done = true;
        frame.value = res.value;
        execFrames.pop();
        if (frame.returnTo !== undefined) {
          frame.returnTo.resume = frame.value;
          frame.returnTo.hasResume = true;
        }
        if (frame.ready.length > 0) activeReady().unshift(...frame.ready);
      } finally {
        stepping = wasStepping;
        scopes = oldScope;
        currentComponent = oldComponent;
      }
    }
    function drainStep() {
      const ready = activeReady();
      if (ready.length == 0) return stepFrame();
      const c = ready.shift();
      if (notInitSignals[c] >= 0) triggerComponent(c);
    }
    function drainFrame(frame: (typeof execFrames)[number]) {
      while (!frame.done) drainStep();
      return frame.value;
    }
    // Process ready components until none remain in the active frame. The notInitSignals guard
    // (>= 0) skips duplicates: triggerComponent decrements to -1 on first call, so
    // any component pushed twice will be a no-op on the second dequeue.
    function drainPendingComponents(force = false) {
      if (stepping) return;
      if (draining && !force) return;
      const wasDraining = draining;
      draining = true;
      try {
        while (activeReady().length > 0 || execFrames.length > 0) drainStep();
      } finally {
        draining = wasDraining;
      }
    }
    function setSignalFullName(fullName: any, value: any) {
      const sId = getSignalIdx(fullName);
      let firstInit = false;
      if (witness[sId] === undefined) firstInit = true;
      witness[sId] = BigInt(value);
      const triggers = signals[sId].triggerComponents;
      for (let i = 0; i < signals[sId].triggerComponents.length; i++) {
        const idCmp = triggers[i];
        if (firstInit) notInitSignals[idCmp]--;
      }
      const seen = new Set();
      for (let i = 0; i < triggers.length; i++) {
        const c = triggers[i];
        // Old circom can alias many inputs of the same component to one signal,
        // producing duplicate trigger ids. Decrement every alias first, then
        // queue each ready component once in old first-trigger order; repeated
        // queueReady calls repeatedly scan queues and can move duplicates.
        if (notInitSignals[c] == 0 && !seen.has(c)) {
          seen.add(c);
          queueReady(c);
        }
      }
      if (!stepping) drainPendingComponents();
      return witness[sId];
    }
    function getSignalFullName(name: string) {
      const id = getSignalIdx(name);
      // Circom-generated code can make several components ready at once through
      // aliasing. Drain only when this read actually needs pending work; eager
      // drains can run a child before the current parent reaches an earlier write.
      if (witness[id] === undefined && activeReady().length > 0) drainPendingComponents(true);
      if (witness[id] === undefined) throw new Error('Signal not initialized: ' + name);
      return witness[id];
    }
    const cName = (name: string) => (name == 'one' ? 'one' : currentComponent + '.' + name);

    // Minimal API that used inside evaluated code
    const ctx = {
      // Pins
      setPin(compName: string, compSel: string[], sigName: string, sigSel: string[], value: any) {
        const name = signalStr(cName(compName), compSel) + '.' + signalStr(sigName, sigSel);
        setSignalFullName(name, value);
      },
      getPin(compName: string, componentSels: string[], sigName: string, sigSel: string[]) {
        const name = signalStr(cName(compName), componentSels) + '.' + signalStr(sigName, sigSel);
        return getSignalFullName(name);
      },
      // Vars
      setVar(name: string, sels: string[], value: any) {
        const scope = scopes[scopes.length - 1];
        if (sels.length == 0) {
          scope[name] = value;
        } else {
          if (scope[name] === undefined) scope[name] = [];
          let cur = scope[name];
          for (let i = 0; i < sels.length - 1; i++) {
            if (cur[sels[i]] === undefined) cur[sels[i]] = [];
            cur = cur[sels[i]];
          }
          cur[sels[sels.length - 1]] = value;
        }
        return value;
      },
      getVar(name: string, sels: string[]) {
        for (let i = scopes.length - 1; i >= 0; i--)
          if (scopes[i][name] !== undefined) return select(scopes[i][name], sels);
        throw new Error('Variable not defined: ' + name);
      },
      // Signals
      setSignal(name: string, sels: string[], value: any) {
        setSignalFullName(
          signalStr(currentComponent ? currentComponent + '.' + name : name, sels),
          value
        );
      },
      getSignal(name: string, sels: string[]) {
        return getSignalFullName(signalStr(cName(name), sels));
      },
      // Utils
      callFunction(name: string, params: any) {
        const newScope: Record<string, any> = {};
        for (let p = 0; p < functions[name].params.length; p++)
          newScope[functions[name].params[p]] = params[p];
        const frame = {
          name: currentComponent,
          scope: newScope,
          iter: functions[name].func(ctx),
          ready: [] as any[],
          resume: undefined,
          hasResume: false,
          done: false,
          value: undefined,
        };
        if (stepping) return { tag: callFrameTag, frame };
        execFrames.push(frame);
        return drainFrame(frame);
      },
      assert(a: any, b: any, errStr: string = '') {
        a = BigInt(a);
        b = BigInt(b);
        if (a === b) return;
        throw new Error(`Constraint doesn't match ${currentComponent}: ${errStr} -> ${a} != ${b}`);
      },
    };
    patcher.patch();
    try {
      // Processing
      for (const c in components) notInitSignals[c] = components[c].inputSignals;
      ctx.setSignal('one', [], BigInt(1));
      // Queue all components that are already fully initialised (zero remaining inputs)
      // and drain the queue iteratively rather than triggering them inline. This avoids
      // a call-stack overflow when complex circuits have long inter-template chains.
      for (let c in notInitSignals) if (notInitSignals[c] == 0) queueReady(c);
      drainPendingComponents();
      currentComponent = 'main';
      for (const assignment of pendingInputs)
        setSignalFullName(assignment.fullName, assignment.value);
      for (let i = 0; i < witness.length; i++)
        if (witness[i] === undefined) throw new Error('Signal not assigned: ' + signalNames(i));

      return witness.slice(0, circJson.nVars);
    } finally {
      patcher.restore();
    }
  };
}

/** Binary coder type for `.r1cs` files. */
export type R1CSType = P.CoderType<
  P.StructInput<{
    magic: undefined;
    version: number;
    sections: P.Values<{
      header: {
        TAG: 'header';
        data: P.StructInput<{
          prime: /*elided*/ any;
          nWires: /*elided*/ any;
          nPubOut: /*elided*/ any;
          nPubIn: /*elided*/ any;
          nPrvIn: /*elided*/ any;
          nLables: /*elided*/ any;
          mConstraints: /*elided*/ any;
        }>;
      };
      constraint: {
        TAG: 'constraint';
        data: [Constraint, Constraint, Constraint][];
      };
      wire2label: {
        TAG: 'wire2label';
        data: bigint[];
      };
      customGatesList: {
        TAG: 'customGatesList';
        data: P.Bytes;
      };
      customGatesApplication: {
        TAG: 'customGatesApplication';
        data: P.Bytes;
      };
    }>[];
  }>
>;

/** Binary coder type for `.wtns` files. */
export type WTNSType = P.CoderType<
  P.StructInput<{
    magic: undefined;
    version: number;
    sections: P.Values<{
      header: {
        TAG: 'header';
        data: P.StructInput<{
          prime: /*elided*/ any;
          size: /*elided*/ any;
        }>;
      };
      witness: {
        TAG: 'witness';
        data: bigint[];
      };
    }>[];
  }>
>;

type CodersOutput = {
  R1CS: R1CSType;
  binWitness: P.CoderType<bigint[]>;
  WTNS: WTNSType;
  getCircuitInfo: (bytes: Uint8Array) => CircuitInfo;
  ZKeyRaw: P.CoderType<any>;
  parseZKey: (bytes: Uint8Array) => { json: any; pkey: ProvingKey; vkey: VerificationKey };
};

/**
 * Binary coders and parsers for Circom2 artifacts.
 * @param curve - Curve pair used for field sizing and point decoding.
 * @param artifactLimits - Optional resource limits checked before metadata-driven allocations.
 * @returns R1CS, witness, and zkey coders plus parse helpers.
 * @example
 * Build the coders once, then use them to parse and encode Circom2 artifacts.
 * ```ts
 * const { bn254 } = await import('@noble/curves/bn254.js');
 * const coders = getCoders(bn254);
 * const bytes = coders.binWitness.encode([1n, 2n]);
 * coders.binWitness.decode(bytes);
 * ```
 */
export const getCoders = (
  curve: BLSCurvePair,
  artifactLimits: ArtifactLimits = {}
): TRet<CodersOutput> => {
  if (!isPlainObject(curve))
    throw new TypeError('"curve" expected curve object, got type=' + typeof curve);
  if (!isPlainObject(curve.fields))
    throw new TypeError('"curve.fields" expected object, got type=' + typeof curve.fields);
  if (!isPlainObject(curve.fields.Fr))
    throw new TypeError('"curve.fields.Fr" expected object, got type=' + typeof curve.fields.Fr);
  const limits = resolveArtifactLimits(artifactLimits);
  const field = curve.fields.Fr;
  let fieldRootBits = 0;
  for (let n = field.ORDER - BigInt(1); (n & BigInt(1)) === BigInt(0); n >>= BigInt(1))
    fieldRootBits++;
  // NOTE: we need to pass field here, even if bigints are variable size, they are fixed to field bytes!
  const fieldBytes = field.BYTES;
  const fieldCoder = P.bigint(fieldBytes, true, false);
  const Header = P.struct({
    prime: P.prefix(P.U32LE, fieldCoder), // TODO: verify that exactly same as field.ORDER?
    nWires: P.U32LE, // Total Number of wires including ONE signal (Index 0).
    nPubOut: P.U32LE, // Total Number of wires public output wires. They should be starting at idx 1
    nPubIn: P.U32LE, // Total Number of wires public input wires. They should be starting just after the public output
    nPrvIn: P.U32LE, // Total Number of wires private input wires. They should be starting just after the public inputs
    nLables: P.U64LE, // Total Number of wires private input wires. They should be starting just after the public inputs
    mConstraints: P.U32LE, // Total Number of constraints
  });
  type ConstraintPair = [number, bigint];
  const constraintDict = {
    encode: (from: ConstraintPair[]): Constraint => {
      if (!Array.isArray(from)) throw new Error('array expected');
      const to: Constraint = {};
      for (const item of from) {
        if (!Array.isArray(item) || item.length !== 2)
          throw new Error(`array of two elements expected`);
        const [key, value] = item;
        if (Object.prototype.hasOwnProperty.call(to, key))
          throw new Error(`key(${key}) appears twice in constraint`);
        to[key] = value;
      }
      return to;
    },
    decode: (to: Constraint): ConstraintPair[] => {
      if (to === null || typeof to !== 'object' || Array.isArray(to))
        throw new Error(`expected constraint object, got ${to}`);
      return Object.entries(to).map(([key, value]): ConstraintPair => {
        // Object.entries() stringifies numeric R1CS signal ids; U32LE needs the number back.
        if (!/^(0|[1-9][0-9]*)$/.test(key))
          throw new Error(`expected uint32 constraint key, got ${key}`);
        const n = Number(key);
        if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff)
          throw new Error(`expected uint32 constraint key, got ${key}`);
        return [n, value];
      });
    },
  };
  const Constraint: P.CoderType<Constraint> = P.apply(
    P.array(P.U32LE, P.tuple([P.U32LE, fieldCoder])),
    constraintDict
  );
  // A*B-C = 0
  const Constraints: P.CoderType<[Constraint, Constraint, Constraint][]> = P.array(
    null,
    P.tuple([Constraint, Constraint, Constraint])
  );
  const WireMap = P.array(null, P.U64LE);
  // prefix() emits JS byte lengths, while Circom section headers serialize them as u64.
  const sectionLen = P.apply(P.U64LE, P.coders.numberBigint);
  const section = <T>(inner: P.CoderType<T>) => P.prefix(sectionLen, inner);
  const empty = P.bytes(null);
  const R1CSSection = P.mappedTag(P.U32LE, {
    header: [0x01, section(Header)],
    constraint: [0x02, section(Constraints)],
    wire2label: [0x03, section(WireMap)],
    // not implemented: ultra-plonk
    customGatesList: [0x04, section(empty)],
    customGatesApplication: [0x05, section(empty)],
  });
  const R1CS = P.struct({
    magic: P.magic(P.string(4), 'r1cs'),
    version: P.U32LE,
    sections: P.array(P.U32LE, R1CSSection),
  });
  const binWitness = P.array(null, fieldCoder);
  const WTNSHeader = P.struct({
    prime: P.prefix(P.U32LE, fieldCoder),
    size: P.U32LE,
  });
  const WTNSSection = P.mappedTag(P.U32LE, {
    header: [0x01, section(WTNSHeader)],
    witness: [0x02, section(P.array(null, fieldCoder))],
  });
  const WTNS = P.struct({
    magic: P.magic(P.string(4), 'wtns'),
    version: P.U32LE,
    sections: P.array(P.U32LE, WTNSSection),
  });
  const G1 = P.tuple([fieldCoder, fieldCoder]);
  const G2 = P.tuple([fieldCoder, fieldCoder, fieldCoder, fieldCoder]);
  const ZKeyHeader = P.map(P.U32LE, {
    groth16: 1,
  });
  const ZKeyHeaderGroth = P.struct({
    n8q: P.U32LE,
    q: fieldCoder,
    n8r: P.U32LE,
    r: fieldCoder,
    nVars: P.U32LE,
    nPublic: P.U32LE,
    domainSize: P.U32LE,
    vk_alpha_1: G1,
    vk_beta_1: G1,
    vk_beta_2: G2,
    vk_gamma_2: G2,
    vk_delta_1: G1,
    vk_delta_2: G2,
  });
  const ZKeyCoeff = P.struct({
    matrix: P.U32LE,
    constraint: P.U32LE,
    signal: P.U32LE,
    value: fieldCoder,
  });
  const ZKeySection = P.mappedTag(P.U32LE, {
    header: [1, section(ZKeyHeader)],
    headerGroth: [2, section(ZKeyHeaderGroth)],
    IC: [3, section(P.array(null, G1))],
    ccoefs: [4, section(P.array(P.U32LE, ZKeyCoeff))],
    A: [5, section(P.array(null, G1))],
    B1: [6, section(P.array(null, G1))],
    B2: [7, section(P.array(null, G2))],
    C: [8, section(P.array(null, G1))],
    hExps: [9, section(P.array(null, G1))],
    Contributions: [10, section(P.bytes(null))],
  });
  const ZKeyRaw = P.struct({
    magic: P.magic(P.string(4), 'zkey'),
    version: P.U32LE,
    sections: P.array(P.U32LE, ZKeySection),
  });

  const collectUniqueSections = (
    format: string,
    sections: { TAG: string; data: unknown }[],
    required: readonly string[]
  ): Record<string, any> => {
    const out: Record<string, any> = Object.create(null);
    for (const section of sections) {
      if (Object.prototype.hasOwnProperty.call(out, section.TAG))
        throw new Error(`${format}: duplicate ${section.TAG} section`);
      out[section.TAG] = section.data;
    }
    for (const tag of required) {
      if (!Object.prototype.hasOwnProperty.call(out, tag))
        throw new Error(`${format}: cannot find ${tag}`);
    }
    return out;
  };
  const checkArtifactSize = (bytes: Uint8Array, format: string) => {
    if (bytes.length > limits.maxBytes)
      throw new Error(
        `${format} exceeds configured byte limit ${limits.maxBytes}: ${bytes.length}`
      );
  };
  const checkMetadataLimit = (value: number, limit: number, name: string) => {
    if (value > limit) throw new Error(`${name} exceeds configured limit ${limit}: ${value}`);
  };

  const getCircuitInfo = (bytes: TArg<Uint8Array>): CircuitInfo => {
    bytes = abytes(bytes, undefined, 'bytes');
    checkArtifactSize(bytes, 'R1CS');
    const data = R1CS.decode(bytes);
    if (data.version !== 1) throw new Error(`R1CS: unsupported version ${data.version}`);
    const sections = collectUniqueSections('R1CS', data.sections, [
      'header',
      'constraint',
      'wire2label',
    ]);
    const header = sections.header;
    const constraints = sections.constraint as [Constraint, Constraint, Constraint][];
    const wire2label = sections.wire2label as bigint[];
    if (header.prime !== field.ORDER) throw new Error('R1CS: wrong field order');
    if (header.nWires < 1) throw new Error(`R1CS: invalid wire count ${header.nWires}`);
    checkMetadataLimit(header.nWires, limits.maxVariables, 'R1CS wire count');
    checkMetadataLimit(constraints.length, limits.maxConstraints, 'R1CS constraint count');
    if (header.mConstraints !== constraints.length)
      throw new Error(
        `R1CS: expected ${header.mConstraints} constraints, got ${constraints.length}`
      );
    if (wire2label.length !== header.nWires)
      throw new Error(`R1CS: expected ${header.nWires} wire labels, got ${wire2label.length}`);
    if (header.nLables < BigInt(header.nWires))
      throw new Error(`R1CS: label count is smaller than wire count`);
    const declaredSignals = 1 + header.nPubOut + header.nPubIn + header.nPrvIn;
    if (!Number.isSafeInteger(declaredSignals) || declaredSignals > header.nWires)
      throw new Error(`R1CS: public/private signal counts exceed wire count`);
    const domainRows = constraints.length + header.nPubOut + header.nPubIn;
    if (domainRows < 1) throw new Error('R1CS: cannot derive domain from an empty circuit');
    const domainBits = Math.floor(Math.log2(domainRows)) + 1;
    if (domainBits > fieldRootBits) throw new Error('R1CS: domain exceeds field root capacity');
    checkMetadataLimit(2 ** domainBits, limits.maxDomainSize, 'R1CS domainSize');
    for (let row = 0; row < constraints.length; row++) {
      for (const side of constraints[row]) {
        for (const key of Object.keys(side)) {
          if (Number(key) >= header.nWires)
            throw new Error(`R1CS: constraint ${row} wire index out of range: ${key}`);
        }
      }
    }
    for (const tag of ['customGatesList', 'customGatesApplication']) {
      const custom = sections[tag] as Uint8Array | undefined;
      if (custom && custom.length !== 0)
        throw new Error(`R1CS: unsupported nonempty ${tag} section`);
    }
    return {
      nVars: header.nWires,
      nPubInputs: header.nPubIn,
      nOutputs: header.nPubOut,
      constraints,
    };
  };
  function parseZKey(zkey: TArg<Uint8Array>) {
    zkey = abytes(zkey, undefined, 'zkey');
    checkArtifactSize(zkey, 'ZKey');
    const { Fr, Fp } = curve.fields;
    // Montgomery encoding of field elements
    const fieldFromMont = (f: IField<bigint>, is1: boolean) => {
      const Rr = f.pow(BigInt(2), BigInt(f.BYTES * 8));
      const RRi = f.inv(Rr);
      const RRi2 = f.mul(RRi, RRi);
      // G1/G2 coordinates carry one Montgomery factor; coefficient field elements need two.
      return (x: bigint) => f.mul(x, is1 ? RRi : RRi2);
    };
    const is0 = (x: bigint) => x === BigInt(0);
    const convFr2 = fieldFromMont(Fr, false);
    const convFp = fieldFromMont(Fp, true);
    const convG1 = ([x, y]: bigint[]): G1Point =>
      is0(x) && is0(y) ? [BigInt(0), BigInt(1), BigInt(0)] : [convFp(x), convFp(y), BigInt(1)];

    //     [ [ 0n, 0n ], [ 0n, 0n ], [ 1n, 0n ] ], ->     [ [ 0n, 0n ], [ 1n, 0n ], [ 0n, 0n ] ],
    const convG2 = ([xc0, xc1, yc0, yc1]: bigint[]): G2Point =>
      is0(xc0) && is0(xc1) && is0(yc0) && is0(yc1)
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
    const data = ZKeyRaw.decode(zkey);
    if (data.version !== 1) throw new Error(`ZKey: unsupported version ${data.version}`);
    const res = collectUniqueSections('ZKey', data.sections, [
      'header',
      'headerGroth',
      'IC',
      'ccoefs',
      'A',
      'B1',
      'B2',
      'C',
      'hExps',
    ]);
    const header = res.headerGroth;
    if (res.header !== 'groth16') throw new Error(`ZKey: unsupported protocol ${res.header}`);
    if (
      header.n8q !== Fp.BYTES ||
      header.q !== Fp.ORDER ||
      header.n8r !== Fr.BYTES ||
      header.r !== Fr.ORDER
    )
      throw new Error('ZKey: field mismatch');
    if (header.nVars < 1 || header.nPublic >= header.nVars)
      throw new Error(`ZKey: invalid variable/public counts`);
    checkMetadataLimit(header.nVars, limits.maxVariables, 'ZKey variable count');
    const domainBits = Math.log2(header.domainSize);
    if (!Number.isInteger(domainBits))
      throw new Error(`ZKey: domainSize must be a power of two, got ${header.domainSize}`);
    if (domainBits > fieldRootBits) throw new Error(`ZKey: domainSize exceeds field root capacity`);
    checkMetadataLimit(header.domainSize, limits.maxDomainSize, 'ZKey domainSize');
    const checkLength = (value: unknown, expected: number, name: string) => {
      if (!Array.isArray(value) || value.length !== expected)
        throw new Error(
          `ZKey: expected ${name}.length === ${expected}, got ${Array.isArray(value) ? value.length : 'non-array'}`
        );
    };
    checkLength(res.IC, header.nPublic + 1, 'IC');
    checkLength(res.A, header.nVars, 'A');
    checkLength(res.B1, header.nVars, 'B1');
    checkLength(res.B2, header.nVars, 'B2');
    checkLength(res.C, header.nVars - header.nPublic - 1, 'C');
    checkLength(res.hExps, header.domainSize, 'hExps');
    if (!Array.isArray(res.ccoefs)) throw new Error('ZKey: expected ccoefs array');
    for (const coefficient of res.ccoefs) {
      if (
        coefficient.matrix > 2 ||
        coefficient.constraint >= header.domainSize ||
        coefficient.signal >= header.nVars
      )
        throw new Error('ZKey: invalid coefficient index');
    }
    // Same format as verification key
    const json = {
      protocol: res.header,
      ...header,
      vk_alpha_1: convG1(header.vk_alpha_1),
      vk_beta_1: convG1(header.vk_beta_1),
      vk_delta_1: convG1(header.vk_delta_1),
      vk_beta_2: convG2(header.vk_beta_2),
      vk_delta_2: convG2(header.vk_delta_2),
      vk_gamma_2: convG2(header.vk_gamma_2),
      power: domainBits,
      IC: res.IC.map(convG1),
      ccoefs: res.ccoefs.map((i) => ({ ...i, value: convFr2(i.value) })),
      A: res.A.map(convG1),
      B1: res.B1.map(convG1),
      B2: res.B2.map(convG2),
      // snarkjs zkeys omit the leading zero C-query entries for public signals.
      C: new Array(header.nPublic + 1).fill(null).concat(res.C.map(convG1)),
      hExps: res.hExps.map(convG1),
    };
    // Our format (old snarkjs compat)
    const pkey: ProvingKey = {
      protocol: 'groth',
      nVars: json.nVars,
      nPublic: json.nPublic,
      domainSize: json.domainSize,
      domainBits: json.power,
      // Polynominals (instead polsA/polsB/polsC)
      ccoefs: json.ccoefs, // changed
      //
      A: json.A,
      B1: json.B1,
      B2: json.B2,
      C: json.C,
      //
      vk_alfa_1: json.vk_alpha_1,
      vk_beta_1: json.vk_beta_1,
      vk_delta_1: json.vk_delta_1,
      vk_beta_2: json.vk_beta_2,
      vk_delta_2: json.vk_delta_2,
      //
      hExps: json.hExps,
    };
    const vkey: VerificationKey = {
      protocol: 'groth',
      nPublic: json.nPublic,
      IC: json.IC,
      vk_alfa_1: json.vk_alpha_1,
      vk_beta_2: json.vk_beta_2,
      vk_gamma_2: json.vk_gamma_2,
      vk_delta_2: json.vk_delta_2,
    };
    return { json, pkey, vkey };
  }

  return { R1CS, binWitness, WTNS, getCircuitInfo, ZKeyRaw, parseZKey } as TRet<CodersOutput>;
};
