/**
 * The code is only used if you plan to run **legacy circom-js programs**. It is unused in WASM.
 * Minimal witness program executor for circom programs, based on websnark/wasmsnark/snarkjs.
 * Unsafe: it uses eval, better to be used inside worker threads.
 * Depends on **monkey-patched BigInt** prototypes due to how circom programs are serialized.
 * We only patch prototypes before execution. After finishing, patches are reverted.
 * @module
 */

import { invert, pow, type IField } from '@noble/curves/abstract/modular';
import { bn254 as nobleBn254 } from '@noble/curves/bn254';
import * as P from 'micro-packed';
import { type CircuitInfo, type Constraint } from './index.ts';

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
    shr: (a: bigint, b: bigint) => a >> BigInt(b),
  };
  let patched = false;
  let orig: Record<string, Function> = {};
  const proto = BigInt.prototype as any;
  return {
    patch() {
      if (patched) throw new Error('bigint: already patched');
      for (const name in methods) {
        orig[name] = proto[name];
        proto[name] = function (...args: any[]) {
          return (methods as any)[name](this, ...args);
        };
      }
      patched = true;
    },
    restore() {
      if (!patched) throw new Error('bigint: not patched');
      for (const name in methods) {
        if (orig[name] === undefined) delete proto[name];
        else proto[name] = orig[name];
      }
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
export function generateWitness(circJson: any): (input: any) => any {
  const P = nobleBn254.fields.Fr.ORDER;
  const MASK = nobleBn254.fields.Fr.MASK;

  const signals = circJson.signals;
  const components = circJson.components;
  const templates: Record<string, Function> = {};
  // Bind P & MASK directly into templates/functions, so we see dependency
  for (let t in circJson.templates) {
    templates[t] = new Function('bigInt', '__P__', '__MASK__', 'return ' + circJson.templates[t])(
      BigInt,
      P,
      MASK
    );
  }
  const functions: Record<string, { params: any[]; func: Function }> = {};
  for (let f in circJson.functions) {
    functions[f] = {
      params: circJson.functions[f].params,
      func: new Function('bigInt', '__P__', '__MASK__', 'return ' + circJson.functions[f].func)(
        BigInt,
        P,
        MASK
      ),
    };
  }
  function inputIdx(i: any) {
    if (i >= circJson.nInputs) throw new Error('Accessing an invalid input: ' + i);
    return circJson.nOutputs + 1 + i;
  }
  function getSignalIdx(name: any) {
    if (circJson.signalName2Idx[name] !== undefined) return circJson.signalName2Idx[name];
    if (!isNaN(name)) return Number(name);
    throw new Error('Invalid signal identifier: ' + name);
  }
  const signalNames = (i: any) => signals[getSignalIdx(i)].names.join(', ');
  const patcher = monkeyPatchBigInt();

  return function (input: any): any {
    patcher.patch();
    const witness = new Array(circJson.nSignals);
    let currentComponent: string | undefined;
    let scopes: Scope[] = []; // scope stack
    const notInitSignals = {} as any;

    function inScope(newScope: Scope, cb: Function) {
      const oldScope = scopes;
      scopes = [scopes[0], newScope];
      const res = cb();
      scopes = oldScope;
      return res;
    }

    function triggerComponent(c: any) {
      notInitSignals[c]--;
      const oldComponent = currentComponent;
      currentComponent = components[c].name;
      const template = components[c].template;
      const newScope: any = {};
      for (let p in components[c].params) newScope[p] = components[c].params[p];
      inScope(newScope, () => templates[template](ctx));
      currentComponent = oldComponent;
    }
    function setSignalFullName(fullName: any, value: any) {
      const sId = getSignalIdx(fullName);
      let firstInit = false;
      if (witness[sId] === undefined) firstInit = true;
      witness[sId] = BigInt(value);
      const callComponents = [];
      for (let i = 0; i < signals[sId].triggerComponents.length; i++) {
        var idCmp = signals[sId].triggerComponents[i];
        if (firstInit) notInitSignals[idCmp]--;
        callComponents.push(idCmp);
      }
      callComponents.map((c) => {
        if (notInitSignals[c] == 0) triggerComponent(c);
      });
      return witness[sId];
    }
    function getSignalFullName(name: string) {
      const id = getSignalIdx(name);
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
          // TODO: replace with iterative version
          function setVarArray(a: any, sels2: any, value: any) {
            if (sels2.length == 1) {
              a[sels2[0]] = value;
            } else {
              if (a[sels2[0]] === undefined) a[sels2[0]] = [];
              setVarArray(a[sels2[0]], sels2.slice(1), value);
            }
          }
          setVarArray(scope[name], sels, value);
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
        return inScope(newScope, () => functions[name].func(ctx));
      },
      assert(a: any, b: any, errStr: string = '') {
        a = BigInt(a);
        b = BigInt(b);
        if (a === b) return;
        throw new Error(`Constraint doesn't match ${currentComponent}: ${errStr} -> ${a} != ${b}`);
      },
    };
    // Processing
    for (const c in components) notInitSignals[c] = components[c].inputSignals;
    ctx.setSignal('one', [], BigInt(1));
    for (let c in notInitSignals) if (notInitSignals[c] == 0) triggerComponent(c);
    for (let s in input) {
      currentComponent = 'main';
      // Recursively iterates program and with scope stack
      function iterate(values: any, selectors: any, cb: (selector: string[], value: any) => void) {
        if (!Array.isArray(values)) return cb(selectors, values);
        for (let i = 0; i < values.length; i++) iterate(values[i], [...selectors, i], cb);
      }
      iterate(input[s], [], (selector, value) => {
        if (value === undefined) throw new Error('Signal not defined:' + s);
        ctx.setSignal(s, selector, BigInt(value));
      });
    }
    for (let i = 0; i < circJson.nInputs; i++) {
      const idx = inputIdx(i);
      if (witness[idx] === undefined)
        throw new Error('Input Signal not assigned: ' + signalNames(idx));
    }
    for (let i = 0; i < witness.length; i++)
      if (witness[i] === undefined) throw new Error('Signal not assigned: ' + signalNames(i));

    patcher.restore();
    return witness.slice(0, circJson.nVars);
  };
}

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

/** Binary coders for Circom2 */
export const getCoders = (
  field: IField<bigint>
): {
  R1CS: R1CSType;
  binWitness: P.CoderType<bigint[]>;
  WTNS: WTNSType;
  getCircuitInfo: (bytes: Uint8Array) => CircuitInfo;
} => {
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
  const Constraint: P.CoderType<Constraint> = P.apply(
    P.array(P.U32LE, P.tuple([P.U32LE, fieldCoder])),
    P.coders.dict() as any // TODO: dict key is string, not number
  );
  // A*B-C = 0
  const Constraints: P.CoderType<[Constraint, Constraint, Constraint][]> = P.array(
    null,
    P.tuple([Constraint, Constraint, Constraint])
  );
  const WireMap = P.array(null, P.U64LE);
  const section = <T>(inner: P.CoderType<T>) => P.prefix(P.U64LE, inner);
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

  const getCircuitInfo = (bytes: Uint8Array): CircuitInfo => {
    const data = R1CS.decode(bytes);
    const constraints = data.sections.find((i) => i.TAG === 'constraint');
    if (!constraints) throw new Error('R1CS: cannot find constraints');
    const header = data.sections.find((i) => i.TAG === 'header');
    if (!header) throw new Error('R1CS: cannot find header');
    if (header.data.prime !== field.ORDER) throw new Error('R1CS: wrong field order');
    return {
      nVars: header.data.nWires,
      nPubInputs: header.data.nPubIn,
      nOutputs: header.data.nPubOut,
      constraints: constraints.data,
    };
  };
  return { R1CS, binWitness, WTNS, getCircuitInfo };
};
