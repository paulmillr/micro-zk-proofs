/**
 * Builds a synthetic circom-js circuit JSON that chains N "relay" components in series:
 *
 *   user input  →  main.c0  →  main.c1  →  …  →  main.c(N-1)  →  output
 *
 * Each component reads its `in` signal and immediately writes the same value to its
 * `out` signal.  Adjacent components share a signal slot, so c(i).out and c(i+1).in
 * are the same witness entry — setting it decrements c(i+1)'s uninitialized-input
 * counter and, when that counter reaches zero, marks c(i+1) as ready to execute.
 *
 * Without the queue-based fix in generateWitness this produces a call stack N frames
 * deep (triggerComponent → template → setSignal → triggerComponent → …), which
 * overflows the JS engine for large N.  With the fix every component after the first
 * is deferred to pendingComponents and processed iteratively.
 *
 * Signal slot layout
 * ------------------
 *  0          : "one"                           (constant 1)
 *  1          : "main.out" / "main.c(N-1).out" (final output, written by last relay)
 *  2          : "main.in"  / "main.c0.in"      (user-supplied input)
 *  3..N+1     : shared intermediate slots c(i).out = c(i+1).in  for i = 0..N-2
 */
export function buildDeepChainCircuit(n) {
  if (n < 1) throw new RangeError('n must be >= 1');

  // ── signals ──────────────────────────────────────────────────────────────────
  // Slot 0: constant one
  const signals = [{ names: ['one'], triggerComponents: [] }];

  // Slot 1: final output (shared name with c(N-1).out so the Relay template that
  // executes as "main.c(N-1)" can reach it via ctx.setSignal("out", []))
  signals.push({ names: ['main.out', `main.c${n - 1}.out`], triggerComponents: [] });

  // Slot 2: user input (shared with c0.in so getSignal("in") inside c0 resolves here)
  signals.push({ names: ['main.in', 'main.c0.in'], triggerComponents: [0] });

  // Slots 3..N+1: one shared slot per adjacent pair c(i).out / c(i+1).in
  for (let i = 0; i < n - 1; i++) {
    signals.push({
      names: [`main.c${i}.out`, `main.c${i + 1}.in`],
      // Setting this slot means c(i+1) has received its only input → ready to run
      triggerComponents: [i + 1],
    });
  }

  // ── signalName2Idx ────────────────────────────────────────────────────────────
  const signalName2Idx = {};
  for (let s = 0; s < signals.length; s++) {
    for (const name of signals[s].names) signalName2Idx[name] = s;
  }

  // ── components ───────────────────────────────────────────────────────────────
  const components = [];
  for (let i = 0; i < n; i++) {
    components.push({ name: `main.c${i}`, template: 'Relay', inputSignals: 1, params: {} });
  }

  // ── template ─────────────────────────────────────────────────────────────────
  // The Relay template passes its single input through to its output unchanged.
  // getSignal("in") resolves to `currentComponent + ".in"` (e.g. "main.c0.in"),
  // setSignal("out") resolves to `currentComponent + ".out"` (e.g. "main.c0.out").
  const templates = {
    Relay: `function(ctx) {
      ctx.setSignal("out", [], ctx.getSignal("in", []));
    }`,
  };

  return {
    nVars: n + 2, // one slot per signal
    nInputs: 1, // only "in"
    nOutputs: 1, // only "out" (slot 1, checked by generateWitness after inputIdx)
    nSignals: n + 2,
    signals,
    components,
    templates,
    functions: {},
    signalName2Idx,
  };
}

/**
 * Builds the same legacy JSON shape circom 0.0.35 emits for a nested direct-child
 * pass-through chain generated from:
 *
 *   template T_i() {
 *     signal input in;
 *     signal output out;
 *     component child = T_{i+1}();
 *     child.in <== in;
 *     child.out ==> out;
 *   }
 *
 * The old compiler aliases every nested child input/output with main.in in one
 * signal slot. That slot triggers every component, and direct-child execution
 * recurses through the hierarchy.
 */
export function buildNestedDirectChildCircuit(n) {
  if (n < 1) throw new RangeError('n must be >= 1');

  const signals = [
    { names: ['one'], triggerComponents: [] },
    { names: ['main.out'], triggerComponents: [] },
    { names: ['main.in'], triggerComponents: [] },
  ];
  const components = [{ name: 'main', template: 'T0', inputSignals: 1, params: {} }];
  const templates = {
    Leaf: `function(ctx) {
      ctx.setSignal("out", [], ctx.getSignal("in", []));
    }`,
  };

  let name = 'main';
  for (let i = 0; i < n; i++) {
    signals[2].names.push(`${name}.child.in`, `${name}.child.out`);
    signals[2].triggerComponents.push(i);
    templates[`T${i}`] = `function(ctx) {
      ctx.setPin("child", [], "in", [], ctx.getSignal("in", []));
      ctx.setSignal("out", [], ctx.getPin("child", [], "out", []));
    }`;
    name += '.child';
    if (i < n - 1) components.push({ name, template: `T${i + 1}`, inputSignals: 1, params: {} });
  }
  components.push({ name, template: 'Leaf', inputSignals: 1, params: {} });
  signals[2].triggerComponents.push(n);

  const signalName2Idx = {};
  for (let s = 0; s < signals.length; s++) {
    for (const sig of signals[s].names) signalName2Idx[sig] = s;
  }

  return {
    nVars: 3,
    nInputs: 1,
    nOutputs: 1,
    nSignals: 3,
    signals,
    components,
    templates,
    functions: {},
    signalName2Idx,
  };
}

/**
 * Builds the legacy JSON shape circom 0.0.35 emits when a generated function writes
 * a signal that is later aliased into a nested child input:
 *
 *   function setChild(v) {
 *     signal output childIn;
 *     childIn <== v;
 *     return v;
 *   }
 *
 *   template T_i() {
 *     signal input in;
 *     signal output out;
 *     signal childIn;
 *     component child = T_{i+1}();
 *     var x;
 *     x = setChild(in);
 *     out <== in;
 *     child.out ==> out;
 *     childIn ==> child.in;
 *   }
 *
 * The function call triggers the child before the parent template can continue.
 * A scheduler that drains function-triggered children from inside the caller's
 * generator step can still build a deep JS call stack even if template-level
 * setPin/setSignal statements are trampolined.
 */
export function buildFunctionTriggeredChildCircuit(n) {
  if (n < 1) throw new RangeError('n must be >= 1');

  const names = ['main'];
  for (let i = 1; i <= n; i++) names.push(`${names[i - 1]}.child`);

  const signals = [
    { names: ['one'], triggerComponents: [] },
    { names: names.map((name) => `${name}.out`), triggerComponents: [] },
  ];
  for (let i = 0; i < n; i++) {
    signals.push({
      names: [`${names[i]}.childIn`, `${names[i + 1]}.in`],
      triggerComponents: [i + 1],
    });
  }
  signals.push({ names: ['main.in'], triggerComponents: [0] });

  const signalName2Idx = {};
  for (let s = 0; s < signals.length; s++) {
    for (const sig of signals[s].names) signalName2Idx[sig] = s;
  }

  const components = [];
  for (let i = 0; i <= n; i++) {
    components.push({
      name: names[i],
      template: i === n ? 'Leaf' : `T${i}`,
      inputSignals: 1,
      params: {},
    });
  }

  const templates = {
    Leaf: `function(ctx) {
      ctx.setSignal("out", [], ctx.getSignal("in", []));
    }`,
  };
  for (let i = 0; i < n; i++) {
    templates[`T${i}`] = `function(ctx) {
      ctx.setVar("x", [], ctx.callFunction("setChild", [ctx.getSignal("in", [])]));
      ctx.setSignal("out", [], ctx.getSignal("in", []));
      ctx.setSignal("out", [], ctx.getPin("child", [], "out", []));
      ctx.setPin("child", [], "in", [], ctx.getSignal("childIn", []));
    }`;
  }

  return {
    nVars: n + 3,
    nInputs: 1,
    nOutputs: n + 1,
    nSignals: n + 3,
    signals,
    components,
    templates,
    functions: {
      setChild: {
        params: ['v'],
        func: `function(ctx) {
      ctx.setSignal("childIn", [], ctx.getVar("v",[]));
      return ctx.getVar("v",[]);;
    }`,
      },
    },
    signalName2Idx,
  };
}

/**
 * Builds a duplicate-trigger shape old circom 0.0.35 can emit when several
 * aliased child inputs point at the same parent signal.
 *
 * Source shape:
 *
 *   template C(k) {
 *     signal input in[DUP];
 *     signal output out;
 *     out <== in[0] + k;
 *   }
 *
 *   template Main() {
 *     signal input in;
 *     signal output out;
 *     signal fan;
 *     component c[WIDTH];
 *     for each c[i].in[j]: fan ==> c[i].in[j];
 *     fan <== in;
 *     out <== fan;
 *   }
 *
 * The important property is that `fan.triggerComponents` contains each child id
 * `dup` times. The witness should still execute each child once and then let the
 * parent continuation write the final output.
 */
export function buildDuplicateTriggerCircuit(width, dup) {
  if (width < 1) throw new RangeError('width must be >= 1');
  if (dup < 1) throw new RangeError('dup must be >= 1');

  const signals = [
    { names: ['one'], triggerComponents: [] },
    { names: ['main.out'], triggerComponents: [] },
    { names: ['main.in'], triggerComponents: [0] },
    { names: ['main.fan'], triggerComponents: [] },
  ];
  const components = [{ name: 'main', params: {}, template: 'Main', inputSignals: 1 }];
  for (let i = 0; i < width; i++) {
    signals[1].names.push(`main.c${i}.out`);
    components.push({
      name: `main.c${i}`,
      params: { k: i + 1 },
      template: 'Child',
      inputSignals: dup,
    });
    for (let j = 0; j < dup; j++) {
      signals[3].names.push(`main.c${i}.in[${j}]`);
      signals[3].triggerComponents.push(i + 1);
    }
  }

  const signalName2Idx = {};
  for (let s = 0; s < signals.length; s++) {
    for (const name of signals[s].names) signalName2Idx[name] = s;
  }

  return {
    nVars: 4,
    nInputs: 1,
    nOutputs: 1,
    nSignals: 4,
    signals,
    components,
    templates: {
      Main: `function(ctx) {
      ctx.setSignal("fan", [], ctx.getSignal("in", []));
      ctx.setSignal("out", [], ctx.getSignal("fan", []));
    }`,
      Child: `function(ctx) {
      ctx.setSignal("out", [], bigInt(ctx.getSignal("in", ["0"])).add(bigInt(ctx.getVar("k", []))).mod(__P__));
    }`,
    },
    functions: {},
    signalName2Idx,
  };
}
