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
    nVars: n + 2,     // one slot per signal
    nInputs: 1,       // only "in"
    nOutputs: 1,      // only "out" (slot 1, checked by generateWitness after inputIdx)
    nSignals: n + 2,
    signals,
    components,
    templates,
    functions: {},
    signalName2Idx,
  };
}
