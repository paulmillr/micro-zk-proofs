/** Resource limits applied before artifact metadata can drive large allocations. */
export type ArtifactLimits = {
  /** Maximum serialized R1CS or ZKey size. Defaults to 64 MiB. */
  maxBytes?: number;
  /** Maximum circuit or proving-key variable count. Defaults to 65,536. */
  maxVariables?: number;
  /** Maximum R1CS constraint count. Defaults to 65,536. */
  maxConstraints?: number;
  /** Maximum proving domain size. Defaults to 131,072. */
  maxDomainSize?: number;
};

/** Fully resolved artifact limits used internally. */
export type ResolvedArtifactLimits = Required<ArtifactLimits>;

const defaults: ResolvedArtifactLimits = {
  maxBytes: 64 * 1024 * 1024,
  maxVariables: 2 ** 16,
  maxConstraints: 2 ** 16,
  maxDomainSize: 2 ** 17,
};

/** Validates and fills optional resource limits. */
export function resolveArtifactLimits(limits: ArtifactLimits = {}): ResolvedArtifactLimits {
  if (limits === null || typeof limits !== 'object' || Array.isArray(limits))
    throw new TypeError('"limits" expected object, got type=' + typeof limits);
  const resolved = { ...defaults, ...limits };
  for (const [name, value] of Object.entries(resolved)) {
    if (!Number.isSafeInteger(value) || value <= 0)
      throw new Error(`expected positive integer ${name}, got ${value}`);
  }
  return Object.freeze(resolved);
}
