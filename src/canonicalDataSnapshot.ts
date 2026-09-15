// Bounded, descriptor-safe copy for caller-supplied receipt data.
//
// Ported from the reviewed ACP admission boundary
// (`apps/launchguard-acp/src/contracts/canonicalDataSnapshot.ts`, #94). The
// semantics are identical: every declared field is read exactly ONCE through
// its own-property descriptor — never through an accessor — so a stateful
// getter or Proxy trap cannot show integrity verification one face and a
// later subject-binding pass another. The result is a detached, deeply frozen
// JSON-data graph; both verifier axes consume only this capture.
//
// Two ACP-specific guards are deliberately NOT ported: the reserved
// `holderAttempt` inheritance probe (that field belongs to the ACP 1.1.4
// witness admission grammar; receipts carry no reserved semantic field, and
// inherited properties are already excluded wholesale by the
// own-enumerable-data-property copy) and the `rejectSharedReferences` option
// (a closed-witness-grammar constraint; a receipt decoded from JSON cannot
// contain aliases, and shared references are copied per occurrence here).

export class CanonicalDataSnapshotError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalDataSnapshotError";
  }
}

export interface CanonicalDataSnapshotOptions {
  maxNodes: number;
  label: string;
}

type SnapshotContainer = Record<string, unknown> | unknown[];

const isArrayIndex = (key: string): boolean => {
  if (!/^(?:0|[1-9][0-9]*)$/.test(key)) return false;
  const index = Number(key);
  return Number.isSafeInteger(index) && index >= 0 && index < 2 ** 32 - 1;
};

const primitiveSnapshot = (value: unknown, label: string): unknown => {
  if (value === null) return null;
  switch (typeof value) {
    case "string":
    case "boolean":
      return value;
    case "number":
      if (Number.isFinite(value)) return value;
      break;
  }
  throw new CanonicalDataSnapshotError(
    `${label} contains an unsupported primitive value`,
  );
};

/**
 * Return a detached, frozen graph without reading caller-provided property
 * values through ordinary access. Arrays must be dense data arrays and objects
 * must be ordinary/null-prototype data objects; this prevents semantic fields
 * from being hidden in prototypes, descriptors, symbols, or array extras.
 */
export const canonicalDataSnapshot = <T>(
  root: T,
  options: CanonicalDataSnapshotOptions,
): T => {
  if (root === null || typeof root !== "object") {
    return primitiveSnapshot(root, options.label) as T;
  }

  type EnterFrame = {
    kind: "enter";
    source: object;
    target: SnapshotContainer;
  };
  type ExitFrame = { kind: "exit"; source: object };
  type Frame = EnterFrame | ExitFrame;

  const makeContainer = (source: object): SnapshotContainer =>
    Array.isArray(source) ? [] : Object.create(null) as Record<string, unknown>;
  let rootTarget: SnapshotContainer;
  try {
    // Array.isArray on a revoked-Proxy ROOT throws before the main loop's
    // containment is entered — bind it to the same bounded error here.
    rootTarget = makeContainer(root);
  } catch {
    throw new CanonicalDataSnapshotError(
      `${options.label} cannot be safely detached`,
    );
  }
  const stack: Frame[] = [{ kind: "enter", source: root, target: rootTarget }];
  const ancestors = new WeakSet<object>();
  const created: object[] = [];
  let work = 0;

  const addValue = (
    target: SnapshotContainer,
    key: string | number,
    value: unknown,
    children: EnterFrame[],
  ): void => {
    if (value !== null && typeof value === "object") {
      const child = makeContainer(value);
      if (Array.isArray(target)) {
        target[key as number] = child;
      } else {
        Object.defineProperty(target, key, {
          value: child,
          enumerable: true,
          configurable: false,
          writable: false,
        });
      }
      children.push({ kind: "enter", source: value, target: child });
      return;
    }
    const primitive = primitiveSnapshot(value, options.label);
    if (Array.isArray(target)) {
      target[key as number] = primitive;
    } else {
      Object.defineProperty(target, key, {
        value: primitive,
        enumerable: true,
        configurable: false,
        writable: false,
      });
    }
  };

  try {
    while (stack.length > 0) {
      const frame = stack.pop();
      if (!frame) break;
      if (frame.kind === "exit") {
        ancestors.delete(frame.source);
        continue;
      }
      if (work >= options.maxNodes) {
        throw new CanonicalDataSnapshotError(
          `${options.label} exceeds copy budget`,
        );
      }
      work += 1;
      if (ancestors.has(frame.source)) {
        throw new CanonicalDataSnapshotError(
          `${options.label} contains a cycle`,
        );
      }
      ancestors.add(frame.source);
      created.push(frame.target);

      if (Object.getOwnPropertySymbols(frame.source).length > 0) {
        throw new CanonicalDataSnapshotError(
          `${options.label} contains a symbol-keyed property`,
        );
      }

      const children: EnterFrame[] = [];
      if (Array.isArray(frame.source)) {
        if (Object.getPrototypeOf(frame.source) !== Array.prototype) {
          throw new CanonicalDataSnapshotError(
            `${options.label} contains an unsupported array prototype`,
          );
        }
        const lengthDescriptor = Object.getOwnPropertyDescriptor(
          frame.source,
          "length",
        );
        if (!lengthDescriptor || !("value" in lengthDescriptor) ||
            !Number.isSafeInteger(lengthDescriptor.value) ||
            lengthDescriptor.value < 0) {
          throw new CanonicalDataSnapshotError(
            `${options.label} contains an invalid array length`,
          );
        }
        const length = lengthDescriptor.value;
        const names = Object.getOwnPropertyNames(frame.source);
        if (names.length !== length + 1 || !names.includes("length")) {
          throw new CanonicalDataSnapshotError(
            `${options.label} contains a sparse or extended array`,
          );
        }
        for (let index = 0; index < length; index += 1) {
          if (work >= options.maxNodes) {
            throw new CanonicalDataSnapshotError(
              `${options.label} exceeds copy budget`,
            );
          }
          work += 1;
          const key = String(index);
          const descriptor = Object.getOwnPropertyDescriptor(frame.source, key);
          if (!descriptor || !("value" in descriptor) || !descriptor.enumerable ||
              !isArrayIndex(key)) {
            throw new CanonicalDataSnapshotError(
              `${options.label} contains an accessor or invalid array element`,
            );
          }
          addValue(frame.target, index, descriptor.value, children);
        }
      } else {
        const prototype = Object.getPrototypeOf(frame.source);
        if (prototype !== Object.prototype && prototype !== null) {
          throw new CanonicalDataSnapshotError(
            `${options.label} contains an unsupported object prototype`,
          );
        }
        for (const key of Object.getOwnPropertyNames(frame.source)) {
          if (work >= options.maxNodes) {
            throw new CanonicalDataSnapshotError(
              `${options.label} exceeds copy budget`,
            );
          }
          work += 1;
          const descriptor = Object.getOwnPropertyDescriptor(frame.source, key);
          if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
            throw new CanonicalDataSnapshotError(
              `${options.label} contains an accessor or non-enumerable property`,
            );
          }
          addValue(frame.target, key, descriptor.value, children);
        }
      }
      stack.push({ kind: "exit", source: frame.source });
      for (let index = children.length - 1; index >= 0; index -= 1) {
        const child = children[index];
        if (child) stack.push(child);
      }
    }
  } catch (error) {
    if (error instanceof CanonicalDataSnapshotError) throw error;
    throw new CanonicalDataSnapshotError(
      `${options.label} cannot be safely detached`,
    );
  }

  for (let index = created.length - 1; index >= 0; index -= 1) {
    const value = created[index];
    if (value) Object.freeze(value);
  }
  return rootTarget as T;
};
