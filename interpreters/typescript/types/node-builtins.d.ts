/**
 * The exact surface of the Node builtins this package uses, declared here.
 *
 * WHY not `@types/node`: this implementation's dependency claim is that its
 * only dev-time dependency is the TypeScript compiler and its only runtime
 * dependency is the Node standard library. Pulling a second package in — even
 * one that ships no runtime code — would make that claim need a footnote. The
 * surface actually used is small enough to state, and stating it has a second
 * benefit: everything the test harness and the mint script are allowed to touch
 * outside the protocol code is visible in one file.
 *
 * `src/` imports NONE of these. Only `test/`, `testkit/` and `scripts/` do,
 * which is the file-system and process boundary kept out of the protocol code.
 */

declare module 'node:test' {
  export interface TestContext {
    /** Marks the running test as skipped, with the reason shown in the report. */
    skip(message?: string): void;
    diagnostic(message: string): void;
  }
  export type TestFn = (t: TestContext) => void | Promise<void>;
  export function test(name: string, fn: TestFn): Promise<void>;
  export function describe(name: string, fn: () => void): void;
  export function it(name: string, fn: TestFn): void;
}

declare module 'node:assert/strict' {
  interface StrictAssert {
    // `asserts value` is what lets a test narrow a nullable fixture without a
    // cast: `assert.ok(mandate)` and the compiler knows it is present from
    // there on. It matches what the runtime actually does.
    (value: unknown, message?: string | Error): asserts value;
    ok(value: unknown, message?: string | Error): asserts value;
    equal(actual: unknown, expected: unknown, message?: string | Error): void;
    notEqual(actual: unknown, expected: unknown, message?: string | Error): void;
    deepEqual(actual: unknown, expected: unknown, message?: string | Error): void;
    match(value: string, pattern: RegExp, message?: string | Error): void;
    throws(fn: () => unknown, expected?: unknown, message?: string | Error): void;
    rejects(fn: () => Promise<unknown>, expected?: unknown, message?: string | Error): Promise<void>;
    fail(message?: string | Error): never;
  }
  const assert: StrictAssert;
  export default assert;
}

declare module 'node:fs' {
  export function readFileSync(path: string | URL): Uint8Array;
  export function readFileSync(path: string | URL, encoding: 'utf8'): string;
  export function existsSync(path: string | URL): boolean;
  export function readdirSync(path: string | URL): string[];
  /** Used by `scripts/mint_ts_envelope.ts` alone — no test writes anything. */
  export function writeFileSync(path: string | URL, data: string, encoding: 'utf8'): void;
}

declare module 'node:process' {
  interface WritableStream {
    write(chunk: string): boolean;
  }
  interface Process {
    readonly argv: string[];
    readonly stdout: WritableStream;
    readonly stderr: WritableStream;
    exitCode: number | undefined;
    readonly version: string;
  }
  const process: Process;
  export default process;
}
