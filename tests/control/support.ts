/**
 * Shared helpers for the D062 control-channel integration tests: an in-memory
 * identity-named descriptor anchor, a passing/injected anchor verifier, real
 * named-pipe server startup, a CLI driver, and a raw-socket client for byte-level
 * adversarial cases. Not a test file (no `.test.ts`), so vitest does not collect
 * it.
 */

import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';

import { AutoflowOrchestrator } from '../../src/autoflow/orchestrator.js';
import { AutoflowRuntime } from '../../src/autoflow/runtime.js';
import type { WorkflowBinding } from '../../src/domain/index.js';
import { NONCE_BYTES, computeServerMac } from '../../src/control/control-auth.js';
import {
  buildHelloBody,
  buildResultBody,
  frameMessage,
  MAX_BODY_BYTES,
  parseClientRequest,
  parseHelloBody,
  parseResultBody,
} from '../../src/control/control-channel.js';
import { CONTROL_RESULT, type ControlResultStatus } from '../../src/control/control-command.js';
import { runControlCli, type ControlCliOutcome } from '../../src/control/cli.js';
import {
  ANCHOR_SECRET_RUNTIME_ID,
  DESCRIPTOR_CREATION_REJECTION,
  bindDescriptor,
  createRuntimeDescriptor,
  descriptorFilenameFor,
  parseDescriptor,
  pipePathFromName,
  serializeAnchorSecret,
  serializeDescriptor,
  type ControlAnchorVerification,
  type DescriptorAclVerification,
  type DescriptorCreation,
  type DescriptorFileDeps,
  type ParsedDescriptor,
  type PipeProbe,
} from '../../src/control/control-store.js';
import {
  startControlChannel,
  type ControlChannelHandle,
  type DescriptorCreatorFn,
  type StartControlChannelDeps,
} from '../../src/control/control-runtime.js';

export const REPO = 'repo-agentbridge';
export const SHA = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
export const BINDING: WorkflowBinding = {
  workflowId: 'wf-d062-0001',
  repositoryId: REPO,
  boundCommitSha: SHA,
};

export const FAKE_ANCHOR = 'C:\\FakeAnchor';

/**
 * The fixed anchor secret every in-memory anchor is born with (see memAnchor),
 * so bound descriptors minted by tests verify against any memAnchor. Real
 * anchors mint a random one through the creator; only the in-memory fixture
 * shares a constant.
 */
export const TEST_ANCHOR_SECRET: Buffer = Buffer.alloc(32, 0x5a);
export const TEST_ANCHOR_SECRET_FILENAME = descriptorFilenameFor(ANCHOR_SECRET_RUNTIME_ID);

/** Mint a descriptor already bound to {@link TEST_ANCHOR_SECRET}. */
export function mintBound(): ParsedDescriptor {
  return bindDescriptor(createRuntimeDescriptor(), TEST_ANCHOR_SECRET);
}

export function passingVerify(): Promise<ControlAnchorVerification> {
  return Promise.resolve({ ok: true, anchorPath: FAKE_ANCHOR });
}

export function passingDescriptorVerify(): Promise<DescriptorAclVerification> {
  return Promise.resolve({ ok: true });
}

/**
 * An in-memory anchor: a map from absolute descriptor path to file text. Models
 * exactly the operations the runtime and CLI perform — list the anchor, read one
 * exact file, remove one exact file, and CREATE_NEW-create one exact file — so
 * tests touch no real filesystem, anchor, or native creator.
 */
export interface MemAnchor {
  readonly anchorPath: string;
  /** The anchor secret this anchor was born with (TEST_ANCHOR_SECRET unless seeded without one). */
  readonly secret: Buffer;
  readonly deps: DescriptorFileDeps;
  /** The CREATE_NEW creation seam: refuses an existing path (CREATOR_FAILED). */
  readonly create: DescriptorCreatorFn;
  /** All stored descriptor texts keyed by basename. */
  entries(): ReadonlyMap<string, string>;
  /** The text stored for a runtime id, or `null`. */
  get(runtimeId: string): string | null;
  /** Store a text for a runtime id (test seeding; bypasses CREATE_NEW). */
  set(runtimeId: string, text: string): void;
  /** Store raw text under an arbitrary basename (malformed / non-candidate seeding). */
  setRaw(basename: string, text: string): void;
  /** Remove a runtime id's file (test seeding). */
  remove(runtimeId: string): void;
  /** Number of removeFile calls made through the deps. */
  removeCalls(): number;
  /** Number of create calls made through the seam. */
  createCalls(): number;
}

/** An in-memory `ENOENT`, shaped like the fs error (`code`) the real opener throws. */
function enoent(): Error {
  return Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
}

/**
 * @param withSecret Seed the reserved anchor secret file (TEST_ANCHOR_SECRET) —
 * the state every provisioned anchor reaches after its first runtime start.
 * `false` models an anchor no bound runtime has ever started in.
 */
export function memAnchor(anchorPath: string = FAKE_ANCHOR, withSecret = true): MemAnchor {
  const files = new Map<string, string>();
  if (withSecret) {
    files.set(TEST_ANCHOR_SECRET_FILENAME, serializeAnchorSecret(TEST_ANCHOR_SECRET));
  }
  let removeCalls = 0;
  let createCalls = 0;
  const pathOf = (basename: string): string => join(anchorPath, basename);
  const basenameOf = (path: string): string | null => {
    for (const name of files.keys()) {
      if (pathOf(name) === path) {
        return name;
      }
    }
    return null;
  };
  return {
    anchorPath,
    secret: TEST_ANCHOR_SECRET,
    deps: {
      listAnchor: (dir: string): readonly string[] => {
        if (dir !== anchorPath) {
          throw enoent();
        }
        return [...files.keys()];
      },
      readFile: (path: string): string => {
        const name = basenameOf(path);
        if (name === null) {
          throw enoent();
        }
        return files.get(name) ?? '';
      },
      removeFile: (path: string): void => {
        removeCalls += 1;
        const name = basenameOf(path);
        if (name === null) {
          throw enoent();
        }
        files.delete(name);
      },
      // The in-memory anchor carries no OS security metadata, so every candidate
      // is treated as verified here; tests of the discovery gate override this.
      verifyDescriptor: passingDescriptorVerify,
    },
    create: (dir: string, runtimeId: string, bytes: Buffer): Promise<DescriptorCreation> => {
      createCalls += 1;
      if (dir !== anchorPath) {
        return Promise.resolve({ ok: false, reason: DESCRIPTOR_CREATION_REJECTION.CREATOR_FAILED });
      }
      const name = descriptorFilenameFor(runtimeId);
      if (files.has(name)) {
        // CREATE_NEW: an existing pathname is an error, never an overwrite.
        return Promise.resolve({ ok: false, reason: DESCRIPTOR_CREATION_REJECTION.CREATOR_FAILED });
      }
      files.set(name, bytes.toString('utf8'));
      return Promise.resolve({ ok: true });
    },
    entries: (): ReadonlyMap<string, string> => new Map(files),
    get: (runtimeId: string): string | null => files.get(descriptorFilenameFor(runtimeId)) ?? null,
    set: (runtimeId: string, text: string): void => {
      files.set(descriptorFilenameFor(runtimeId), text);
    },
    setRaw: (basename: string, text: string): void => {
      files.set(basename, text);
    },
    remove: (runtimeId: string): void => {
      files.delete(descriptorFilenameFor(runtimeId));
    },
    removeCalls: (): number => removeCalls,
    createCalls: (): number => createCalls,
  };
}

/** A pipe probe answering from a fixed table (pipe path -> liveness); default UNKNOWN. */
export function tableProbe(
  table: Readonly<Record<string, 'ABSENT' | 'PRESENT' | 'UNKNOWN'>>,
  fallback: 'ABSENT' | 'PRESENT' | 'UNKNOWN' = 'UNKNOWN',
): PipeProbe {
  return (pipePath: string): Promise<'ABSENT' | 'PRESENT' | 'UNKNOWN'> =>
    Promise.resolve(table[pipePath] ?? fallback);
}

/** A probe that reports every pipe ABSENT (the "everything crashed" world). */
export const allAbsentProbe: PipeProbe = () => Promise.resolve('ABSENT');

export function newOrchestrator(): { runtime: AutoflowRuntime; orchestrator: AutoflowOrchestrator } {
  const runtime = new AutoflowRuntime();
  return { runtime, orchestrator: new AutoflowOrchestrator(runtime) };
}

export interface StartServerOptions {
  readonly timeoutMs?: number;
  readonly probePipe?: PipeProbe;
  readonly overrides?: Partial<StartControlChannelDeps>;
}

/**
 * Start a real control-channel server (real named pipe) backed by the in-memory
 * anchor. Anchor and descriptor ACL verification pass by injection; creation is
 * the anchor's CREATE_NEW seam; the pipe probe is the REAL one unless injected,
 * so liveness reflects the real kernel pipe namespace.
 */
export async function startServer(
  orchestrator: AutoflowOrchestrator,
  anchor: MemAnchor,
  options: StartServerOptions = {},
): Promise<ControlChannelHandle> {
  const handle = await startControlChannel({
    orchestrator,
    verify: passingVerify,
    verifyDescriptor: passingDescriptorVerify,
    descriptorDeps: anchor.deps,
    createDescriptor: anchor.create,
    logger: (): void => {
      /* silent */
    },
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
    ...(options.probePipe === undefined ? {} : { probePipe: options.probePipe }),
    ...options.overrides,
  });
  if (handle === null) {
    throw new Error('control channel failed to start');
  }
  return handle;
}

export interface CliRun {
  readonly outcome: ControlCliOutcome;
  readonly out: readonly string[];
  readonly err: readonly string[];
}

export interface CallCliOptions {
  readonly descriptorDeps?: DescriptorFileDeps;
  readonly probePipe?: PipeProbe;
  readonly timeoutMs?: number;
}

/** Drive the official CLI against the in-memory anchor (real pipe transport, real probe). */
export async function callCli(anchor: MemAnchor, options: CallCliOptions = {}): Promise<CliRun> {
  const out: string[] = [];
  const err: string[] = [];
  const outcome = await runControlCli({
    verify: passingVerify,
    descriptorDeps: options.descriptorDeps ?? anchor.deps,
    out: (message: string): void => {
      out.push(message);
    },
    err: (message: string): void => {
      err.push(message);
    },
    ...(options.probePipe === undefined ? {} : { probePipe: options.probePipe }),
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
  });
  return { outcome, out, err };
}

/** The parsed descriptor a handle published into the anchor (must exist and be valid). */
export function descriptorOf(anchor: MemAnchor, handle: ControlChannelHandle): ParsedDescriptor {
  const serialized = anchor.get(handle.runtimeId);
  if (serialized === null) {
    throw new Error('no descriptor in anchor for handle');
  }
  const parsed = parseDescriptor(serialized);
  if (parsed === null) {
    throw new Error('descriptor in anchor is invalid');
  }
  return parsed;
}

/** The token + pipe path for a handle's descriptor. */
export function descriptorFacts(
  anchor: MemAnchor,
  handle: ControlChannelHandle,
): { token: Buffer; pipePath: string } {
  const parsed = descriptorOf(anchor, handle);
  return { token: parsed.token, pipePath: pipePathFromName(parsed.descriptor.pipeName) };
}

/** Produce a descriptor JSON with the same pipe name but a different token. */
export function withTamperedToken(serialized: string): string {
  const parsed = parseDescriptor(serialized);
  if (parsed === null) {
    throw new Error('withTamperedToken: input is not a descriptor');
  }
  const token = randomBytes(32);
  // Correctly BOUND to the test anchor secret, so only the token is wrong: the
  // rejection under test is the server's (HMAC), not discovery's binding check.
  const tampered = bindDescriptor(
    { descriptor: { version: 2, pipeName: parsed.descriptor.pipeName, token: token.toString('base64url') }, token, runtimeId: parsed.runtimeId, proof: null },
    TEST_ANCHOR_SECRET,
  );
  return serializeDescriptor(tampered.descriptor);
}

export type RawOutcome =
  | { readonly kind: 'result'; readonly result: string }
  | { readonly kind: 'closed' };

export interface RawClientOptions {
  /** Given the server nonce, return the frame to send, or `null` to just wait. */
  onHello: (nonceS: Buffer) => Buffer | null;
  readonly waitMs?: number;
}

/**
 * A raw named-pipe client for byte-level adversarial tests. Reads the hello,
 * lets the caller craft the request bytes, and returns the parsed server result
 * or a closed indication.
 */
export function rawClient(pipePath: string, options: RawClientOptions): Promise<RawOutcome> {
  return new Promise<RawOutcome>((resolvePromise) => {
    const socket = net.connect(pipePath);
    let carry: Buffer = Buffer.alloc(0);
    let phase: 'hello' | 'result' = 'hello';
    const state = { done: false };
    let holdTimer: NodeJS.Timeout | null = null;

    const finish = (outcome: RawOutcome): void => {
      if (state.done) {
        return;
      }
      state.done = true;
      if (holdTimer !== null) {
        clearTimeout(holdTimer);
      }
      socket.destroy();
      resolvePromise(outcome);
    };

    socket.on('error', () => {
      finish({ kind: 'closed' });
    });
    socket.on('close', () => {
      finish({ kind: 'closed' });
    });
    socket.on('data', (chunk: Buffer) => {
      if (state.done) {
        return;
      }
      carry = Buffer.concat([carry, chunk]);
      for (;;) {
        if (carry.length < 4) {
          return;
        }
        const length = carry.readUInt32BE(0);
        if (length === 0 || length > MAX_BODY_BYTES) {
          finish({ kind: 'closed' });
          return;
        }
        const total = 4 + length;
        if (carry.length < total) {
          return;
        }
        const body = carry.subarray(4, total);
        carry = carry.subarray(total);
        if (phase === 'hello') {
          const nonceS = parseHelloBody(body);
          if (nonceS === null) {
            finish({ kind: 'closed' });
            return;
          }
          phase = 'result';
          const toSend = options.onHello(nonceS);
          if (toSend === null) {
            // Hold the connection open (e.g., to trigger a server timeout).
            holdTimer = setTimeout(() => {
              /* keep-alive noop */
            }, options.waitMs ?? 1000);
            return;
          }
          socket.write(toSend);
          return;
        }
        const parsed = parseResultBody(body);
        if (parsed === null) {
          finish({ kind: 'closed' });
          return;
        }
        finish({ kind: 'result', result: parsed.result });
        return;
      }
    });
  });
}

/**
 * A rogue server that completes the handshake and signs macS with `token` — a
 * fresh random (wrong) token by default, or a leaked genuine token to model an
 * attacker who read an unverified descriptor and can therefore authenticate.
 */
export function startRogueServer(
  pipePath: string,
  status: ControlResultStatus = CONTROL_RESULT.APPLIED,
  token: Buffer = randomBytes(32),
): Promise<net.Server> {
  const server = net.createServer((socket: net.Socket) => {
    const nonceS = randomBytes(NONCE_BYTES);
    let carry: Buffer = Buffer.alloc(0);
    socket.on('error', () => {
      /* ignore */
    });
    socket.on('data', (chunk: Buffer) => {
      carry = Buffer.concat([carry, chunk]);
      if (carry.length < 4) {
        return;
      }
      const length = carry.readUInt32BE(0);
      if (carry.length < 4 + length) {
        return;
      }
      const body = carry.subarray(4, 4 + length);
      const parsed = parseClientRequest(body);
      if (!parsed.ok) {
        socket.destroy();
        return;
      }
      const resultBytes = Buffer.from(status, 'utf8');
      const macS = computeServerMac(token, nonceS, parsed.nonceC, parsed.commandBytes, resultBytes);
      socket.end(frameMessage(buildResultBody(status, macS)));
    });
    socket.write(frameMessage(buildHelloBody(nonceS)));
  });
  return new Promise<net.Server>((resolvePromise, rejectPromise) => {
    server.once('error', rejectPromise);
    server.listen(pipePath, () => {
      server.removeListener('error', rejectPromise);
      resolvePromise(server);
    });
  });
}

/** A silent pipe server holding a name open (a live pipe that speaks no protocol). */
export function startSilentServer(pipePath: string): Promise<net.Server> {
  const server = net.createServer((socket: net.Socket) => {
    socket.on('error', () => {
      /* ignore */
    });
  });
  return new Promise<net.Server>((resolvePromise, rejectPromise) => {
    server.once('error', rejectPromise);
    server.listen(pipePath, () => {
      server.removeListener('error', rejectPromise);
      resolvePromise(server);
    });
  });
}

export function closeServer(server: net.Server): Promise<void> {
  return new Promise<void>((resolvePromise) => {
    server.close(() => {
      resolvePromise();
    });
  });
}

export function delay(ms: number): Promise<void> {
  return new Promise<void>((resolvePromise) => {
    setTimeout(resolvePromise, ms);
  });
}
