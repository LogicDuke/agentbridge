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
import {
  NONCE_BYTES,
  generateRuntimeKeyPair,
  signServerResult,
  type ChannelIdentity,
  type RuntimeKeyPair,
} from '../../src/control/control-auth.js';
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
  DESCRIPTOR_CREATION_REJECTION,
  createRuntimeDescriptor,
  descriptorFilenameFor,
  parseDescriptor,
  pipePathFromName,
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

/** One runtime's minted v3 identity plus the ephemeral keypair behind it. */
export interface MintedRuntime {
  readonly parsed: ParsedDescriptor;
  readonly keyPair: RuntimeKeyPair;
  readonly identity: ChannelIdentity;
}

/**
 * Mint a v3 descriptor around a fresh ephemeral keypair. The private key is
 * returned ONLY to the test that minted it, exactly as a live runtime keeps it
 * in its own memory — nothing here writes it anywhere.
 */
export function mintRuntime(): MintedRuntime {
  const keyPair = generateRuntimeKeyPair();
  const parsed = createRuntimeDescriptor(keyPair.verifyKey);
  return {
    parsed,
    keyPair,
    identity: { runtimeId: parsed.runtimeId, pipeName: parsed.descriptor.pipeName },
  };
}

/** Mint a v3 descriptor when the test does not need the signing key. */
export function mintDescriptor(): ParsedDescriptor {
  return mintRuntime().parsed;
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
 * An anchor holds nothing but identity-named descriptors. There is no reserved
 * secret file any more: the anchor carries no durable secret of its own.
 */
export function memAnchor(anchorPath: string = FAKE_ANCHOR): MemAnchor {
  const files = new Map<string, string>();
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

/** The token, verify key, channel identity and pipe path for a handle's descriptor. */
export function descriptorFacts(
  anchor: MemAnchor,
  handle: ControlChannelHandle,
): { token: Buffer; verifyKey: Buffer; identity: ChannelIdentity; pipePath: string } {
  const parsed = descriptorOf(anchor, handle);
  return {
    token: parsed.token,
    verifyKey: parsed.verifyKey,
    identity: { runtimeId: parsed.runtimeId, pipeName: parsed.descriptor.pipeName },
    pipePath: pipePathFromName(parsed.descriptor.pipeName),
  };
}

/**
 * A well-formed v3 descriptor with the same pipe name and verifyKey but a
 * DIFFERENT token, so the rejection under test is the server's macC check and
 * nothing else.
 */
export function withTamperedToken(serialized: string): string {
  const parsed = parseDescriptor(serialized);
  if (parsed === null) {
    throw new Error('withTamperedToken: input is not a descriptor');
  }
  return serializeDescriptor({
    version: 3,
    pipeName: parsed.descriptor.pipeName,
    token: randomBytes(32).toString('base64url'),
    verifyKey: parsed.descriptor.verifyKey,
  });
}

/** A legacy v2 descriptor body for the exact same runtime identity. */
export function asLegacyV2(serialized: string): string {
  const parsed = parseDescriptor(serialized);
  if (parsed === null) {
    throw new Error('asLegacyV2: input is not a descriptor');
  }
  return JSON.stringify({
    version: 2,
    pipeName: parsed.descriptor.pipeName,
    token: parsed.descriptor.token,
  });
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
 * How a squatter tries to forge the server result. Every variant models a party
 * that holds a byte-identical COPY of a genuine descriptor — so it has the token
 * and the public verifyKey — but has never held the ephemeral private key.
 */
export type RogueForgery =
  /** Emit 64 random bytes where the signature belongs. */
  | { readonly kind: 'random' }
  /** Sign correctly, but with a keypair the squatter generated itself. */
  | { readonly kind: 'ownKey'; readonly identity: ChannelIdentity }
  /** Replay a signature harvested from the genuine runtime on an earlier exchange. */
  | { readonly kind: 'harvested'; readonly signature: Buffer }
  /**
   * The ONLY variant that can succeed: the genuine runtime itself, holding the
   * real private key. Used as the positive control.
   */
  | { readonly kind: 'genuine'; readonly keyPair: RuntimeKeyPair; readonly identity: ChannelIdentity };

/**
 * A rogue server holding a squatted pipe name. It completes framing and the
 * hello, then answers with whatever the chosen forgery produces.
 */
export function startRogueServer(
  pipePath: string,
  status: ControlResultStatus = CONTROL_RESULT.APPLIED,
  forgery: RogueForgery = { kind: 'random' },
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
      let signature: Buffer;
      if (forgery.kind === 'harvested') {
        signature = forgery.signature;
      } else if (forgery.kind === 'ownKey') {
        signature = signServerResult(
          generateRuntimeKeyPair().privateKey,
          forgery.identity,
          nonceS,
          parsed.nonceC,
          parsed.commandBytes,
          resultBytes,
        );
      } else if (forgery.kind === 'genuine') {
        signature = signServerResult(
          forgery.keyPair.privateKey,
          forgery.identity,
          nonceS,
          parsed.nonceC,
          parsed.commandBytes,
          resultBytes,
        );
      } else {
        signature = randomBytes(64);
      }
      socket.end(frameMessage(buildResultBody(status, signature)));
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
