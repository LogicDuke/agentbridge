/**
 * Shared helpers for the D062 control-channel integration tests: an in-memory
 * descriptor store, a passing/injected anchor verifier, real named-pipe server
 * startup, a CLI driver, and a raw-socket client for byte-level adversarial
 * cases. Not a test file (no `.test.ts`), so vitest does not collect it.
 */

import net from 'node:net';
import { randomBytes } from 'node:crypto';

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
  parseDescriptor,
  pipePathFromName,
  serializeDescriptor,
  type ControlAnchorVerification,
  type DescriptorAclVerification,
  type DescriptorFileDeps,
} from '../../src/control/control-store.js';
import { startControlChannel, type ControlChannelHandle } from '../../src/control/control-runtime.js';

export const REPO = 'repo-agentbridge';
export const SHA = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
export const BINDING: WorkflowBinding = {
  workflowId: 'wf-d062-0001',
  repositoryId: REPO,
  boundCommitSha: SHA,
};

export const FAKE_ANCHOR = 'C:\\FakeAnchor';

export function passingVerify(): Promise<ControlAnchorVerification> {
  return Promise.resolve({ ok: true, anchorPath: FAKE_ANCHOR });
}

export function passingDescriptorVerify(): Promise<DescriptorAclVerification> {
  return Promise.resolve({ ok: true });
}

export interface MemStore {
  readonly deps: DescriptorFileDeps;
  get(): string | null;
  set(value: string | null): void;
}

/** An in-memory descriptor store, so tests touch no real filesystem or anchor. */
export function memStore(): MemStore {
  let data: string | null = null;
  return {
    deps: {
      readFile: (): string => {
        if (data === null) {
          throw new Error('ENOENT');
        }
        return data;
      },
      writeFile: (_path: string, value: string): void => {
        if (data !== null) {
          const exists = new Error('already exists') as NodeJS.ErrnoException;
          exists.code = 'EEXIST';
          throw exists;
        }
        data = value;
      },
      removeFile: (): void => {
        data = null;
      },
    },
    get: (): string | null => data,
    set: (value: string | null): void => {
      data = value;
    },
  };
}

export function newOrchestrator(): { runtime: AutoflowRuntime; orchestrator: AutoflowOrchestrator } {
  const runtime = new AutoflowRuntime();
  return { runtime, orchestrator: new AutoflowOrchestrator(runtime) };
}

export interface StartServerOptions {
  readonly timeoutMs?: number;
}

/** Start a real control-channel server backed by the in-memory store. */
export async function startServer(
  orchestrator: AutoflowOrchestrator,
  store: MemStore,
  options: StartServerOptions = {},
): Promise<ControlChannelHandle> {
  const handle = await startControlChannel({
    orchestrator,
    verify: passingVerify,
    verifyDescriptor: passingDescriptorVerify,
    descriptorDeps: store.deps,
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
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
  readonly timeoutMs?: number;
}

/** Drive the official CLI against the in-memory store (real pipe transport). */
export async function callCli(store: MemStore, options: CallCliOptions = {}): Promise<CliRun> {
  const out: string[] = [];
  const err: string[] = [];
  const outcome = await runControlCli({
    verify: passingVerify,
    descriptorDeps: options.descriptorDeps ?? store.deps,
    out: (message: string): void => {
      out.push(message);
    },
    err: (message: string): void => {
      err.push(message);
    },
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
  });
  return { outcome, out, err };
}

/** The token + pipe path for the descriptor currently in the store. */
export function descriptorFacts(store: MemStore): { token: Buffer; pipePath: string } {
  const serialized = store.get();
  if (serialized === null) {
    throw new Error('no descriptor in store');
  }
  const parsed = parseDescriptor(serialized);
  if (parsed === null) {
    throw new Error('descriptor in store is invalid');
  }
  return { token: parsed.token, pipePath: pipePathFromName(parsed.descriptor.pipeName) };
}

/** Produce a descriptor JSON with the same pipe name but a different token. */
export function withTamperedToken(serialized: string): string {
  const parsed = JSON.parse(serialized) as {
    version: 1;
    pid: number;
    pipeName: string;
    token: string;
  };
  return serializeDescriptor({
    version: 1,
    pid: parsed.pid,
    pipeName: parsed.pipeName,
    token: randomBytes(32).toString('base64url'),
  });
}

/** A fixed descriptorDeps that always returns a given descriptor JSON. */
export function fixedDescriptorDeps(serialized: string): DescriptorFileDeps {
  return {
    readFile: (): string => serialized,
    writeFile: (): void => {
      /* no-op */
    },
    removeFile: (): void => {
      /* no-op */
    },
  };
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

/** A rogue server that completes the handshake but signs macS with a wrong token. */
export function startRogueServer(
  pipePath: string,
  status: ControlResultStatus = CONTROL_RESULT.APPLIED,
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
      const wrongToken = randomBytes(32);
      const resultBytes = Buffer.from(status, 'utf8');
      const macS = computeServerMac(wrongToken, nonceS, parsed.nonceC, parsed.commandBytes, resultBytes);
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
