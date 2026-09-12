/**
 * The official `agentbridge-control` CLI — the only supported client of the
 * Decision 062 control channel (direct third-party pipe clients are
 * unsupported).
 *
 * It may only: verify the hardened control anchor, discover the one live
 * identity-named descriptor, connect to that runtime's pipe, perform the
 * handshake, submit **one** `OPEN_HUMAN_GATE`, authenticate the server
 * response, and print a bounded result. It constructs no `WorkflowEvent`, holds
 * no `WorkflowState` authority, accepts no arbitrary event, and takes no
 * commit/repository/workflow selector as command authority. It runs no Git,
 * GitHub, shell, or process command, and never deletes a descriptor.
 *
 * Discovery is bounded and deterministic (see `discoverControlRuntime`): every
 * `runtime-descriptor-<id>.json` in the verified anchor is first security-verified
 * (non-reparse identity, exact operator owner, protected operator+SYSTEM DACL —
 * the same gate the runtime applies to its own file) BEFORE its token is read;
 * each verified candidate is parsed safely, its pipe is probed, and the command
 * is sent only when EXACTLY ONE candidate's pipe is live. Zero live candidates is
 * "unavailable"; two or more is "ambiguous" and fails closed. Nothing is chosen
 * by mtime, PID, lexicographic order, or last-writer-wins.
 *
 * Critically, it prints an applied outcome **only** when the server's Ed25519
 * `sigS` verifies against the `verifyKey` of the SAME descriptor discovery
 * selected, over a transcript binding that runtime's id and pipe name, both
 * nonces, and the exact command and result bytes. A missing, wrong, cross-runtime,
 * or replayed signature is an authentication failure and is never reported as
 * `APPLIED`.
 *
 * Because the signing key is ephemeral and lives only in the genuine runtime's
 * memory, a party serving a squatted pipe with a byte-identical copy of a
 * genuine descriptor cannot produce `sigS` and can never make this CLI exit 0.
 * The CLI's own `nonceC` is fresh per connection, so a signature harvested from
 * a live runtime is useless here once that runtime is gone.
 */

import net from 'node:net';
import { randomBytes } from 'node:crypto';

import {
  computeClientMac,
  verifyServerResult,
  NONCE_BYTES,
  type ChannelIdentity,
} from './control-auth.js';
import {
  CONTROL_COMMAND,
  CONTROL_RESULT,
  isControlResultStatus,
  type ControlResultStatus,
} from './control-command.js';
import {
  buildRequestBody,
  DEFAULT_CONNECTION_TIMEOUT_MS,
  frameMessage,
  LENGTH_PREFIX_BYTES,
  MAX_BODY_BYTES,
  parseHelloBody,
  parseResultBody,
} from './control-channel.js';
import {
  defaultPipeProbe,
  discoverControlRuntime,
  pipePathFromName,
  verifyControlAnchor,
  type ControlAnchorVerification,
  type DescriptorFileDeps,
  type PipeProbe,
  type VerifyControlAnchorDeps,
} from './control-store.js';

/** Connect to a pipe path, returning a socket. Injectable for tests. */
export type ConnectFn = (pipePath: string) => net.Socket;

const defaultConnect: ConnectFn = (pipePath: string): net.Socket => net.connect(pipePath);

export interface RunControlCliDeps {
  readonly env?: NodeJS.ProcessEnv;
  readonly verify?: (deps: VerifyControlAnchorDeps) => Promise<ControlAnchorVerification>;
  readonly descriptorDeps?: DescriptorFileDeps;
  readonly probePipe?: PipeProbe;
  readonly connect?: ConnectFn;
  readonly nonceGen?: () => Buffer;
  readonly timeoutMs?: number;
  readonly out?: (message: string) => void;
  readonly err?: (message: string) => void;
}

export interface ControlCliOutcome {
  readonly exitCode: number;
  readonly status: ControlResultStatus | null;
  readonly authenticated: boolean;
}

interface ClientProtocolOutcome {
  readonly authenticated: boolean;
  readonly status: ControlResultStatus | null;
  readonly errorMessage?: string;
}

interface ClientProtocolArgs {
  readonly connect: ConnectFn;
  readonly pipePath: string;
  readonly identity: ChannelIdentity;
  readonly token: Buffer;
  /** Raw Ed25519 public key from the discovered descriptor. */
  readonly verifyKey: Buffer;
  readonly nonceGen: () => Buffer;
  readonly timeoutMs: number;
}

/** Run the client side of the handshake over one connection. */
function runClientProtocol(args: ClientProtocolArgs): Promise<ClientProtocolOutcome> {
  return new Promise<ClientProtocolOutcome>((resolvePromise) => {
    const socket = args.connect(args.pipePath);
    const commandBytes = Buffer.from(CONTROL_COMMAND.OPEN_HUMAN_GATE, 'utf8');
    // A mutable state object (not a plain `let`) so narrowing is reset across
    // the `handleFrame` call and the settled re-check below is genuine.
    const state = { settled: false };
    let phase: 'hello' | 'result' = 'hello';
    let nonceS: Buffer | null = null;
    let nonceC: Buffer | null = null;
    let carry: Buffer = Buffer.alloc(0);

    const finish = (outcome: ClientProtocolOutcome): void => {
      if (state.settled) {
        return;
      }
      state.settled = true;
      socket.destroy();
      resolvePromise(outcome);
    };

    const handleFrame = (body: Buffer): void => {
      if (phase === 'hello') {
        nonceS = parseHelloBody(body);
        if (nonceS === null) {
          finish({ authenticated: false, status: null, errorMessage: 'bad server hello' });
          return;
        }
        nonceC = args.nonceGen();
        const macC = computeClientMac(args.token, args.identity, nonceS, nonceC, commandBytes);
        phase = 'result';
        socket.write(frameMessage(buildRequestBody(nonceC, CONTROL_COMMAND.OPEN_HUMAN_GATE, macC)));
        return;
      }
      const parsed = parseResultBody(body);
      if (parsed === null || nonceS === null || nonceC === null) {
        finish({ authenticated: false, status: null, errorMessage: 'bad server result' });
        return;
      }
      const verified = verifyServerResult(
        args.verifyKey,
        args.identity,
        nonceS,
        nonceC,
        commandBytes,
        Buffer.from(parsed.result, 'utf8'),
        parsed.sig,
      );
      if (!verified) {
        finish({ authenticated: false, status: null, errorMessage: 'server authentication failed' });
        return;
      }
      if (!isControlResultStatus(parsed.result)) {
        finish({ authenticated: false, status: null, errorMessage: 'unknown server result' });
        return;
      }
      finish({ authenticated: true, status: parsed.result });
    };

    socket.setTimeout(args.timeoutMs);
    socket.on('timeout', () => {
      finish({ authenticated: false, status: null, errorMessage: 'connection timed out' });
    });
    socket.on('error', () => {
      finish({ authenticated: false, status: null, errorMessage: 'connection error' });
    });
    socket.on('close', () => {
      finish({ authenticated: false, status: null, errorMessage: 'connection closed' });
    });
    socket.on('data', (chunk: Buffer) => {
      if (state.settled) {
        return;
      }
      carry = carry.length === 0 ? chunk : Buffer.concat([carry, chunk]);
      for (;;) {
        if (carry.length < LENGTH_PREFIX_BYTES) {
          return;
        }
        const length = carry.readUInt32BE(0);
        if (length === 0 || length > MAX_BODY_BYTES) {
          finish({ authenticated: false, status: null, errorMessage: 'server framing error' });
          return;
        }
        const total = LENGTH_PREFIX_BYTES + length;
        if (carry.length < total) {
          return;
        }
        const body = carry.subarray(LENGTH_PREFIX_BYTES, total);
        carry = carry.subarray(total);
        // `finish` is idempotent and destroys the socket, so a stray extra frame
        // after settling re-enters harmlessly; the next iteration returns once
        // `carry` is drained below the length prefix.
        handleFrame(body);
      }
    });
  });
}

/**
 * Verify the anchor, discover the one live runtime, run the handshake, and
 * report a bounded outcome. Never prints `APPLIED` unless the server
 * authenticated; never sends the command when discovery is ambiguous.
 */
export async function runControlCli(deps: RunControlCliDeps = {}): Promise<ControlCliOutcome> {
  const env = deps.env ?? process.env;
  const verify = deps.verify ?? verifyControlAnchor;
  const probePipe = deps.probePipe ?? defaultPipeProbe();
  const connect = deps.connect ?? defaultConnect;
  const nonceGen = deps.nonceGen ?? ((): Buffer => randomBytes(NONCE_BYTES));
  const timeoutMs = deps.timeoutMs ?? DEFAULT_CONNECTION_TIMEOUT_MS;
  const out = deps.out ?? ((message: string): void => {
    console.log(message);
  });
  const err = deps.err ?? ((message: string): void => {
    console.error(message);
  });

  const verification = await verify({ env });
  if (!verification.ok) {
    err(`agentbridge-control: control channel unavailable (${verification.reason}).`);
    return { exitCode: 1, status: null, authenticated: false };
  }

  const discovery = await discoverControlRuntime(
    verification.anchorPath,
    probePipe,
    deps.descriptorDeps,
  );
  if (discovery.kind === 'UNAVAILABLE') {
    err(`agentbridge-control: no live control runtime found (${discovery.reason}).`);
    return { exitCode: 1, status: null, authenticated: false };
  }
  if (discovery.kind === 'AMBIGUOUS') {
    err(
      `agentbridge-control: ambiguous control runtime (${String(discovery.live.length)} live ` +
        'descriptors); refusing to choose.',
    );
    return { exitCode: 1, status: null, authenticated: false };
  }

  const outcome = await runClientProtocol({
    connect,
    pipePath: pipePathFromName(discovery.parsed.descriptor.pipeName),
    identity: {
      runtimeId: discovery.parsed.runtimeId,
      pipeName: discovery.parsed.descriptor.pipeName,
    },
    token: discovery.parsed.token,
    verifyKey: discovery.parsed.verifyKey,
    nonceGen,
    timeoutMs,
  });

  if (!outcome.authenticated || outcome.status === null) {
    err(`agentbridge-control: ${outcome.errorMessage ?? 'server authentication failed'}.`);
    return { exitCode: 1, status: null, authenticated: false };
  }

  out(`agentbridge-control: OPEN_HUMAN_GATE -> ${outcome.status}`);
  return {
    exitCode: outcome.status === CONTROL_RESULT.APPLIED ? 0 : 1,
    status: outcome.status,
    authenticated: true,
  };
}

/**
 * The complete CLI flow with the process exit code applied. Invoked ONLY by the
 * dedicated entry wrapper `cli-main.ts`; this module never runs it on import, so
 * it stays a plain library (tests import `runControlCli`). There is deliberately
 * no entry-identity predicate here: comparing `import.meta.url`, `argv[1]`, or
 * realpaths is alias-sensitive and racy, and a false "not entry" decision was a
 * silent exit 0 — violating EXIT 0 ⇒ APPLIED.
 */
export async function cliMain(): Promise<void> {
  const outcome = await runControlCli();
  process.exitCode = outcome.exitCode;
}
