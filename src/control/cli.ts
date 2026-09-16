/**
 * The official `agentbridge-control` CLI — the only supported client of the
 * Decision 062 control channel (direct third-party pipe clients are
 * unsupported).
 *
 * It may only: verify the hardened control anchor, discover the one live
 * identity-named descriptor, ATTEST the pipe that descriptor points at, connect
 * to that same pipe, perform the handshake, submit **one** `OPEN_HUMAN_GATE`,
 * authenticate the server response, and print a bounded result. It constructs no
 * `WorkflowEvent`, holds no `WorkflowState` authority, accepts no arbitrary
 * event, and takes no commit/repository/workflow selector as command authority.
 * It runs no Git, GitHub, shell, or process command other than the two
 * build-provenanced read-only native artifacts, and never deletes a descriptor.
 *
 * Discovery is bounded and deterministic (see `discoverControlRuntime`): every
 * `runtime-descriptor-<id>.json` in the verified anchor is parsed safely, each
 * valid candidate's pipe is probed, and the command is sent only when EXACTLY ONE
 * candidate's pipe is live. Zero live candidates is "unavailable"; two or more is
 * "ambiguous" and fails closed. Nothing is chosen by mtime, PID, lexicographic
 * order, or last-writer-wins.
 *
 * ## The descriptor is a hint; the pipe is the evidence (DDR-D062-B)
 *
 * Nothing in a descriptor is treated as a credential for the SERVER direction.
 * A descriptor supplies a pipe name to rendezvous at and a token to authorize
 * this client's command with — that is all it may do, and it carries no
 * `verifyKey` to trust even if someone plants one.
 *
 * Before any command is sent, the native pipe attestor is run against the
 * discovered pipe path. It connects, reads the OWNER and DACL of the kernel
 * pipe object behind THAT connected handle, and relays exactly one bounded
 * hello read from the SAME pipe handle. This CLI then requires:
 *
 *   1. the attested pipe OWNER to equal the trusted operator SID the anchor gate
 *      already resolved and proved owns the anchor, AND that object's DACL to be
 *      exactly the accepted protected operator-only descriptor (owner alone is
 *      not enough — see DDR-D062-D); and
 *   2. the command session's own hello to announce the VERY SAME `verifyKey`
 *      bytes the attested hello announced.
 *
 * (2) is what binds the second connection to the first: whether the kernel
 * routes a later connect to the same pipe instance or a different one, either
 * outcome must present the attested key or the session is abandoned. A runtime
 * that restarted between attestation and the command session mints a fresh
 * keypair and therefore fails (2).
 *
 * Only then is `OPEN_HUMAN_GATE` sent, MAC'd with the token (client-to-server
 * only), and the result is believed **only** when its Ed25519 `sigS` verifies
 * against the ATTESTED key over a transcript binding that runtime's id, pipe
 * name and key, both nonces, and the exact command and result bytes. A missing,
 * wrong, cross-runtime, or replayed signature is an authentication failure and
 * is never reported as `APPLIED`. There is no path by which a token-authenticated
 * result could be accepted, because no such primitive exists any more.
 *
 * Because the signing key is ephemeral and lives only in the genuine runtime's
 * memory, a party serving a squatted pipe with a byte-identical copy of a genuine
 * descriptor can neither pass attestation (wrong pipe owner, or a descriptor that
 * is not the accepted operator-only one) nor produce `sigS`, and can
 * never make this CLI exit 0. The CLI's own `nonceC` is fresh per connection, so
 * a signature harvested from a live runtime is useless here once that runtime is
 * gone.
 *
 * Every attestation, session, key, or signature failure is a nonzero exit with no
 * fallback to a weaker check.
 */

import net from 'node:net';
import { randomBytes } from 'node:crypto';

import {
  computeClientMac,
  macEqual,
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
  attestControlPipe,
  defaultPipeProbe,
  discoverControlRuntime,
  pipePathFromName,
  verifyControlAnchor,
  type AttestControlPipeDeps,
  type ControlAnchorVerification,
  type DescriptorFileDeps,
  type PipeAttestation,
  type PipeProbe,
  type VerifyControlAnchorDeps,
} from './control-store.js';

/** Connect to a pipe path, returning a socket. Injectable for tests. */
export type ConnectFn = (pipePath: string) => net.Socket;

const defaultConnect: ConnectFn = (pipePath: string): net.Socket => net.connect(pipePath);

/** Attest one live pipe against the trusted operator SID. Injectable for tests. */
export type AttestFn = (pipePath: string, operatorSid: string) => Promise<PipeAttestation>;

export interface RunControlCliDeps {
  readonly env?: NodeJS.ProcessEnv;
  readonly verify?: (deps: VerifyControlAnchorDeps) => Promise<ControlAnchorVerification>;
  readonly descriptorDeps?: DescriptorFileDeps;
  readonly probePipe?: PipeProbe;
  readonly attest?: AttestFn;
  readonly attestDeps?: AttestControlPipeDeps;
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
  /** Carries the ATTESTED verify key; the session hello must match it exactly. */
  readonly identity: ChannelIdentity;
  readonly token: Buffer;
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
        const hello = parseHelloBody(body);
        if (hello === null) {
          finish({ authenticated: false, status: null, errorMessage: 'bad server hello' });
          return;
        }
        // KEY BINDING. This session must be served by the same runtime identity
        // attestation proved, whichever pipe instance the kernel routed us to.
        // A takeover of the freed pipe name, or a restarted runtime that minted
        // a fresh keypair, announces different bytes and is abandoned here —
        // before the command is ever sent. (`macEqual` is a length-guarded
        // constant-time buffer compare; the key is public, but there is no
        // reason to compare it any less carefully.)
        if (!macEqual(hello.verifyKey, args.identity.verifyKey)) {
          finish({
            authenticated: false,
            status: null,
            errorMessage: 'server identity does not match the attested runtime',
          });
          return;
        }
        nonceS = hello.nonceS;
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
 * Verify the anchor, discover the one live runtime, attest the process serving
 * its pipe, run the handshake against the attested identity, and report a
 * bounded outcome. Never prints `APPLIED` unless the server authenticated with a
 * signature under the attested key; never sends the command when discovery is
 * ambiguous or attestation fails.
 */
export async function runControlCli(deps: RunControlCliDeps = {}): Promise<ControlCliOutcome> {
  const env = deps.env ?? process.env;
  const verify = deps.verify ?? verifyControlAnchor;
  const probePipe = deps.probePipe ?? defaultPipeProbe();
  const attest: AttestFn =
    deps.attest ??
    ((pipePath: string, operatorSid: string): Promise<PipeAttestation> =>
      attestControlPipe(pipePath, operatorSid, deps.attestDeps ?? { env }));
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

  const pipePath = pipePathFromName(discovery.parsed.descriptor.pipeName);

  // Attest the LIVE pipe before anything is sent to it. The descriptor got us
  // here; it grants nothing beyond that.
  const attestation = await attest(pipePath, verification.operatorSid);
  if (!attestation.ok) {
    err(`agentbridge-control: pipe attestation failed (${attestation.reason}).`);
    return { exitCode: 1, status: null, authenticated: false };
  }
  // The relayed hello is parsed by the SAME total parser the session hello uses,
  // so malformed, truncated, extra-keyed, or non-canonical relayed bytes fail
  // closed here rather than yielding a half-trusted key.
  const attestedHello = parseHelloBody(attestation.evidence.helloBody);
  if (attestedHello === null) {
    err('agentbridge-control: pipe attestation failed (ATTESTED_HELLO_MALFORMED).');
    return { exitCode: 1, status: null, authenticated: false };
  }

  const outcome = await runClientProtocol({
    connect,
    pipePath,
    identity: {
      runtimeId: discovery.parsed.runtimeId,
      pipeName: discovery.parsed.descriptor.pipeName,
      verifyKey: attestedHello.verifyKey,
    },
    token: discovery.parsed.token,
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
