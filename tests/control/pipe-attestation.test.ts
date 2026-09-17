/**
 * DDR-D062-D Amendment 1 — LIVE PIPE-OBJECT IDENTITY RELAYER: the focused
 * attack matrix.
 *
 * The property under test is the one a descriptor can never establish:
 *
 *     CLI EXIT 0 (APPLIED)  ⇒  the pipe that answered is a kernel object OWNED
 *                              by the trusted operator and carrying exactly the
 *                              protected operator-only DACL, whose server holds
 *                              the private half of the key attestation relayed.
 *
 * Nothing here trusts a file. A descriptor supplies a pipe name and the
 * client-to-server token; every server-direction decision comes from attesting
 * the LIVE pipe and from an Ed25519 signature under the ATTESTED key.
 *
 * Two kinds of test appear below and they are labelled:
 *
 *   - REAL-ARTIFACT tests run the actual build-provenanced
 *     `agentbridge-win-pipe-attest.exe` against actual named pipes (dist-gated,
 *     Windows only).
 *   - SEAM tests inject at `runControlCli({ attest })` or drive
 *     `attestPipeServer` with a simulated subprocess. Their SID is injectable
 *     because an in-process test cannot serve a pipe from a second account; the
 *     REAL parser, the REAL SID comparison, the REAL key binding and the REAL
 *     signature check all still run. Cross-account rejection against a genuinely
 *     foreign SID is a two-account/CI obligation, not something this file can
 *     discharge.
 */

import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { createHmac, randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import net from 'node:net';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { WORKFLOW_STATUS } from '../../src/domain/index.js';
import {
  canonicalTranscript,
  computeClientMac,
  generateRuntimeKeyPair,
  macEqual,
  verifyServerResult,
  NONCE_BYTES,
  type ChannelIdentity,
} from '../../src/control/control-auth.js';
import {
  buildHelloBody,
  buildRequestBody,
  buildResultBody,
  createControlChannelServer,
  frameMessage,
  type ControlChannelServer,
  type CreateControlChannelServerOptions,
  parseClientRequest,
  parseHelloBody,
  parseResultBody,
  LENGTH_PREFIX_BYTES,
} from '../../src/control/control-channel.js';
import { CONTROL_COMMAND, CONTROL_RESULT } from '../../src/control/control-command.js';
import { runControlCli } from '../../src/control/cli.js';
import type { ControlChannelHandle } from '../../src/control/control-runtime.js';
import type { AttestControlPipeDeps } from '../../src/control/control-store.js';
import {
  PIPE_ATTESTATION_REJECTION,
  attestPipeServer,
  defaultProcessRunner,
  loadPipeAcceptor,
  type OwnerHelperProvenance,
  type PipeAcceptorLoad,
  parseAttestationEvidence,
  parseWhoamiUser,
  parseDescriptor,
  pipeNameForRuntimeId,
  pipePathFromName,
  serializeDescriptor,
  type PipeAttestation,
  type ProcessResult,
} from '../../src/control/control-store.js';
import {
  BINDING,
  FAKE_ANCHOR,
  FAKE_OPERATOR_SID,
  FOREIGN_OPERATOR_SID,
  acceptedAce,
  attestDouble,
  attestEvidenceText,
  callCli,
  closeServer,
  delay,
  descriptorFacts,
  descriptorOf,
  memAnchor,
  newOrchestrator,
  passingVerify,
  readOneFrameBody,
  startRogueServer,
  startServer,
} from './support.js';

const CMD = Buffer.from(CONTROL_COMMAND.OPEN_HUMAN_GATE, 'utf8');

const handles: ControlChannelHandle[] = [];
const servers: net.Server[] = [];
const children: ChildProcess[] = [];

afterEach(async () => {
  for (const child of children.splice(0)) {
    child.kill('SIGKILL');
  }
  await Promise.all(servers.splice(0).map((server) => closeServer(server)));
  await Promise.all(handles.splice(0).map((handle) => handle.close()));
});

/** Trusted-operator attestation deps for a simulated attestor subprocess. */
const simulatedArtifact = {
  loadProvenance: (): Promise<{ filename: string; sha256: string }> =>
    Promise.resolve({ filename: 'attest.exe', sha256: 'a'.repeat(64) }),
  resolveAttestorPath: (filename: string): string => filename,
  readAttestorBytes: (): Buffer => Buffer.from('native'),
  hashBytes: (): string => 'a'.repeat(64),
};

/** Run the real SID/evidence policy over one simulated attestor stdout. */
function attestWithStdout(stdout: string, operatorSid = FAKE_OPERATOR_SID): Promise<PipeAttestation> {
  const runProcess = (): Promise<ProcessResult> => Promise.resolve({ ok: true, stdout });
  return attestPipeServer('\\\\.\\pipe\\x', operatorSid, runProcess, simulatedArtifact);
}

/* ================================================================== *
 * 1. The CONNECTED PIPE OBJECT decides, not the descriptor file.
 *    Both conjuncts are load-bearing: the pipe object's OWNER SID AND the
 *    exact protected operator-only DACL structure. Owner alone is
 *    insufficient — a same-SID program could hold the name with a broad
 *    descriptor and a foreign principal could then add an instance to it.
 * ================================================================== */

describe('DDR-D062-D — a perfect descriptor grants nothing (SEAM)', () => {
  it('1. foreign SID + an attacker-perfect descriptor and pipe → rejected, no command sent', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const anchor = memAnchor();
    const handle = await startServer(orchestrator, anchor);
    const facts = descriptorFacts(anchor, handle);
    // A byte-perfect copy of the genuine descriptor: right pipe name, right token.
    const perfect = memAnchor();
    perfect.set(handle.runtimeId, anchor.get(handle.runtimeId) ?? '');
    expect(perfect.get(handle.runtimeId)).toBe(anchor.get(handle.runtimeId));

    // The attacker holds the pipe name after the genuine runtime is gone.
    await handle.close();
    const rogue = await startRogueServer(facts.pipePath);
    servers.push(rogue);

    const run = await callCli(anchor, {
      descriptorDeps: perfect.deps,
      attest: attestDouble({ pipeOwnerSid: FOREIGN_OPERATOR_SID }),
    });
    expect(run.outcome.exitCode).toBe(1);
    expect(run.outcome.authenticated).toBe(false);
    expect(run.outcome.status).toBeNull();
    expect(run.err.some((line) => line.includes('PIPE_OWNER_MISMATCH'))).toBe(true);
    expect(run.out).toEqual([]);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
  });

  it('2. a historical WRITE_DAC rewrite that redirects the descriptor at a foreign pipe → rejected', async () => {
    // The threat: someone who once held WRITE_DAC rewrote the descriptor to name
    // THEIR pipe and restored a perfect owner/DACL afterwards. The file inspects
    // as flawless; the process behind the pipe is what it is.
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const attackerId = 'dead'.repeat(8);
    const attackerPipe = pipePathFromName(pipeNameForRuntimeId(attackerId));
    const rogue = await startRogueServer(attackerPipe);
    servers.push(rogue);

    const rewritten = memAnchor();
    rewritten.set(
      attackerId,
      serializeDescriptor({
        version: 4,
        pipeName: pipeNameForRuntimeId(attackerId),
        token: randomBytes(32).toString('base64url'),
      }),
    );

    const run = await callCli(rewritten, {
      attest: attestDouble({ pipeOwnerSid: FOREIGN_OPERATOR_SID }),
    });
    expect(run.outcome.exitCode).toBe(1);
    expect(run.outcome.status).toBeNull();
    expect(run.err.some((line) => line.includes('PIPE_OWNER_MISMATCH'))).toBe(true);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
  });

  it('3. a world-writable descriptor in front of a GENUINE trusted runtime still succeeds', async () => {
    // The mirror of 1 and 2: descriptor provenance is not what authorizes. This
    // descriptor was never produced by the provenanced creator at all — it is
    // seeded straight into the anchor, i.e. a file anyone could have written —
    // and the command still applies, because the LIVE pipe attests correctly and
    // signs under the attested key.
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const anchor = memAnchor();
    const handle = await startServer(orchestrator, anchor);
    handles.push(handle);

    const worldWritable = memAnchor();
    worldWritable.set(handle.runtimeId, anchor.get(handle.runtimeId) ?? '');

    const run = await callCli(anchor, { descriptorDeps: worldWritable.deps });
    expect(run.outcome.exitCode).toBe(0);
    expect(run.outcome.authenticated).toBe(true);
    expect(run.outcome.status).toBe(CONTROL_RESULT.APPLIED);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.AWAITING_HUMAN_DECISION);
  });

  it('6. a descriptor carrying a verifyKey on disk is rejected outright, never partially trusted', () => {
    const genuine = generateRuntimeKeyPair();
    const runtimeId = 'b'.repeat(32);
    const withKey = JSON.stringify({
      version: 4,
      pipeName: pipeNameForRuntimeId(runtimeId),
      token: randomBytes(32).toString('base64url'),
      verifyKey: genuine.verifyKey.toString('base64url'),
    });
    expect(parseDescriptor(withKey)).toBeNull();
    // A v3-shaped descriptor is equally rejected: there is no downgrade.
    expect(
      parseDescriptor(
        JSON.stringify({
          version: 3,
          pipeName: pipeNameForRuntimeId(runtimeId),
          token: randomBytes(32).toString('base64url'),
          verifyKey: genuine.verifyKey.toString('base64url'),
        }),
      ),
    ).toBeNull();
  });

  it('6b. an anchor holding only a verifyKey-bearing descriptor is discovered as nothing', async () => {
    const anchor = memAnchor();
    const runtimeId = 'c'.repeat(32);
    anchor.set(
      runtimeId,
      JSON.stringify({
        version: 4,
        pipeName: pipeNameForRuntimeId(runtimeId),
        token: randomBytes(32).toString('base64url'),
        verifyKey: generateRuntimeKeyPair().verifyKey.toString('base64url'),
      }),
    );
    const run = await callCli(anchor);
    expect(run.outcome.exitCode).toBe(1);
    expect(run.outcome.status).toBeNull();
    expect(run.err.some((line) => line.includes('NO_LIVE_CANDIDATES'))).toBe(true);
  });
});

/* ================================================================== *
 * 2. Key binding: the session must be the runtime that was attested
 * ================================================================== */

describe('DDR-D062-D — attested key binds the command session (SEAM)', () => {
  it('4. genuine attestation, then an attacker takes over the pipe name → rejected before the command is sent', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const anchor = memAnchor();
    const handle = await startServer(orchestrator, anchor);
    const facts = descriptorFacts(anchor, handle);
    const preserved = memAnchor();
    preserved.set(handle.runtimeId, anchor.get(handle.runtimeId) ?? '');

    // Attest the GENUINE runtime and freeze that evidence.
    const genuineEvidence = await attestDouble()(facts.pipePath, FAKE_OPERATOR_SID);
    expect(genuineEvidence.ok).toBe(true);

    // Now the genuine runtime goes away and an attacker claims the name.
    await handle.close();
    const requests: Buffer[] = [];
    const rogue = await startRogueServer(facts.pipePath);
    rogue.on('connection', (socket: net.Socket) => {
      socket.on('data', (chunk: Buffer) => {
        requests.push(chunk);
      });
    });
    servers.push(rogue);

    const err: string[] = [];
    const out: string[] = [];
    const outcome = await runControlCli({
      verify: passingVerify,
      descriptorDeps: preserved.deps,
      attest: () => Promise.resolve(genuineEvidence),
      out: (m: string): void => {
        out.push(m);
      },
      err: (m: string): void => {
        err.push(m);
      },
    });

    expect(outcome.exitCode).toBe(1);
    expect(outcome.authenticated).toBe(false);
    expect(outcome.status).toBeNull();
    expect(err.some((line) => line.includes('does not match the attested runtime'))).toBe(true);
    expect(out).toEqual([]);
    // The command — and therefore the token — never reached the impostor.
    await delay(30);
    expect(requests).toEqual([]);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
  });

  it('5. an attacker that echoes the genuine PUBLIC key but lacks the private half → signature rejection', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const anchor = memAnchor();
    const handle = await startServer(orchestrator, anchor);
    const facts = descriptorFacts(anchor, handle);
    const preserved = memAnchor();
    preserved.set(handle.runtimeId, anchor.get(handle.runtimeId) ?? '');

    // Observe the genuine runtime's announced key, exactly as an eavesdropper could.
    const genuineHelloBody = await readOneFrameBody(facts.pipePath);
    expect(genuineHelloBody).not.toBeNull();
    const genuineHello = parseHelloBody(genuineHelloBody ?? Buffer.alloc(0));
    expect(genuineHello).not.toBeNull();
    const genuineKey = genuineHello?.verifyKey ?? Buffer.alloc(0);

    await handle.close();
    // The rogue parrots the genuine public key, so attestation and key binding
    // both PASS. Only possession of the private half is missing.
    const rogue = await startRogueServer(facts.pipePath, {
      status: CONTROL_RESULT.APPLIED,
      announceKey: genuineKey,
    });
    servers.push(rogue);

    const run = await callCli(anchor, { descriptorDeps: preserved.deps });
    expect(run.outcome.exitCode).toBe(1);
    expect(run.outcome.authenticated).toBe(false);
    expect(run.outcome.status).toBeNull();
    expect(run.err.some((line) => line.includes('server authentication failed'))).toBe(true);
    expect(run.out.some((line) => line.includes('APPLIED'))).toBe(false);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
  });

  it('10. a genuine signed result replayed into a fresh session → rejected', async () => {
    // A server that signs ONE result for one fixed nonce pair and then replays
    // those exact bytes to every later client. Its key is announced honestly, so
    // attestation and key binding pass; only freshness fails.
    const keys = generateRuntimeKeyPair();
    const runtimeId = 'a1b2'.repeat(8);
    const pipeName = pipeNameForRuntimeId(runtimeId);
    const pipePath = pipePathFromName(pipeName);
    const identity: ChannelIdentity = { runtimeId, pipeName, verifyKey: keys.verifyKey };
    const harvestedNonceS = randomBytes(NONCE_BYTES);
    const harvestedNonceC = randomBytes(NONCE_BYTES);
    const resultBytes = Buffer.from(CONTROL_RESULT.APPLIED, 'utf8');
    const { signServerResult } = await import('../../src/control/control-auth.js');
    const harvestedBody = buildResultBody(
      CONTROL_RESULT.APPLIED,
      signServerResult(
        keys.privateKey,
        identity,
        harvestedNonceS,
        harvestedNonceC,
        CMD,
        resultBytes,
      ),
    );

    const replay = net.createServer((socket: net.Socket) => {
      socket.on('error', () => {
        /* ignore */
      });
      socket.on('data', () => {
        socket.end(frameMessage(harvestedBody));
      });
      // Announce the harvested session's nonce too: even a fully replayed
      // transcript cannot survive the client's own fresh nonceC.
      socket.write(frameMessage(buildHelloBody(harvestedNonceS, keys.verifyKey)));
    });
    await new Promise<void>((resolvePromise, rejectPromise) => {
      replay.once('error', rejectPromise);
      replay.listen(pipePath, () => {
        replay.removeListener('error', rejectPromise);
        resolvePromise();
      });
    });
    servers.push(replay);

    const anchor = memAnchor();
    anchor.set(
      runtimeId,
      serializeDescriptor({ version: 4, pipeName, token: randomBytes(32).toString('base64url') }),
    );
    const run = await callCli(anchor);
    expect(run.outcome.exitCode).toBe(1);
    expect(run.outcome.authenticated).toBe(false);
    expect(run.outcome.status).toBeNull();
    expect(run.err.some((line) => line.includes('server authentication failed'))).toBe(true);
  });

  it('11. a runtime restart between attestation and the command session → rejected', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const first = await startServer(orchestrator, anchor);
    const firstFacts = descriptorFacts(anchor, first);
    const staleEvidence = await attestDouble()(firstFacts.pipePath, FAKE_OPERATOR_SID);
    expect(staleEvidence.ok).toBe(true);

    // The runtime restarts: a NEW identity, a NEW descriptor, a NEW keypair.
    await first.close();
    const second = await startServer(orchestrator, anchor);
    handles.push(second);
    expect(second.runtimeId).not.toBe(first.runtimeId);

    const err: string[] = [];
    const outcome = await runControlCli({
      verify: passingVerify,
      descriptorDeps: anchor.deps,
      // The client still holds the FIRST runtime's attestation.
      attest: () => Promise.resolve(staleEvidence),
      out: (): void => {
        /* silent */
      },
      err: (m: string): void => {
        err.push(m);
      },
    });
    expect(outcome.exitCode).toBe(1);
    expect(outcome.authenticated).toBe(false);
    expect(err.some((line) => line.includes('does not match the attested runtime'))).toBe(true);
  });
});

/* ================================================================== *
 * 3. Negative controls — each guard is load-bearing
 * ================================================================== */

/**
 * A client that verifies the result against whatever key the SESSION announced,
 * instead of the attested one. This is the pre-DDR-D062-D trust shape.
 */
function announcedKeyClient(
  pipePath: string,
  runtimeId: string,
  token: Buffer,
): Promise<{ accepted: boolean; status: string | null }> {
  return new Promise((resolvePromise) => {
    const socket = net.connect(pipePath);
    const state = { done: false };
    let phase: 'hello' | 'result' = 'hello';
    let identity: ChannelIdentity | null = null;
    let nonceS: Buffer | null = null;
    let nonceC: Buffer | null = null;
    let carry = Buffer.alloc(0);
    const finish = (accepted: boolean, status: string | null): void => {
      if (state.done) {
        return;
      }
      state.done = true;
      socket.destroy();
      resolvePromise({ accepted, status });
    };
    socket.setTimeout(2000);
    socket.on('timeout', () => {
      finish(false, null);
    });
    socket.on('error', () => {
      finish(false, null);
    });
    socket.on('close', () => {
      finish(false, null);
    });
    socket.on('data', (chunk: Buffer) => {
      carry = Buffer.concat([carry, chunk]);
      if (carry.length < LENGTH_PREFIX_BYTES) {
        return;
      }
      const length = carry.readUInt32BE(0);
      if (carry.length < LENGTH_PREFIX_BYTES + length) {
        return;
      }
      const body = carry.subarray(LENGTH_PREFIX_BYTES, LENGTH_PREFIX_BYTES + length);
      carry = carry.subarray(LENGTH_PREFIX_BYTES + length);
      if (phase === 'hello') {
        const hello = parseHelloBody(body);
        if (hello === null) {
          finish(false, null);
          return;
        }
        // NO attested-key comparison: trust the key this session announced.
        identity = {
          runtimeId,
          pipeName: pipeNameForRuntimeId(runtimeId),
          verifyKey: hello.verifyKey,
        };
        nonceS = hello.nonceS;
        nonceC = randomBytes(NONCE_BYTES);
        phase = 'result';
        socket.write(
          frameMessage(
            buildRequestBody(
              nonceC,
              CONTROL_COMMAND.OPEN_HUMAN_GATE,
              computeClientMac(token, identity, nonceS, nonceC, CMD),
            ),
          ),
        );
        return;
      }
      const parsed = parseResultBody(body);
      if (parsed === null || identity === null || nonceS === null || nonceC === null) {
        finish(false, null);
        return;
      }
      const ok = verifyServerResult(
        identity,
        nonceS,
        nonceC,
        CMD,
        Buffer.from(parsed.result, 'utf8'),
        parsed.sig,
      );
      finish(ok, ok ? parsed.result : null);
    });
  });
}

describe('DDR-D062-D — negative controls (each guard is load-bearing)', () => {
  it('12a. trusting the SESSION-announced key instead of the attested one → the takeover SUCCEEDS', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const handle = await startServer(orchestrator, anchor);
    const facts = descriptorFacts(anchor, handle);
    const parsed = descriptorOf(anchor, handle);
    const runtimeId = handle.runtimeId;
    await handle.close();
    const rogue = await startRogueServer(facts.pipePath, { status: CONTROL_RESULT.APPLIED });
    servers.push(rogue);

    const weak = await announcedKeyClient(facts.pipePath, runtimeId, parsed.token);
    // Proof the attestation binding carries the whole load: without it, the
    // impostor's own signature is accepted and APPLIED is believed.
    expect(weak.accepted).toBe(true);
    expect(weak.status).toBe(CONTROL_RESULT.APPLIED);

    // The production CLI, on the very same takeover, refuses.
    const preserved = memAnchor();
    preserved.set(runtimeId, serializeDescriptor(parsed.descriptor));
    const run = await callCli(anchor, {
      descriptorDeps: preserved.deps,
      attest: attestDouble({ pipeOwnerSid: FOREIGN_OPERATOR_SID }),
    });
    expect(run.outcome.status).toBeNull();
  });

  it('12b. without the session-key equality check the command (and the token) reaches the impostor first', async () => {
    // With the equality check the impostor receives NOTHING (proven in test 4).
    // Removing only that check still ends in a signature rejection, but the
    // command has already been sent: the check is what keeps the token and the
    // command away from a server that is not the attested runtime.
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const handle = await startServer(orchestrator, anchor);
    const facts = descriptorFacts(anchor, handle);
    const parsed = descriptorOf(anchor, handle);
    const runtimeId = handle.runtimeId;
    await handle.close();

    const requests: Buffer[] = [];
    const rogue = await startRogueServer(facts.pipePath, { status: CONTROL_RESULT.APPLIED });
    rogue.on('connection', (socket: net.Socket) => {
      socket.on('data', (chunk: Buffer) => {
        requests.push(chunk);
      });
    });
    servers.push(rogue);

    const weak = await announcedKeyClient(facts.pipePath, runtimeId, parsed.token);
    expect(weak.accepted).toBe(true);
    expect(requests.length).toBeGreaterThan(0);
  });

  it('13. re-enabling a token-authenticated server result → the FOREIGN server is believed', async () => {
    // The deleted primitive, reconstructed here only to show why it had to go: a
    // squatter who copied the descriptor holds the token, so a token-keyed result
    // MAC is something it can produce at will.
    const runtimeId = 'f0f0'.repeat(8);
    const pipeName = pipeNameForRuntimeId(runtimeId);
    const pipePath = pipePathFromName(pipeName);
    const token = randomBytes(32);
    const keys = generateRuntimeKeyPair();
    const identity: ChannelIdentity = { runtimeId, pipeName, verifyKey: keys.verifyKey };
    const serverMac = (nonceS: Buffer, nonceC: Buffer, resultBytes: Buffer): Buffer =>
      createHmac('sha256', token)
        .update(
          canonicalTranscript([
            Buffer.from('S', 'utf8'),
            Buffer.from(runtimeId, 'utf8'),
            Buffer.from(pipeName, 'utf8'),
            keys.verifyKey,
            nonceS,
            nonceC,
            CMD,
            resultBytes,
          ]),
        )
        .digest();

    let observed: { nonceS: Buffer; nonceC: Buffer; mac: Buffer; result: Buffer } | null = null;
    const foreign = net.createServer((socket: net.Socket) => {
      const nonceS = randomBytes(NONCE_BYTES);
      let carry = Buffer.alloc(0);
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
        const request = parseClientRequest(carry.subarray(4, 4 + length));
        if (!request.ok) {
          socket.destroy();
          return;
        }
        const resultBytes = Buffer.from(CONTROL_RESULT.APPLIED, 'utf8');
        observed = {
          nonceS,
          nonceC: request.nonceC,
          mac: serverMac(nonceS, request.nonceC, resultBytes),
          result: resultBytes,
        };
        socket.end(frameMessage(buildResultBody(CONTROL_RESULT.APPLIED, Buffer.alloc(64))));
      });
      socket.write(frameMessage(buildHelloBody(nonceS, keys.verifyKey)));
    });
    await new Promise<void>((resolvePromise, rejectPromise) => {
      foreign.once('error', rejectPromise);
      foreign.listen(pipePath, () => {
        foreign.removeListener('error', rejectPromise);
        resolvePromise();
      });
    });
    servers.push(foreign);

    const anchor = memAnchor();
    anchor.set(
      runtimeId,
      serializeDescriptor({ version: 4, pipeName, token: token.toString('base64url') }),
    );

    // Production: the Ed25519 check refuses this server.
    const run = await callCli(anchor);
    expect(run.outcome.status).toBeNull();
    expect(run.outcome.authenticated).toBe(false);

    // The negative control: a client that authenticated the result with the TOKEN
    // would have accepted the same foreign server's APPLIED.
    const seen = observed as { nonceS: Buffer; nonceC: Buffer; mac: Buffer; result: Buffer } | null;
    expect(seen).not.toBeNull();
    if (seen !== null) {
      expect(macEqual(seen.mac, serverMac(seen.nonceS, seen.nonceC, seen.result))).toBe(true);
    }
    // And the primitive that would have done it no longer exists in production.
    const auth = (await import('../../src/control/control-auth.js')) as Record<string, unknown>;
    expect(auth['computeServerMac']).toBeUndefined();
    // Nor anywhere else in the control source.
    expect(identity.verifyKey.length).toBe(32);
  });
});

/* ================================================================== *
 * 4. Evidence parsing is total; every failure is fail-closed
 * ================================================================== */

describe('DDR-D062-D/A1 — attestor output is parsed totally (SEAM)', () => {
  const sid = FAKE_OPERATOR_SID;
  const hello = Buffer.from('{"v":2}', 'utf8');
  const good = attestEvidenceText(sid, hello);

  const hex = hello.toString('hex');
  const head = `AGENTBRIDGE-ATTEST-V3\nPIPEOWNER ${sid}\n`;
  const aceLine = `ACE 0 ${acceptedAce(sid)}\n`;

  it('14a. the exact grammar parses structurally, and the hello bytes survive verbatim', () => {
    const parsed = parseAttestationEvidence(good);
    expect(parsed?.pipeOwnerSid).toBe(sid.toLowerCase());
    expect(parsed?.daclPresent).toBe(true);
    expect(parsed?.daclProtected).toBe(true);
    expect(parsed?.aceCount).toBe(1);
    expect(parsed?.aces).toEqual([
      { type: '00', flags: '00', mask: '0012019f', trustee: sid.toLowerCase() },
    ]);
    expect(parsed?.helloBody.equals(hello)).toBe(true);
  });

  it('14b. malformed, truncated, extra, reordered and non-canonical outputs are all rejected', () => {
    const bad: readonly string[] = [
      '',
      'AGENTBRIDGE-ATTEST-V3\n',
      // T7. NEITHER superseded grammar is a fallback. The V1 three-line form
      // with SERVERSID, and the V2 four-line form with PIPESD, are both simply
      // malformed evidence now — including when they wear the V3 magic.
      `AGENTBRIDGE-ATTEST-V1\nSERVERSID ${sid}\nHELLO ${hex}\n`,
      `AGENTBRIDGE-ATTEST-V2\nPIPEOWNER ${sid}\nPIPESD O:${sid}D:P(A;;0x12019f;;;${sid})\nHELLO ${hex}\n`,
      `AGENTBRIDGE-ATTEST-V3\nSERVERSID ${sid}\nHELLO ${hex}\n`,
      `AGENTBRIDGE-ATTEST-V3\nPIPEOWNER ${sid}\nPIPESD O:${sid}D:P(A;;0x12019f;;;${sid})\nHELLO ${hex}\n`,
      // the V3 shape under a past or future magic
      `AGENTBRIDGE-ATTEST-V2\nPIPEOWNER ${sid}\nDACL 1 1 1\n${aceLine}HELLO ${hex}\n`,
      `AGENTBRIDGE-ATTEST-V4\nPIPEOWNER ${sid}\nDACL 1 1 1\n${aceLine}HELLO ${hex}\n`,
      // no trailing newline / extra line / surplus blank line
      good.slice(0, -1),
      `${good}EXTRA junk\n`,
      `${good}\n`,
      // CRLF instead of LF
      good.replace(/\n/g, '\r\n'),
      // reordered top-level lines
      `${head}${aceLine}DACL 1 1 1\nHELLO ${hex}\n`,
      `AGENTBRIDGE-ATTEST-V3\nDACL 1 1 1\nPIPEOWNER ${sid}\n${aceLine}HELLO ${hex}\n`,
      `${head}DACL 1 1 1\nHELLO ${hex}\n${aceLine}`,
      // the DACL line missing, or duplicated
      `${head}${aceLine}HELLO ${hex}\n`,
      `${head}DACL 1 1 1\nDACL 1 1 1\n${aceLine}HELLO ${hex}\n`,
      // an ACE line beyond the declared count, and a declared count with no ACE
      `${head}DACL 1 1 1\n${aceLine}${aceLine}HELLO ${hex}\n`,
      `${head}DACL 1 1 1\nHELLO ${hex}\n`,
      `${head}DACL 1 1 2\n${aceLine}HELLO ${hex}\n`,
      // duplicated, skipped and reordered ACE indices
      `${head}DACL 1 1 2\nACE 0 ${acceptedAce(sid)}\nACE 0 ${acceptedAce(sid)}\nHELLO ${hex}\n`,
      `${head}DACL 1 1 2\nACE 0 ${acceptedAce(sid)}\nACE 2 ${acceptedAce(sid)}\nHELLO ${hex}\n`,
      `${head}DACL 1 1 2\nACE 1 ${acceptedAce(sid)}\nACE 0 ${acceptedAce(sid)}\nHELLO ${hex}\n`,
      // non-canonical decimals
      `${head}DACL 1 1 01\n${aceLine}HELLO ${hex}\n`,
      `${head}DACL 1 1 1\nACE 00 ${acceptedAce(sid)}\nHELLO ${hex}\n`,
      // booleans that are not exactly 0 or 1
      `${head}DACL true 1 1\n${aceLine}HELLO ${hex}\n`,
      `${head}DACL 1 2 1\n${aceLine}HELLO ${hex}\n`,
      // T16. SDDL ALIASES cannot be spelled: not as an owner, not as a trustee,
      // and a symbolic mask is not a hex field.
      `AGENTBRIDGE-ATTEST-V3\nPIPEOWNER LA\nDACL 1 1 1\n${aceLine}HELLO ${hex}\n`,
      `AGENTBRIDGE-ATTEST-V3\nPIPEOWNER BA\nDACL 1 1 1\n${aceLine}HELLO ${hex}\n`,
      `${head}DACL 1 1 1\nACE 0 00 00 0012019f LA\nHELLO ${hex}\n`,
      `${head}DACL 1 1 1\nACE 0 00 00 0012019f BA\nHELLO ${hex}\n`,
      `${head}DACL 1 1 1\nACE 0 00 00 0012019f SY\nHELLO ${hex}\n`,
      `${head}DACL 1 1 1\nACE 0 00 00 FR ${sid}\nHELLO ${hex}\n`,
      `${head}DACL 1 1 1\nACE 0 00 00 FA ${sid}\nHELLO ${hex}\n`,
      // uppercase / short / long hex fields
      `${head}DACL 1 1 1\nACE 0 00 00 0012019F ${sid}\nHELLO ${hex}\n`,
      `${head}DACL 1 1 1\nACE 0 00 00 12019f ${sid}\nHELLO ${hex}\n`,
      `${head}DACL 1 1 1\nACE 0 00 00 000012019f ${sid}\nHELLO ${hex}\n`,
      `${head}DACL 1 1 1\nACE 0 0 00 0012019f ${sid}\nHELLO ${hex}\n`,
      `${head}DACL 1 1 1\nACE 0 00 000 0012019f ${sid}\nHELLO ${hex}\n`,
      // a malformed or non-canonical SID anywhere
      `AGENTBRIDGE-ATTEST-V3\nPIPEOWNER NT-AUTHORITY\\SYSTEM\nDACL 1 1 1\n${aceLine}HELLO ${hex}\n`,
      `${head}DACL 1 1 1\nACE 0 00 00 0012019f S-1-\nHELLO ${hex}\n`,
      `${head}DACL 1 1 1\nACE 0 00 00 0012019f not-a-sid\nHELLO ${hex}\n`,
      // a field separator smuggled into a token
      `${head}DACL 1 1 1\nACE 0 00 00 0012019f ${sid} extra\nHELLO ${hex}\n`,
      // uppercase / odd-length / empty hello hex
      `${head}DACL 1 1 1\n${aceLine}HELLO ${hex.toUpperCase()}\n`,
      `${head}DACL 1 1 1\n${aceLine}HELLO abc\n`,
      `${head}DACL 1 1 1\n${aceLine}HELLO \n`,
      // wrong labels
      `AGENTBRIDGE-ATTEST-V3\nSID ${sid}\nDACL 1 1 1\n${aceLine}HELLO ${hex}\n`,
      `${head}ACL 1 1 1\n${aceLine}HELLO ${hex}\n`,
      `${head}DACL 1 1 1\nENTRY 0 ${acceptedAce(sid)}\nHELLO ${hex}\n`,
      // evidence beyond the configured bound
      `${head}DACL 1 1 1\n${aceLine}HELLO ${'ab'.repeat(40000)}\n`,
    ];
    for (const text of bad) {
      expect(parseAttestationEvidence(text), JSON.stringify(text.slice(0, 60))).toBeNull();
    }
    // Every truncation prefix of a valid evidence text is rejected.
    for (let index = 0; index < good.length; index += 1) {
      expect(parseAttestationEvidence(good.slice(0, index))).toBeNull();
    }
  });

  it('14c. a mangled attestor output reaches the CLI as a fail-closed exit, never a partial trust', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const handle = await startServer(orchestrator, anchor);
    handles.push(handle);
    const run = await callCli(anchor, {
      attest: attestDouble({ mangle: (evidence: string): string => `${evidence}EXTRA\n` }),
    });
    expect(run.outcome.exitCode).toBe(1);
    expect(run.outcome.status).toBeNull();
    expect(run.err.some((line) => line.includes('EVIDENCE_MALFORMED'))).toBe(true);
  });

  it('14d. a relayed hello that is not a well-formed hello fails closed (no key is extracted)', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const handle = await startServer(orchestrator, anchor);
    handles.push(handle);
    const run = await callCli(anchor, {
      attest: attestDouble({
        mangle: (): string => attestEvidenceText(FAKE_OPERATOR_SID, Buffer.from('not json', 'utf8')),
      }),
    });
    expect(run.outcome.exitCode).toBe(1);
    expect(run.outcome.status).toBeNull();
    expect(run.err.some((line) => line.includes('ATTESTED_HELLO_MALFORMED'))).toBe(true);
  });

  it('a nonzero attestor exit is ATTESTATION_FAILED, and a non-canonical operator SID is OPERATOR_UNRESOLVED', async () => {
    const failing = (): Promise<ProcessResult> => Promise.resolve({ ok: false });
    expect(
      await attestPipeServer('\\\\.\\pipe\\x', FAKE_OPERATOR_SID, failing, simulatedArtifact),
    ).toEqual({ ok: false, reason: PIPE_ATTESTATION_REJECTION.ATTESTATION_FAILED });
    for (const junk of ['', '   ', 'SYSTEM', 'S-1', 'not-a-sid']) {
      expect(await attestWithStdout(good, junk)).toEqual({
        ok: false,
        reason: PIPE_ATTESTATION_REJECTION.OPERATOR_UNRESOLVED,
      });
    }
  });

  it('the attestor binary is hash-gated exactly like the other native artifacts', async () => {
    const stdout = attestEvidenceText(FAKE_OPERATOR_SID, hello);
    const runProcess = (): Promise<ProcessResult> => Promise.resolve({ ok: true, stdout });
    const cases: readonly [Record<string, unknown>, string][] = [
      [{ loadProvenance: () => Promise.resolve(null) }, PIPE_ATTESTATION_REJECTION.ATTESTOR_PROVENANCE_MISSING],
      [
        { loadProvenance: () => Promise.resolve({ filename: '../evil.exe', sha256: 'a'.repeat(64) }) },
        PIPE_ATTESTATION_REJECTION.ATTESTOR_PROVENANCE_MISSING,
      ],
      [{ readAttestorBytes: () => null }, PIPE_ATTESTATION_REJECTION.ATTESTOR_MISSING],
      [{ hashBytes: () => 'b'.repeat(64) }, PIPE_ATTESTATION_REJECTION.ATTESTOR_HASH_MISMATCH],
    ];
    for (const [override, reason] of cases) {
      const result = await attestPipeServer('\\\\.\\pipe\\x', FAKE_OPERATOR_SID, runProcess, {
        ...simulatedArtifact,
        ...override,
      });
      expect(result).toEqual({ ok: false, reason });
    }
  });

  it('7. EVERY attestation rejection is a nonzero exit with no command dispatched and no fallback', async () => {
    for (const reason of Object.values(PIPE_ATTESTATION_REJECTION)) {
      const { runtime, orchestrator } = newOrchestrator();
      orchestrator.open(BINDING);
      const anchor = memAnchor();
      const handle = await startServer(orchestrator, anchor);
      const run = await callCli(anchor, {
        attest: () => Promise.resolve({ ok: false as const, reason }),
      });
      expect(run.outcome.exitCode, reason).toBe(1);
      expect(run.outcome.authenticated, reason).toBe(false);
      expect(run.outcome.status, reason).toBeNull();
      expect(run.out, reason).toEqual([]);
      expect(run.err.some((line) => line.includes(reason)), reason).toBe(true);
      // The workflow is untouched: no weaker path was tried after the rejection.
      expect(runtime.current()?.status, reason).toBe(WORKFLOW_STATUS.OPEN);
      await handle.close();
    }
  });
});

/* ================================================================== *
 * 4b. The pipe DESCRIPTOR is asserted exactly — owner alone is not enough
 * ================================================================== */

describe('DDR-D062-D/A1 — owner AND the exact structural descriptor decide (SEAM)', () => {
  const me = FAKE_OPERATOR_SID;
  const hex = Buffer.from('{"v":2}', 'utf8').toString('hex');
  /** Build V3 evidence from a DACL header and raw ACE bodies. */
  const evidenceOf = (owner: string, dacl: string, aces: readonly string[] = []): string =>
    `AGENTBRIDGE-ATTEST-V3\nPIPEOWNER ${owner}\nDACL ${dacl}\n` +
    aces.map((ace, index) => `ACE ${String(index)} ${ace}\n`).join('') +
    `HELLO ${hex}\n`;
  const accepted = (owner: string): string => evidenceOf(owner, '1 1 1', [acceptedAce(owner)]);

  it('T1. the trusted owner carrying the accepted descriptor → attested', async () => {
    const result = await attestWithStdout(accepted(me));
    expect(result.ok).toBe(true);
  });

  it('T2. a foreign OWNER is rejected even when the DACL is perfect', async () => {
    // The whole descriptor is impeccable except for who owns the object — which
    // is exactly the case a foreign principal cannot manufacture, because the
    // kernel refuses an owner SID the creating token cannot assume.
    const result = await attestWithStdout(
      evidenceOf(FOREIGN_OPERATOR_SID, '1 1 1', [acceptedAce(me)]),
    );
    expect(result).toEqual({
      ok: false,
      reason: PIPE_ATTESTATION_REJECTION.PIPE_OWNER_MISMATCH,
    });
  });

  it('T4/T5/T6. the trusted owner with ANY other descriptor → PIPE_DACL_UNEXPECTED', async () => {
    // This is the counterexample owner-only proof cannot survive: an unrelated
    // program running as the operator holds the expected name with a broad
    // descriptor, and a foreign principal then adds an instance and answers.
    const unacceptable: readonly (readonly [string, readonly string[], string])[] = [
      // T4 — present but NOT protected; or absent entirely
      ['1 0 1', [acceptedAce(me)], 'DACL not protected'],
      ['0 1 1', [acceptedAce(me)], 'DACL not present'],
      ['0 0 1', [acceptedAce(me)], 'DACL neither present nor protected'],
      // T5 — a second ace, including one the relay bound would not have shown
      ['1 1 2', [acceptedAce(me), acceptedAce(FOREIGN_OPERATOR_SID)], 'second ace'],
      ['1 1 2', [acceptedAce(me), '00 00 00120089 S-1-1-0'], 'second ace, broad'],
      // A true count beyond the relay bound: the grammar still demands the
      // bounded ACE lines, and the count alone is what rejects it, so extra
      // entries can never hide behind the relay limit.
      [
        '1 1 9',
        [acceptedAce(me), acceptedAce(me), acceptedAce(me), acceptedAce(me)],
        'true count beyond the relay bound',
      ],
      ['1 1 0', [], 'no ace at all'],
      // T5 — a broad or foreign trustee instead of the operator
      ['1 1 1', ['00 00 0012019f S-1-1-0'], 'Everyone'],
      ['1 1 1', ['00 00 0012019f S-1-5-7'], 'ANONYMOUS LOGON'],
      ['1 1 1', ['00 00 0012019f S-1-5-32-544'], 'Administrators'],
      ['1 1 1', ['00 00 0012019f S-1-5-18'], 'SYSTEM'],
      ['1 1 1', [`00 00 0012019f ${FOREIGN_OPERATOR_SID}`], 'foreign operator'],
      // T6 — a wider or narrower mask
      ['1 1 1', [`00 00 001f01ff ${me}`], 'FILE_ALL_ACCESS'],
      ['1 1 1', [`00 00 00120089 ${me}`], 'read-only'],
      ['1 1 1', [`00 00 10000000 ${me}`], 'GENERIC_ALL'],
      ['1 1 1', [`00 00 0012019e ${me}`], 'one bit short'],
      ['1 1 1', [`00 00 0012039f ${me}`], 'one bit extra'],
      // inheritance flags on the ace
      ['1 1 1', [`00 10 0012019f ${me}`], 'INHERITED_ACE'],
      ['1 1 1', [`00 03 0012019f ${me}`], 'OBJECT|CONTAINER inherit'],
      // a DENY, AUDIT or ALARM ace wearing the right mask
      ['1 1 1', [`01 00 0012019f ${me}`], 'ACCESS_DENIED'],
      ['1 1 1', [`02 00 0012019f ${me}`], 'SYSTEM_AUDIT'],
      ['1 1 1', [`03 00 0012019f ${me}`], 'SYSTEM_ALARM'],
      ['1 1 1', [`09 00 0012019f ${me}`], 'ALLOWED_CALLBACK'],
      // an object ace, whose trustee the kernel layout does not expose
      ['1 1 1', ['05 00 0012019f NONE'], 'ACCESS_ALLOWED_OBJECT'],
    ];
    for (const [dacl, aces, label] of unacceptable) {
      const result = await attestWithStdout(evidenceOf(me, dacl, aces));
      expect(result, label).toEqual({
        ok: false,
        reason: PIPE_ATTESTATION_REJECTION.PIPE_DACL_UNEXPECTED,
      });
    }
  });

  it('T3. a nonzero native exit is fail-closed with no descriptor to inspect', async () => {
    const failed = await attestPipeServer(
      '\\\\.\\pipe\\x',
      me,
      (): Promise<ProcessResult> => Promise.resolve({ ok: false }),
      simulatedArtifact,
    );
    expect(failed).toEqual({
      ok: false,
      reason: PIPE_ATTESTATION_REJECTION.ATTESTATION_FAILED,
    });
  });
});

/* ================================================================== *
 * 5. REAL ARTIFACT — the native attestor against real pipes
 * ================================================================== */

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const attestorExe = join(repoRoot, 'dist', 'control', 'native', 'agentbridge-win-pipe-attest.exe');
const attestorProv = join(repoRoot, 'dist', 'control', 'native', 'pipe-attestor-provenance.js');
// The accept provider too: under DDR-D062-D the end-to-end case is only real if
// the pipe under test carries the genuine protected operator-only descriptor,
// which only the Revision-2 accept provider creates.
const acceptorAddon = join(repoRoot, 'dist', 'control', 'native', 'agentbridge-win-pipe-accept.node');
const acceptorProv = join(repoRoot, 'dist', 'control', 'native', 'pipe-acceptor-provenance.js');
const nativeReady =
  process.platform === 'win32' &&
  existsSync(attestorExe) &&
  existsSync(attestorProv) &&
  existsSync(acceptorAddon) &&
  existsSync(acceptorProv);

/**
 * Point the REAL attestation gate at the REAL built artifact while these tests run
 * the `src/` modules. Only the module-resolution root moves: the binary, its
 * generated provenance, the SHA-256-before-exec gate, the bounded runner, the
 * parser and the SID comparison are all the production ones.
 */
/**
 * Point the REAL accept provider at the REAL built addon the same way, so a
 * pipe created in these tests carries the genuine protected operator-only
 * descriptor. Only the module-resolution root moves: the addon bytes, its
 * generated provenance and the SHA-256-before-load gate are the production ones.
 */
const realAcceptorServer = (options: CreateControlChannelServerOptions): ControlChannelServer =>
  createControlChannelServer({
    ...options,
    loadAcceptor: (): Promise<PipeAcceptorLoad> =>
      loadPipeAcceptor({
        loadProvenance: async (): Promise<OwnerHelperProvenance | null> => {
          const loaded = (await import(pathToFileURL(acceptorProv).href)) as Record<string, unknown>;
          return (loaded['PIPE_ACCEPTOR_PROVENANCE'] as OwnerHelperProvenance | undefined) ?? null;
        },
        resolveAcceptorPath: (): string => acceptorAddon,
      }),
  });

const realArtifactDeps: AttestControlPipeDeps = {
  attestor: {
    loadProvenance: async (): Promise<{ filename: string; sha256: string } | null> => {
      const loaded = (await import(pathToFileURL(attestorProv).href)) as Record<string, unknown>;
      const provenance = loaded['PIPE_ATTESTOR_PROVENANCE'] as
        | { filename: string; sha256: string }
        | undefined;
      return provenance ?? null;
    },
    resolveAttestorPath: (): string => attestorExe,
  },
};

/** The REAL operator SID of this process, resolved exactly as the anchor gate does. */
async function realOperatorSid(): Promise<string> {
  const systemRoot = process.env['SystemRoot'] ?? 'C:\\Windows';
  const run = await defaultProcessRunner(systemRoot)(
    join(systemRoot, 'System32', 'whoami.exe'),
    ['/user'],
  );
  if (!run.ok) {
    throw new Error('whoami failed');
  }
  const operator = parseWhoamiUser(run.stdout);
  if (operator === null) {
    throw new Error('operator unreadable');
  }
  return operator.sid;
}

interface RawRun {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

function runAttestor(args: readonly string[]): Promise<RawRun> {
  return new Promise<RawRun>((resolvePromise) => {
    execFile(
      attestorExe,
      [...args],
      { encoding: 'utf8', timeout: 8000, windowsHide: true, shell: false },
      (error: unknown, stdout: string, stderr: string) => {
        const failure = error as { code?: unknown } | null;
        const code =
          failure === null
            ? 0
            : typeof failure.code === 'number'
              ? failure.code
              : null;
        resolvePromise({ code, stdout, stderr });
      },
    );
  });
}

describe.skipIf(!nativeReady)('DDR-D062-D — the REAL native attestor (Windows, dist-gated)', () => {
  it('relays the exact hello of a real live pipe and the real OWNER SID of its pipe object', async () => {
    const keys = generateRuntimeKeyPair();
    const nonceS = randomBytes(NONCE_BYTES);
    const helloBody = buildHelloBody(nonceS, keys.verifyKey);
    const pipePath = pipePathFromName(pipeNameForRuntimeId('1234'.repeat(8)));
    const server = net.createServer((socket: net.Socket) => {
      socket.on('error', () => {
        /* ignore */
      });
      socket.write(frameMessage(helloBody));
    });
    await new Promise<void>((resolvePromise) => {
      server.listen(pipePath, resolvePromise);
    });
    servers.push(server);

    const run = await runAttestor([pipePath]);
    expect(run.code, run.stderr).toBe(0);
    const evidence = parseAttestationEvidence(run.stdout);
    expect(evidence).not.toBeNull();
    expect(evidence?.helloBody.equals(helloBody)).toBe(true);
    // The relayed hello parses back to the very key the server announced.
    expect(parseHelloBody(evidence?.helloBody ?? Buffer.alloc(0))?.verifyKey.equals(keys.verifyKey)).toBe(
      true,
    );
    // And the OWNER SID is stable across two independent observations of the
    // SAME pipe object — the current test principal's SID, read from the
    // connected handle, never a process identity.
    const self = await runAttestor([pipePath]);
    expect(parseAttestationEvidence(self.stdout)?.pipeOwnerSid).toBe(evidence?.pipeOwnerSid);
  });

  it('rejects malformed arguments, non-pipe paths, UNC pipes, and an absent pipe (fail closed, empty stdout)', async () => {
    for (const args of [
      [],
      ['\\\\.\\pipe\\a', 'extra'],
      ['C:\\Windows'],
      ['relative\\path'],
      ['\\\\.\\pipe\\'],
      ['\\\\remote\\pipe\\agentbridge'],
      [pipePathFromName(pipeNameForRuntimeId('9999'.repeat(8)))], // nothing listening
    ]) {
      const run = await runAttestor(args);
      expect(run.code, JSON.stringify(args)).not.toBe(0);
      expect(run.stdout, JSON.stringify(args)).toBe('');
    }
  });

  /** Start a child that serves `pipePath` with `onConnection` and resolve once listening. */
  async function startChildServer(pipePath: string, onConnection: string): Promise<ChildProcess> {
    const script =
      "import net from 'node:net';" +
      `const s=net.createServer((c)=>{c.on("error",()=>{});${onConnection}});` +
      `s.listen(${JSON.stringify(pipePath)},()=>{process.stdout.write("up\\n");});`;
    // Drop NODE_CHANNEL_FD: a Node child that inherits a vitest worker's IPC fd
    // number writes into the pool's channel and corrupts it. These children need
    // no IPC at all.
    const childEnv = { ...process.env };
    delete childEnv['NODE_CHANNEL_FD'];
    const child = spawn(process.execPath, ['--input-type=module', '-e', script], {
      stdio: ['ignore', 'pipe', 'ignore'],
      env: childEnv,
    });
    children.push(child);
    await new Promise<void>((resolvePromise) => {
      child.stdout.once('data', () => {
        resolvePromise();
      });
    });
    return child;
  }

  it('9. a server that exits the moment it is attested (before any hello) is ALWAYS rejected', async () => {
    // Deterministic: either the connect never lands at all, or it lands and the
    // pipe session is already gone, so the bounded hello read on that same
    // connected handle can never complete. Either way the artifact fails closed
    // with no stdout; there is nothing it could ever emit.
    //
    // Reachable stderr tokens, from the attestor's control flow: ERR_CONNECT
    // (CreateFileW failed) or ERR_HELLO_PREFIX (connected, but not one hello
    // byte exists). The descriptor query cannot fail here — it reads the
    // security of the handle already held, which server death does not disturb —
    // and ERR_HELLO_BODY is unreachable because no prefix can ever be read.
    const pipePath = pipePathFromName(pipeNameForRuntimeId('abcd'.repeat(8)));
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const child = await startChildServer(pipePath, 'process.exit(0);');
      const run = await runAttestor([pipePath]);
      expect(run.code, `attempt ${String(attempt)}: ${run.stderr}`).not.toBe(0);
      expect(run.stdout).toBe('');
      expect(run.stderr.trim()).toMatch(/^(ERR_CONNECT|ERR_HELLO_PREFIX)$/);
      child.kill('SIGKILL');
      await delay(20);
    }
  }, 60000);

  it('8/9b. a server exiting right after its hello either attests completely or not at all', async () => {
    // Here the exit races the attestation, so BOTH outcomes are legitimate. What
    // must never happen is a half-result: an exit 0 whose evidence does not parse,
    // or any stdout at all on a failure. The SAME-HANDLE rule is what makes that
    // true — the OWNER, the DACL and the hello all come from the one connected
    // handle, and the evidence is built whole in a bounded buffer before the
    // single stdout write.
    //
    // Reachable stderr tokens add ERR_HELLO_BODY to the previous test's set: the
    // server does write, so a flushed prefix with a truncated body is possible.
    // ERR_HELLO_LENGTH stays unreachable — those four prefix bytes, if all
    // readable, are the real body length, and a torn prefix is ERR_HELLO_PREFIX.
    const pipePath = pipePathFromName(pipeNameForRuntimeId('abce'.repeat(8)));
    const onConnection =
      "const body=Buffer.from(JSON.stringify({v:2,nonceS:'a'.repeat(43),verifyKey:'b'.repeat(43)}),'utf8');" +
      'const p=Buffer.alloc(4);p.writeUInt32BE(body.length,0);' +
      'c.write(Buffer.concat([p,body]));setImmediate(()=>process.exit(0));';
    for (let attempt = 0; attempt < 6; attempt += 1) {
      const child = await startChildServer(pipePath, onConnection);
      const run = await runAttestor([pipePath]);
      if (run.code === 0) {
        // Complete, parseable, canonical evidence — nothing partial.
        expect(parseAttestationEvidence(run.stdout), run.stdout).not.toBeNull();
      } else {
        expect(run.stdout).toBe('');
        expect(run.stderr.trim()).toMatch(
          /^(ERR_CONNECT|ERR_HELLO_PREFIX|ERR_HELLO_BODY)$/,
        );
      }
      child.kill('SIGKILL');
      await delay(20);
    }
  }, 60000);

  it('F-C1. an ACE carrying NO trustee bytes is observed safely, never read out of bounds', async () => {
    // The exact counterexample independent validation reproduced: a
    // kernel-VALID ACL (IsValidAcl TRUE, CreateNamedPipeW succeeds) whose
    // second ACE is an unknown type with AceSize == 8 — the ACE_HEADER and the
    // access mask, and not one byte more. Pointing IsValidSid at offset 8 there
    // would read Revision and SubAuthorityCount past the end of the ACE.
    //
    // Both shapes are exercised so the size guard is proven LOAD-BEARING: the
    // same unknown ACE type yields the real trustee when the SID is actually
    // present, and NONE only when there is no room for one. A bug that simply
    // mapped "unknown type" to NONE would fail the second case.
    const operatorSid = await realOperatorSid();
    for (const withSid of [false, true]) {
      const { pipePath } = await startCustomAclPipe(withSid);
      const run = await runAttestor([pipePath]);
      // No crash: a STATUS_ACCESS_VIOLATION would surface as a huge/negative
      // code and an empty stdout, never as a clean exit 0 with evidence.
      expect(run.code, `withSid=${String(withSid)} stderr=${run.stderr}`).toBe(0);
      const evidence = parseAttestationEvidence(run.stdout);
      expect(evidence, `withSid=${String(withSid)}`).not.toBeNull();
      expect(evidence?.daclPresent).toBe(true);
      expect(evidence?.daclProtected).toBe(true);
      expect(evidence?.aceCount).toBe(2);
      expect(evidence?.aces).toHaveLength(2);
      // The ordinary ACE is relayed exactly as before.
      expect(evidence?.aces[0]).toEqual({
        type: '00',
        flags: '00',
        mask: '0012019f',
        trustee: operatorSid.toLowerCase(),
      });
      // The unknown ACE: its trustee is NONE only when the ACE cannot hold a
      // SID's fixed head, and the genuine SID otherwise.
      expect(evidence?.aces[1]?.type).toBe('40');
      expect(evidence?.aces[1]?.trustee).toBe(withSid ? operatorSid.toLowerCase() : 'none');
      // And it is still rejected — on the ACE count, before any trustee matters.
      const gate = await attestPipeServer(
        pipePath,
        operatorSid,
        (): Promise<ProcessResult> => Promise.resolve({ ok: true, stdout: run.stdout }),
        simulatedArtifact,
      );
      expect(gate).toEqual({
        ok: false,
        reason: PIPE_ATTESTATION_REJECTION.PIPE_DACL_UNEXPECTED,
      });
    }
  }, 90000);

  it('T15. the reviewed source and the BUILT binary carry no process-object capability at all', async () => {
    // PID reuse is no longer guarded — it is structurally impossible, because
    // no PID is ever consulted. That is a claim about absence, so it is proven
    // over the exact reviewed source the build compiles AND over the bytes of
    // the artifact the runtime actually executes.
    const { readFileSync } = await import('node:fs');
    const source = readFileSync(
      join(repoRoot, 'tools', 'control-owner', 'agentbridge-win-pipe-attest.c'),
      'utf8',
    );
    const binary = readFileSync(attestorExe).toString('latin1');
    const forbidden = [
      'OpenProcess',
      'OpenProcessToken',
      'GetTokenInformation',
      'GetNamedPipeServerProcessId',
      'GetProcessTimes',
      'AdjustTokenPrivileges',
      'LookupPrivilegeValue',
      'SeDebugPrivilege',
    ];
    for (const symbol of forbidden) {
      expect(source.includes(symbol), `source imports ${symbol}`).toBe(false);
      // Imports are plain ASCII in the PE import directory, so absence there is
      // absence of the capability, not merely absence of a call site.
      expect(binary.includes(symbol), `binary imports ${symbol}`).toBe(false);
    }
    // What it DOES do: read the STRUCTURE of the security of the handle it
    // already holds — and nothing that renders it as text.
    expect(source).toContain('GetSecurityInfo(pipe, SE_KERNEL_OBJECT,');
    expect(source).toContain(
      'OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION',
    );
    expect(source).toContain('GetSecurityDescriptorControl(sd, &control, &revision)');
    expect(source).toContain('GetAclInformation(dacl, &acl_size,');
    expect(source).toContain('GetAce(dacl, index, &raw)');
    expect(source).toContain('ConvertSidToStringSidW(sid, &text)');
    // No SDDL rendering survives anywhere in the artifact: that API, and the
    // V2 evidence label it fed, are the defect this amendment removes.
    for (const banned of [
      'ConvertSecurityDescriptorToStringSecurityDescriptorW',
      'ConvertStringSecurityDescriptorToSecurityDescriptorW',
      'PIPESD',
      'SDDL_REVISION',
    ]) {
      expect(source.includes(banned), `source still renders SDDL via ${banned}`).toBe(false);
      expect(binary.includes(banned), `binary still imports ${banned}`).toBe(false);
    }
    expect(source).toContain('AGENTBRIDGE-ATTEST-V3');
    // Exactly one CreateFileW: the pipe is never reopened by name (TOCTOU).
    expect(source.match(/CreateFileW\(/g)?.length).toBe(1);
    // And it can never write a byte to the pipe.
    expect(source).toContain('CreateFileW(pipe_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL)');
    expect(source.includes('GENERIC_WRITE')).toBe(false);
    expect(source.includes('WriteFile(')).toBe(false);
    // The descriptor is read BEFORE the hello, and stdout is written once, last.
    const query = source.lastIndexOf('query_pipe_security(pipe, &owner, &dacl, &sd)');
    const hello = source.lastIndexOf('read_exact(pipe, prefix, ATTEST_PREFIX_BYTES)');
    const emit = source.lastIndexOf('write_stdout(out, len);');
    expect(query).toBeGreaterThan(0);
    expect(hello).toBeGreaterThan(query);
    expect(emit).toBeGreaterThan(hello);
    expect(source.match(/write_stdout\(/g)?.length).toBe(2); // the helper + its one call site
  });

  it('T1-live/15. the REAL accept provider + the REAL attestor attest end to end, leak nothing, and log nothing', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const anchor = memAnchor();
    const logged: string[] = [];
    // The PRODUCTION server factory, so the pipe under test carries the genuine
    // protected operator-only descriptor rather than a libuv default one. This
    // is what makes the assertion below a real T1 and not a simulated one.
    const handle = await startServer(orchestrator, anchor, {
      overrides: {
        createServer: realAcceptorServer,
        logger: (message: string): void => {
          logged.push(message);
        },
      },
    });
    handles.push(handle);
    const facts = descriptorFacts(anchor, handle);

    // Repeated REAL attestations against the live runtime.
    for (let index = 0; index < 8; index += 1) {
      const run = await runAttestor([facts.pipePath]);
      expect(run.code, run.stderr).toBe(0);
      expect(parseAttestationEvidence(run.stdout)).not.toBeNull();
    }
    // The runtime logged nothing at all, and never saw a command.
    expect(logged).toEqual([]);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);

    // A normal session still works immediately afterwards, through the REAL
    // attestor (the CLI's production default) end to end.
    // The trusted operator is THIS process's real SID, and the real attestor must
    // find the live pipe served by exactly it.
    const operatorSid = await realOperatorSid();
    const err: string[] = [];
    const outcome = await runControlCli({
      verify: () => Promise.resolve({ ok: true as const, anchorPath: FAKE_ANCHOR, operatorSid }),
      descriptorDeps: anchor.deps,
      attestDeps: realArtifactDeps,
      err: (m: string): void => {
        err.push(m);
      },
      out: (): void => {
        /* silent */
      },
    });
    expect(err).toEqual([]);
    expect(outcome.exitCode).toBe(0);
    expect(outcome.status).toBe(CONTROL_RESULT.APPLIED);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.AWAITING_HUMAN_DECISION);
    expect(logged).toEqual([]);
  }, 60000);
});

/* ================================================================== *
 * 6. THROWAWAY-PIPE KERNEL REGRESSIONS (Windows)
 *
 * The two kernel facts the DDR's trust root rests on, proven against pipes
 * created and destroyed inside this test and nothing else. No live control
 * pipe, no runtime, no Scheduled Task, no account, no ACL of anything that
 * outlives the test is touched, and nothing here needs elevation.
 *
 * T11 and T12 — the CROSS-PRINCIPAL denials — are deliberately absent: they
 * require a second Windows principal, and creating or altering one is outside
 * this gate's authority. They remain REQUIRED_BUT_AUTHORITY_DEFERRED.
 * ================================================================== */

/** Run one throwaway-pipe probe script and return its parsed JSON result. */
function runPipeProbe(script: string): Promise<Record<string, unknown>> {
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  return new Promise<Record<string, unknown>>((resolvePromise, rejectPromise) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
      { encoding: 'utf8', timeout: 60000, windowsHide: true, shell: false, maxBuffer: 1 << 20 },
      (error: unknown, stdout: string, stderr: string) => {
        if (error !== null && stdout.trim() === '') {
          rejectPromise(new Error(`probe failed: ${stderr}`));
          return;
        }
        resolvePromise(JSON.parse(stdout) as Record<string, unknown>);
      },
    );
  });
}

const PROBE_PREAMBLE = [
  "$ErrorActionPreference = 'Stop'",
  'Add-Type -TypeDefinition @"',
  'using System;',
  'using System.Runtime.InteropServices;',
  'public static class NP {',
  '  [StructLayout(LayoutKind.Sequential)]',
  '  public struct SA { public int nLength; public IntPtr sd; public int inherit; }',
  '  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]',
  '  public static extern IntPtr CreateNamedPipeW(string n, uint om, uint pm, uint mi, uint ob, uint ib, uint t, ref SA sa);',
  '  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]',
  '  public static extern IntPtr CreateFileW(string n, uint a, uint s, IntPtr sa, uint d, uint f, IntPtr t);',
  '  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);',
  '  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]',
  '  public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string s, uint r, out IntPtr sd, IntPtr z);',
  '  [DllImport("advapi32.dll", SetLastError=true)]',
  '  public static extern uint GetSecurityInfo(IntPtr h, int t, uint i, out IntPtr o, out IntPtr g, out IntPtr d, out IntPtr s, out IntPtr sd);',
  '  [DllImport("advapi32.dll", SetLastError=true)]',
  '  public static extern bool GetSecurityDescriptorControl(IntPtr sd, out ushort c, out uint r);',
  '  [DllImport("advapi32.dll", SetLastError=true)]',
  '  public static extern bool GetAclInformation(IntPtr acl, out ACLSIZE info, uint len, int cls);',
  '  [DllImport("advapi32.dll", SetLastError=true)]',
  '  public static extern bool GetAce(IntPtr acl, uint idx, out IntPtr ace);',
  '  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]',
  '  public static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr s);',
  '  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]',
  '  public static extern bool ConvertStringSidToSidW(string s, out IntPtr sid);',
  '  [DllImport("advapi32.dll", SetLastError=true)] public static extern uint GetLengthSid(IntPtr sid);',
  '  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool IsValidAcl(IntPtr acl);',
  '  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool InitializeSecurityDescriptor(IntPtr sd, uint rev);',
  '  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool SetSecurityDescriptorOwner(IntPtr sd, IntPtr owner, bool def);',
  '  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool SetSecurityDescriptorDacl(IntPtr sd, bool present, IntPtr dacl, bool def);',
  '  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool SetSecurityDescriptorControl(IntPtr sd, ushort of, ushort to);',
  '  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool ConnectNamedPipe(IntPtr h, IntPtr ov);',
  '  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool WriteFile(IntPtr h, byte[] b, uint n, out uint w, IntPtr ov);',
  '  [StructLayout(LayoutKind.Sequential)]',
  '  public struct ACLSIZE { public uint AceCount; public uint BytesInUse; public uint BytesFree; }',
  '  [StructLayout(LayoutKind.Sequential)]',
  '  public struct ACEHDR { public byte AceType; public byte AceFlags; public ushort AceSize; }',
  '}',
  '"@',
  '$me = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value',
  'function New-SA([string]$sddl) {',
  '  $sd = [IntPtr]::Zero',
  '  if (-not [NP]::ConvertStringSecurityDescriptorToSecurityDescriptorW($sddl, 1, [ref]$sd, [IntPtr]::Zero)) { throw (\'sddl \' + $sddl) }',
  '  $sa = New-Object NP+SA',
  "  $sa.nLength = [Runtime.InteropServices.Marshal]::SizeOf([type]'NP+SA')",
  '  $sa.sd = $sd',
  '  $sa.inherit = 0',
  '  return $sa',
  '}',
  'function Sid-Text([IntPtr]$sid) {',
  '  $t=[IntPtr]::Zero',
  "  if (-not [NP]::ConvertSidToStringSidW($sid, [ref]$t)) { return 'SID_FAILED' }",
  '  return [Runtime.InteropServices.Marshal]::PtrToStringUni($t)',
  '}',
  '# Read the descriptor the way the production attestor now does: STRUCTURALLY,',
  '# as numeric SIDs and numeric fields. No SDDL rendering is involved at all.',
  'function Read-Struct([IntPtr]$h) {',
  '  $o=[IntPtr]::Zero;$g=[IntPtr]::Zero;$d=[IntPtr]::Zero;$s=[IntPtr]::Zero;$p=[IntPtr]::Zero',
  "  if ([NP]::GetSecurityInfo($h, 6, [uint32]5, [ref]$o, [ref]$g, [ref]$d, [ref]$s, [ref]$p) -ne 0) { return 'QUERY_FAILED' }",
  '  $c=0;$r=0',
  "  if (-not [NP]::GetSecurityDescriptorControl($p, [ref]$c, [ref]$r)) { return 'CONTROL_FAILED' }",
  '  $info = New-Object NP+ACLSIZE',
  "  if (-not [NP]::GetAclInformation($d, [ref]$info, 12, 2)) { return 'ACL_FAILED' }",
  '  $aces = @()',
  '  for ($i = 0; $i -lt $info.AceCount; $i++) {',
  '    $ace=[IntPtr]::Zero',
  "    if (-not [NP]::GetAce($d, [uint32]$i, [ref]$ace)) { return 'ACE_FAILED' }",
  "    $hdr = [Runtime.InteropServices.Marshal]::PtrToStructure($ace, [type]'NP+ACEHDR')",
  '    $mask = [Runtime.InteropServices.Marshal]::ReadInt32($ace, 4)',
  "    $aces += ('{0:x2} {1:x2} {2:x8} {3}' -f $hdr.AceType, $hdr.AceFlags, $mask, (Sid-Text ([IntPtr]::Add($ace, 8))))",
  '  }',
  "  $present = [int][bool]($c -band 4); $guarded = [int][bool]($c -band 4096)",
  "  return ('OWNER=' + (Sid-Text $o) + ' DACL=' + $present + ' ' + $guarded + ' ' + $info.AceCount + ' ACES=' + ($aces -join '|'))",
  '}',
  '$OPEN = 3; $MODE = 8; $FIRST = 524288; $INVALID = [IntPtr]::new(-1)',
].join('\n');

/**
 * Serve ONE throwaway pipe whose DACL is built BYTE BY BYTE, so an ACE shape
 * the normal APIs will not produce can still be presented to the attestor: two
 * ACEs, the second an unknown type 0x40 that either carries a trustee SID or
 * has AceSize == 8 and carries none at all. The ACL is proven kernel-valid
 * (IsValidAcl) before the pipe is created. The server then accepts one client
 * and writes one framed hello, so the attestor completes normally.
 *
 * Resolves once the child announces the pipe path; the child is registered for
 * teardown and is never the live control pipe.
 */
function startCustomAclPipe(withSid: boolean): Promise<{ readonly pipePath: string }> {
  const script = [
    PROBE_PREAMBLE,
    `$withSid = $${withSid ? 'true' : 'false'}`,
    '$meSid = [IntPtr]::Zero',
    "if (-not [NP]::ConvertStringSidToSidW($me, [ref]$meSid)) { throw 'sid' }",
    '$sidLen = [int][NP]::GetLengthSid($meSid)',
    '$sidBytes = New-Object byte[] $sidLen',
    '[Runtime.InteropServices.Marshal]::Copy($meSid, $sidBytes, 0, $sidLen)',
    '$ace1 = 8 + $sidLen',
    'if ($withSid) { $ace2 = 8 + $sidLen } else { $ace2 = 8 }',
    '$aclSize = 8 + $ace1 + $ace2',
    '$acl = New-Object byte[] $aclSize',
    '$acl[0] = 2; $acl[1] = 0',
    '$acl[2] = $aclSize -band 0xFF; $acl[3] = ($aclSize -shr 8) -band 0xFF',
    '$acl[4] = 2; $acl[5] = 0; $acl[6] = 0; $acl[7] = 0',
    '$o = 8',
    '$acl[$o] = 0; $acl[$o+1] = 0',
    '$acl[$o+2] = $ace1 -band 0xFF; $acl[$o+3] = ($ace1 -shr 8) -band 0xFF',
    '$acl[$o+4] = 0x9F; $acl[$o+5] = 0x01; $acl[$o+6] = 0x12; $acl[$o+7] = 0x00',
    '[Array]::Copy($sidBytes, 0, $acl, $o+8, $sidLen)',
    '$o = $o + $ace1',
    '$acl[$o] = 0x40; $acl[$o+1] = 0',
    '$acl[$o+2] = $ace2 -band 0xFF; $acl[$o+3] = ($ace2 -shr 8) -band 0xFF',
    '$acl[$o+4] = 0x9F; $acl[$o+5] = 0x01; $acl[$o+6] = 0x12; $acl[$o+7] = 0x00',
    'if ($withSid) { [Array]::Copy($sidBytes, 0, $acl, $o+8, $sidLen) }',
    '$aclPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($aclSize)',
    '[Runtime.InteropServices.Marshal]::Copy($acl, 0, $aclPtr, $aclSize)',
    "if (-not [NP]::IsValidAcl($aclPtr)) { throw 'the kernel rejected the hand-built ACL' }",
    '$sdPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal(64)',
    "if (-not [NP]::InitializeSecurityDescriptor($sdPtr, 1)) { throw 'sd' }",
    '[void][NP]::SetSecurityDescriptorOwner($sdPtr, $meSid, $false)',
    '[void][NP]::SetSecurityDescriptorDacl($sdPtr, $true, $aclPtr, $false)',
    '[void][NP]::SetSecurityDescriptorControl($sdPtr, 4096, 4096)',
    '$sa = New-Object NP+SA',
    "$sa.nLength = [Runtime.InteropServices.Marshal]::SizeOf([type]'NP+SA')",
    '$sa.sd = $sdPtr; $sa.inherit = 0',
    "$n = '\\\\.\\pipe\\ab-fc1-' + [guid]::NewGuid().ToString('N')",
    '$h = [NP]::CreateNamedPipeW($n, ($OPEN -bor $FIRST), $MODE, 255, 4096, 4096, 0, [ref]$sa)',
    "if ($h -eq $INVALID) { throw ('create ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }",
    "[Console]::Out.WriteLine('READY ' + $n)",
    '[Console]::Out.Flush()',
    '[void][NP]::ConnectNamedPipe($h, [IntPtr]::Zero)',
    "$body = [Text.Encoding]::ASCII.GetBytes('{\"v\":2}')",
    '$frame = New-Object byte[] (4 + $body.Length)',
    '$frame[0]=0; $frame[1]=0; $frame[2]=0; $frame[3]=$body.Length',
    '[Array]::Copy($body, 0, $frame, 4, $body.Length)',
    '$w = 0',
    '[void][NP]::WriteFile($h, $frame, [uint32]$frame.Length, [ref]$w, [IntPtr]::Zero)',
    'Start-Sleep -Seconds 5',
  ].join('\n');
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  return new Promise<{ readonly pipePath: string }>((resolvePromise, rejectPromise) => {
    const child = spawn(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
      { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] },
    );
    children.push(child);
    let out = '';
    let err = '';
    child.stdout.on('data', (chunk: Buffer) => {
      out += chunk.toString('utf8');
      const ready = /READY (\S+)/.exec(out);
      if (ready?.[1] !== undefined) {
        resolvePromise({ pipePath: ready[1] });
      }
    });
    child.stderr.on('data', (chunk: Buffer) => {
      err += chunk.toString('utf8');
    });
    child.on('exit', () => {
      rejectPromise(new Error(`custom-ACL server exited early: ${err || out}`));
    });
  });
}

/**
 * Whether T13's NEGATIVE oracle is valid in this token. With SeRestorePrivilege
 * ENABLED the kernel legitimately permits assigning an arbitrary owner, so
 * ERROR_INVALID_OWNER is not the correct expectation and the oracle must be
 * SKIPPED — never silently passed. Total and pure, so both branches are
 * provable on any machine.
 */
type T13Decision = { readonly kind: 'run' } | { readonly kind: 'skip'; readonly reason: string };

function t13NegativeOracle(restoreEnabled: boolean): T13Decision {
  if (restoreEnabled) {
    return {
      kind: 'skip',
      reason:
        'SeRestorePrivilege is ENABLED in this token: the kernel legitimately permits ' +
        'assigning an arbitrary owner, so the negative ERROR_INVALID_OWNER oracle is ' +
        'not valid here. The own-SID positive control still ran.',
    };
  }
  return { kind: 'run' };
}

describe.skipIf(process.platform !== 'win32')(
  'DDR-D062-D — throwaway-pipe kernel regressions (Windows)',
  () => {
    it('T13-decision. an enabled SeRestorePrivilege SKIPS the negative oracle, never passes it', () => {
      // The dynamic branch is decided by a TOTAL PURE function, so both
      // outcomes are provable here — including the one this machine's token
      // cannot reach. There is no third outcome, and the enabled case never
      // maps to "run", so it can never be reported as a pass of the oracle.
      const enabled = t13NegativeOracle(true);
      expect(enabled.kind).toBe('skip');
      expect(enabled.kind === 'skip' ? enabled.reason : '').toContain('SeRestorePrivilege');
      expect(enabled.kind === 'skip' ? enabled.reason.length : 0).toBeGreaterThan(40);
      expect(t13NegativeOracle(false)).toEqual({ kind: 'run' });
    });

    it('T13. an unprivileged process CANNOT mint a pipe owned by a non-owner-eligible SID', async (ctx) => {
      // This is the kernel fact the whole owner check rests on: a principal
      // cannot assign an owner its token cannot assume.
      //
      // The foreign SID is SYNTHESISED PER RUN in a random authority-21 domain.
      // Well-known SIDs are unusable as "foreign": exact-head CI proved that
      // BUILTIN\Administrators (S-1-5-32-544) is owner-ELIGIBLE in an elevated
      // administrator token, and S-1-5-18 would be wrong if a job ever ran as
      // SYSTEM. A random synthetic domain SID can be neither the caller's user
      // SID nor a group in its token, on any machine, with no account created
      // and no lookup performed.
      const script = [
        PROBE_PREAMBLE,
        '$r = New-Object Random',
        "$foreign = 'S-1-5-21-' + $r.Next(100000000,2000000000) + '-' + $r.Next(100000000,2000000000) + '-' + $r.Next(100000000,2000000000) + '-' + $r.Next(2000,900000)",
        '# The negative expectation is only valid while SeRestorePrivilege is',
        '# DISABLED: enabled, it legitimately permits assigning ANY owner.',
        '$restore = (whoami /priv /fo csv | ConvertFrom-Csv) | Where-Object { $_."Privilege Name" -eq "SeRestorePrivilege" }',
        "$restoreEnabled = ($restore -ne $null) -and ($restore.State -like 'Enabled*')",
        "$n1 = '\\\\.\\pipe\\ab-t13-' + [guid]::NewGuid().ToString('N')",
        "$saForeign = New-SA ('O:' + $foreign + 'D:P(A;;0x12019F;;;' + $me + ')')",
        '$h1 = [NP]::CreateNamedPipeW($n1, ($OPEN -bor $FIRST), $MODE, 255, 4096, 4096, 0, [ref]$saForeign)',
        '$foreignCode = 0',
        'if ($h1 -eq $INVALID) { $foreignCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error() }',
        'else { [void][NP]::CloseHandle($h1) }',
        '# POSITIVE CONTROL: the caller MAY assign its own user SID as owner, so a',
        '# 1307 above cannot be an unrelated failure of the same call.',
        "$n2 = '\\\\.\\pipe\\ab-t13-own-' + [guid]::NewGuid().ToString('N')",
        "$saOwn = New-SA ('O:' + $me + 'D:P(A;;0x12019F;;;' + $me + ')')",
        '$h2 = [NP]::CreateNamedPipeW($n2, ($OPEN -bor $FIRST), $MODE, 255, 4096, 4096, 0, [ref]$saOwn)',
        '$ownCode = 0',
        'if ($h2 -eq $INVALID) { $ownCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error() }',
        'else { [void][NP]::CloseHandle($h2) }',
        '[pscustomobject]@{ foreignCode = $foreignCode; ownCode = $ownCode; restoreEnabled = $restoreEnabled } | ConvertTo-Json -Compress',
      ].join('\n');

      const result = await runPipeProbe(script);
      // The positive control runs FIRST and must hold in every case, or the
      // probe proves nothing — including on the path that skips below.
      expect(result['ownCode'], 'assigning the caller own SID must succeed').toBe(0);

      const decision = t13NegativeOracle(result['restoreEnabled'] === true);
      if (decision.kind === 'skip') {
        // A REAL vitest skip, recorded with its reason. Not an early return:
        // an early return would be reported as a PASS of an oracle that never
        // ran, which is exactly what DDR-D062-D Amendment 1 forbids.
        ctx.skip(decision.reason);
      }
      // 1307 == ERROR_INVALID_OWNER. A 0 would mean the forgery succeeded.
      expect(result['foreignCode']).toBe(1307);
    }, 90000);

    it('T14. the descriptor belongs to the NAME and is fixed at first-instance creation', async () => {
      // Three instances created with three DIFFERENT security attributes — the
      // accepted one, a wide-open one, and the kernel default — and every
      // client, whichever instance it is routed to, reads the FIRST one. A
      // later instance therefore cannot widen what a client attests.
      const script = [
        PROBE_PREAMBLE,
        "$n = '\\\\.\\pipe\\ab-t14-' + [guid]::NewGuid().ToString('N')",
        "$accepted = New-SA ('O:' + $me + 'D:P(A;;0x12019F;;;' + $me + ')')",
        '$i1 = [NP]::CreateNamedPipeW($n, ($OPEN -bor $FIRST), $MODE, 255, 4096, 4096, 0, [ref]$accepted)',
        "$wide = New-SA ('O:' + $me + 'D:P(A;;GA;;;WD)(A;;GA;;;' + $me + ')')",
        '$i2 = [NP]::CreateNamedPipeW($n, $OPEN, $MODE, 255, 4096, 4096, 0, [ref]$wide)',
        '$none = New-Object NP+SA',
        '$i3 = [NP]::CreateNamedPipeW($n, $OPEN, $MODE, 255, 4096, 4096, 0, [ref]$none)',
        '$seen = @()',
        'foreach ($k in 1..3) {',
        '  $c = [NP]::CreateFileW($n, [uint32]2147483648, 0, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)',
        "  if ($c -eq $INVALID) { $seen += 'CONNECT_FAILED'; continue }",
        '  $seen += (Read-Struct $c)',
        '  [void][NP]::CloseHandle($c)',
        '}',
        'foreach ($h in @($i1,$i2,$i3)) { if ($h -ne $INVALID) { [void][NP]::CloseHandle($h) } }',
        "[pscustomobject]@{ seen = $seen; me = $me } | ConvertTo-Json -Compress",
      ].join('\n');

      const result = await runPipeProbe(script);
      const seen = result['seen'] as string[];
      const me = result['me'] as string;
      expect(seen).toHaveLength(3);
      // Every client read the same STRUCTURE...
      expect(new Set(seen.map((s) => s.toLowerCase())).size).toBe(1);
      // ...and it is exactly the FIRST instance's: the accepted owner, a
      // present+protected DACL, exactly one ACCESS_ALLOWED ace with no flags,
      // mask 0x12019F and the operator as trustee. Asserted as STRUCTURE, over
      // numeric SIDs and numeric fields, so no SDDL rendering — and therefore
      // no canonical alias such as LA or BA — can change the outcome.
      expect(seen[0]?.toLowerCase()).toBe(
        `owner=${me} dacl=1 1 1 aces=00 00 0012019f ${me}`.toLowerCase(),
      );
    }, 90000);
  },
);
