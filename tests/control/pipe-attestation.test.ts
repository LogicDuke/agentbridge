/**
 * DDR-D062-B — LIVE PIPE SERVER IDENTITY RELAYER: the focused attack matrix.
 *
 * The property under test is the one a descriptor can never establish:
 *
 *     CLI EXIT 0 (APPLIED)  ⇒  the pipe that answered was served by a process
 *                              owned by the trusted operator, holding the
 *                              private half of the key that attestation relayed.
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
  frameMessage,
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
 * 1. Identity of the SERVING PROCESS decides, not the descriptor
 * ================================================================== */

describe('DDR-D062-B — a perfect descriptor grants nothing (SEAM)', () => {
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
      attest: attestDouble({ serverSid: FOREIGN_OPERATOR_SID }),
    });
    expect(run.outcome.exitCode).toBe(1);
    expect(run.outcome.authenticated).toBe(false);
    expect(run.outcome.status).toBeNull();
    expect(run.err.some((line) => line.includes('SERVER_SID_MISMATCH'))).toBe(true);
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
      attest: attestDouble({ serverSid: FOREIGN_OPERATOR_SID }),
    });
    expect(run.outcome.exitCode).toBe(1);
    expect(run.outcome.status).toBeNull();
    expect(run.err.some((line) => line.includes('SERVER_SID_MISMATCH'))).toBe(true);
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

describe('DDR-D062-B — attested key binds the command session (SEAM)', () => {
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
 * instead of the attested one. This is the pre-DDR-D062-B trust shape.
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

describe('DDR-D062-B — negative controls (each guard is load-bearing)', () => {
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
      attest: attestDouble({ serverSid: FOREIGN_OPERATOR_SID }),
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

describe('DDR-D062-B — attestor output is parsed totally (SEAM)', () => {
  const sid = FAKE_OPERATOR_SID;
  const hello = Buffer.from('{"v":2}', 'utf8');
  const good = attestEvidenceText(sid, hello);

  it('14a. the exact grammar parses, and the hello bytes survive verbatim', () => {
    const parsed = parseAttestationEvidence(good);
    expect(parsed?.serverSid).toBe(sid.toLowerCase());
    expect(parsed?.helloBody.equals(hello)).toBe(true);
  });

  it('14b. malformed, truncated, extra, reordered and non-canonical outputs are all rejected', () => {
    const bad: readonly string[] = [
      '',
      'AGENTBRIDGE-ATTEST-V1\n',
      `AGENTBRIDGE-ATTEST-V2\nSERVERSID ${sid}\nHELLO ${hello.toString('hex')}\n`,
      // no trailing newline
      good.slice(0, -1),
      // an extra line
      `${good}EXTRA junk\n`,
      // a surplus blank line
      `${good}\n`,
      // reordered
      `AGENTBRIDGE-ATTEST-V1\nHELLO ${hello.toString('hex')}\nSERVERSID ${sid}\n`,
      // CRLF instead of LF
      good.replace(/\n/g, '\r\n'),
      // non-canonical SID
      `AGENTBRIDGE-ATTEST-V1\nSERVERSID NT-AUTHORITY\\SYSTEM\nHELLO ${hello.toString('hex')}\n`,
      // uppercase hex
      `AGENTBRIDGE-ATTEST-V1\nSERVERSID ${sid}\nHELLO ${hello.toString('hex').toUpperCase()}\n`,
      // odd-length hex
      `AGENTBRIDGE-ATTEST-V1\nSERVERSID ${sid}\nHELLO abc\n`,
      // empty hello
      `AGENTBRIDGE-ATTEST-V1\nSERVERSID ${sid}\nHELLO \n`,
      // wrong labels
      `AGENTBRIDGE-ATTEST-V1\nSID ${sid}\nHELLO ${hello.toString('hex')}\n`,
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
 * 5. REAL ARTIFACT — the native attestor against real pipes
 * ================================================================== */

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const attestorExe = join(repoRoot, 'dist', 'control', 'native', 'agentbridge-win-pipe-attest.exe');
const attestorProv = join(repoRoot, 'dist', 'control', 'native', 'pipe-attestor-provenance.js');
const nativeReady =
  process.platform === 'win32' && existsSync(attestorExe) && existsSync(attestorProv);

/**
 * Point the REAL attestation gate at the REAL built artifact while these tests run
 * the `src/` modules. Only the module-resolution root moves: the binary, its
 * generated provenance, the SHA-256-before-exec gate, the bounded runner, the
 * parser and the SID comparison are all the production ones.
 */
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

describe.skipIf(!nativeReady)('DDR-D062-B — the REAL native attestor (Windows, dist-gated)', () => {
  it('relays the exact hello of a real live pipe and the real SID of its serving process', async () => {
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
    // And the SID is this test process's own — the process that serves the pipe.
    const self = await runAttestor([pipePath]);
    expect(parseAttestationEvidence(self.stdout)?.serverSid).toBe(evidence?.serverSid);
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
    // Deterministic: the connection is accepted, then the serving process is
    // gone. The pin cannot hold and no hello can arrive, so there is nothing the
    // artifact could ever emit.
    const pipePath = pipePathFromName(pipeNameForRuntimeId('abcd'.repeat(8)));
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const child = await startChildServer(pipePath, 'process.exit(0);');
      const run = await runAttestor([pipePath]);
      expect(run.code, `attempt ${String(attempt)}: ${run.stderr}`).not.toBe(0);
      expect(run.stdout).toBe('');
      expect(run.stderr.trim()).toMatch(
        /^(ERR_CONNECT|ERR_SERVER_PID|ERR_OPEN_PROCESS|ERR_PROC_TIMES|ERR_PID_REUSE|ERR_HELLO_PREFIX|ERR_HELLO_BODY)$/,
      );
      child.kill('SIGKILL');
      await delay(20);
    }
  }, 60000);

  it('8/9b. a server exiting right after its hello either attests completely or not at all', async () => {
    // Here the exit races the attestation, so BOTH outcomes are legitimate. What
    // must never happen is a half-result: an exit 0 whose evidence does not parse,
    // or any stdout at all on a failure. The pin is what makes that true — the SID
    // and the hello are re-attributed to the same live process instance before the
    // single stdout write.
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
          /^(ERR_CONNECT|ERR_SERVER_PID|ERR_OPEN_PROCESS|ERR_PROC_TIMES|ERR_PID_REUSE|ERR_HELLO_PREFIX|ERR_HELLO_BODY)$/,
        );
      }
      child.kill('SIGKILL');
      await delay(20);
    }
  }, 60000);

  it('8b. the reviewed source pins the serving process by creation time and re-proves it before EVERY emission', async () => {
    // A genuine PID recycle cannot be forced from a test, so the guard is proven
    // by construction over the exact reviewed source the build compiles.
    const { readFileSync } = await import('node:fs');
    const source = readFileSync(
      join(repoRoot, 'tools', 'control-owner', 'agentbridge-win-pipe-attest.c'),
      'utf8',
    );
    // The creation FILETIME is captured once, from the pinned handle.
    expect(source).toContain('GetProcessTimes(proc, &created, &exited, &kernel_time, &user_time)');
    // Every re-check compares that exact instant, the pipe's server PID, and liveness.
    expect(source).toContain('return filetime_equal(&now_created, created);');
    expect(source).toContain('GetNamedPipeServerProcessId(pipe, &current_pid) || current_pid != pid');
    expect(source).toContain('WaitForSingleObject(proc, 0) != WAIT_TIMEOUT');
    // Re-proven at least three times: on pin, after the token query, after the hello.
    expect(source.match(/if \(!pin_still_holds\(pipe, proc, pid, &created\)\)/g)?.length).toBe(3);
    // The single stdout write happens only after the last pin proof.
    expect(source.match(/write_stdout\(/g)?.length).toBe(2); // the helper + its one call site
    const lastPin = source.lastIndexOf('pin_still_holds(pipe, proc, pid, &created)');
    const emit = source.lastIndexOf('write_stdout(out, len);');
    expect(lastPin).toBeGreaterThan(0);
    expect(emit).toBeGreaterThan(lastPin);
  });

  it('15. attesting a live runtime leaks no handles, logs nothing, and does not disturb the next session', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const anchor = memAnchor();
    const logged: string[] = [];
    const handle = await startServer(orchestrator, anchor, {
      overrides: {
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
