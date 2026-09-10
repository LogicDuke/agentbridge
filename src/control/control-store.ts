/**
 * Decision 062 Windows control-anchor security model and per-runtime descriptor
 * lifecycle (descriptor lifecycle v2: identity-named, listen-before-publish).
 *
 * ## Verify-before-use, fail-closed
 *
 * Before a descriptor is created or read, the deployment-anchored control
 * directory (conceptually `%LOCALAPPDATA%\AgentBridge\control\`) is verified:
 *
 * - every path component is `lstat`-checked and any symlink/reparse condition is
 *   rejected;
 * - the current operator identity comes from `whoami /user` (the trusted operator
 *   SID);
 * - one build-provenanced native helper reads a single OWNER + DACL
 *   security-descriptor snapshot (Decision 062 Amendment B, grammar V2). Its bytes
 *   are SHA-256-verified against generated build metadata before it is ever run;
 *   the snapshot is emitted as **canonical SIDs only** (never localized account
 *   names) and carries the DACL's PROTECTED state and each ACE's exact flags.
 *   From that one snapshot:
 *     - the anchor **OWNER SID** must equal the exact runtime operator SID. SYSTEM
 *       is an allowed DACL principal but **never** an allowed owner, because an
 *       owner can rewrite the DACL;
 *     - the DACL must be PRESENT (neither NULL nor absent) and PROTECTED (no
 *       inheritance from the parent), and its principals must be **exactly** the
 *       runtime operator plus SYSTEM, by canonical SID — an inherited ACE, any
 *       foreign SID, or an unhandled ACE type fails closed, and the operator SID
 *       must be present.
 *   A display name can never satisfy any comparison. There is one security truth
 *   source, not two.
 *
 * This gate is **implementation only**: it never mutates ACLs and never
 * provisions the production directory. It also makes **no atomic pathname
 * proof** — the snapshot is a single read (a sub-millisecond check-to-use TOCTOU
 * window remains), and Node's `lstat` distinguishes a symlink but not every
 * reparse tag. These limitations are preserved deliberately; authorization never
 * depends on them alone — token possession (mutual HMAC) is the actual
 * authenticator.
 *
 * ## Runtime identity and identity-named descriptors (lifecycle v2)
 *
 * There is NO shared fixed descriptor pathname. A single last-writer-wins file
 * cannot support the durable invariant
 *
 *     CONTROL_START_SUCCESS ⇒ DISCOVERY_STATE IDENTIFIES THAT RUNTIME
 *
 * because any point-in-time ownership check of a shared path is stale the moment
 * it returns. Instead every runtime mints a 128-bit random **runtime id** — the
 * hex suffix of its unpredictable pipe name — and publishes exactly one file named
 * `runtime-descriptor-<runtime-id>.json`. The id is validated character-by-
 * character wherever it enters a filename (here and in the native creator), so no
 * caller-controlled path, separator, or traversal can ever reach the filesystem.
 * A runtime removes only its own identity-named file; no runtime ever overwrites
 * or rotates another runtime's file.
 *
 * ## Token / descriptor lifecycle
 *
 * The runtime token is 256 bits from {@link crypto.randomBytes}, process-lifetime
 * only, rotated every start, and represented base64url **only** inside the
 * hardened descriptor file. It is never an environment variable, argv, Scheduled
 * Task field, log line, error message, and is never sent raw over the pipe (it is
 * an HMAC key). The descriptor carries no PID: liveness is decided by the kernel
 * pipe namespace, never by process identity, so PID reuse is irrelevant.
 *
 * ## Descriptor creation (Decision 062 Amendment C)
 *
 * The descriptor's own security is chosen by **Windows**, not by whoever calls a
 * file write: a newly created file's OWNER comes from the creating token's DEFAULT
 * owner (`BUILTIN\Administrators` under elevation) and its DACL from the parent's
 * inheritable ACEs. A SECOND build-provenanced native artifact with create-only
 * authority — {@link createDescriptorFileNative} — creates exactly
 * `<anchor>\runtime-descriptor-<id>.json` with `CREATE_NEW` and an EXPLICIT
 * security descriptor: owner = its own process `TokenUser` SID, and a PROTECTED
 * DACL whose principals are exactly that operator plus SYSTEM. It derives the
 * operator itself, accepts no owner or filename input (only the anchor and one
 * strictly validated runtime id), receives the secret descriptor bytes only on
 * stdin (never argv), and is hash-verified against its own generated provenance
 * before it is executed. Creation is never trusted on its own word: the READ-ONLY
 * helper then inspects the file that actually exists and
 * {@link evaluateDescriptorSnapshot} must accept it, and the file's parsed
 * contents must equal what this runtime minted.
 *
 * ## Liveness and discovery
 *
 * The named-pipe namespace is kernel-owned: a listening server instance exists
 * exactly while a live process holds it. A descriptor's pipe answering ENOENT is
 * therefore a strong deadness signal, and the ONLY signal that ever authorizes
 * deleting a foreign descriptor. A pipe that exists but does not authenticate is
 * never treated as dead. Discovery enumerates a bounded set of identity-named
 * candidates, parses each safely, probes each pipe, and proceeds only with exactly
 * one live candidate; zero is unavailable and two or more is ambiguous (fail
 * closed). Nothing is ever chosen by mtime, PID, lexicographic order, or
 * last-writer-wins.
 */

import { execFile } from 'node:child_process';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { closeSync, lstatSync, openSync, readdirSync, readFileSync, readSync, unlinkSync } from 'node:fs';
import net from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { decodeBase64UrlExact, encodeBase64Url } from './control-codec.js';

const randomBytesFn = randomBytes;

/** 256-bit runtime token. */
const TOKEN_BYTES = 32;
/** 128-bit runtime identity, rendered as 32 lowercase hex characters. */
const RUNTIME_ID_BYTES = 16;
/** Hard cap on a descriptor file we are willing to parse or create. */
export const MAX_DESCRIPTOR_BYTES = 4096;
/** Finite deadline and output cap for the allowed subprocesses. */
const PROCESS_TIMEOUT_MS = 5000;
const PROCESS_MAX_BUFFER = 1024 * 1024;
/** Defensive cap on path depth while enumerating ancestors. */
const MAX_PATH_DEPTH = 64;
/** Bounded maximum number of descriptor candidates examined in one pass. */
export const MAX_DESCRIPTOR_CANDIDATES = 64;
/** Finite deadline for one pipe liveness probe. */
const PIPE_PROBE_TIMEOUT_MS = 2000;

/**
 * Well-known SYSTEM principal, by canonical SID only. Every principal enters
 * authorization as a SID from the native snapshot, so the localized display name
 * ("NT AUTHORITY\SYSTEM") is never consulted.
 */
const SYSTEM_SID = 's-1-5-18';

/* ------------------------------------------------------------------ *
 * Anchor path resolution
 * ------------------------------------------------------------------ */

/** Resolve the conceptual `%LOCALAPPDATA%\AgentBridge\control\`, or `null`. */
export function resolveControlAnchorPath(env: NodeJS.ProcessEnv): string | null {
  const base = env['LOCALAPPDATA'];
  if (typeof base !== 'string' || base.trim().length === 0) {
    return null;
  }
  return join(base, 'AgentBridge', 'control');
}

/** The Windows named-pipe path for a descriptor's pipe name. */
export function pipePathFromName(pipeName: string): string {
  return `\\\\.\\pipe\\${pipeName}`;
}

/* ------------------------------------------------------------------ *
 * Runtime identity
 * ------------------------------------------------------------------ */

const PIPE_NAME_PREFIX = 'agentbridge-control-';
const DESCRIPTOR_FILENAME_PREFIX = 'runtime-descriptor-';
const DESCRIPTOR_FILENAME_SUFFIX = '.json';

/** Exactly 32 lowercase hex characters — the only shape a runtime id may take. */
const RUNTIME_ID_PATTERN = /^[0-9a-f]{32}$/;
const PIPE_NAME_PATTERN = /^agentbridge-control-([0-9a-f]{32})$/;
const DESCRIPTOR_FILENAME_PATTERN = /^runtime-descriptor-([0-9a-f]{32})\.json$/;

/** Whether a value is a strictly well-formed runtime id. */
export function isRuntimeId(value: unknown): value is string {
  return typeof value === 'string' && RUNTIME_ID_PATTERN.test(value);
}

/** The runtime id carried by a pipe name, or `null` if the name is malformed. */
export function runtimeIdFromPipeName(pipeName: string): string | null {
  const match = PIPE_NAME_PATTERN.exec(pipeName);
  return match?.[1] ?? null;
}

/** The pipe name for a runtime id. Throws on a malformed id (fail closed). */
export function pipeNameForRuntimeId(runtimeId: string): string {
  if (!isRuntimeId(runtimeId)) {
    throw new TypeError('control-store: malformed runtime id.');
  }
  return `${PIPE_NAME_PREFIX}${runtimeId}`;
}

/**
 * The identity-named descriptor basename for a runtime id. Throws on a malformed
 * id: the id is the ONLY caller-influenced component and it is whitelisted to
 * `[0-9a-f]{32}`, so no separator, dot, traversal, or absolute segment can enter.
 */
export function descriptorFilenameFor(runtimeId: string): string {
  if (!isRuntimeId(runtimeId)) {
    throw new TypeError('control-store: malformed runtime id.');
  }
  return `${DESCRIPTOR_FILENAME_PREFIX}${runtimeId}${DESCRIPTOR_FILENAME_SUFFIX}`;
}

/** The identity-named descriptor path inside an anchor directory. */
export function descriptorPathFor(anchorPath: string, runtimeId: string): string {
  return join(anchorPath, descriptorFilenameFor(runtimeId));
}

/** The runtime id named by a descriptor basename, or `null` if it is not one. */
export function runtimeIdFromDescriptorFilename(filename: string): string | null {
  const match = DESCRIPTOR_FILENAME_PATTERN.exec(filename);
  return match?.[1] ?? null;
}

/* ------------------------------------------------------------------ *
 * Descriptor model (v2)
 * ------------------------------------------------------------------ */

/** The hardened per-runtime descriptor written into the verified anchor. */
export interface RuntimeDescriptor {
  readonly version: 2;
  readonly pipeName: string;
  /** base64url of the 256-bit token — hardened storage only, never elsewhere. */
  readonly token: string;
}

/** A parsed, trusted descriptor with its raw token and derived runtime id. */
export interface ParsedDescriptor {
  readonly descriptor: RuntimeDescriptor;
  readonly token: Buffer;
  readonly runtimeId: string;
}

/**
 * Mint a fresh descriptor, its raw token, and its runtime id. The token rotates
 * every call (fresh `randomBytes`), the runtime id is per-process unpredictable
 * (128-bit) and is the pipe name's suffix, and the raw token is returned
 * separately so the caller can key HMAC without re-decoding it.
 */
export function createRuntimeDescriptor(): ParsedDescriptor {
  const token = randomBytesFn(TOKEN_BYTES);
  const runtimeId = randomBytesFn(RUNTIME_ID_BYTES).toString('hex');
  const descriptor: RuntimeDescriptor = {
    version: 2,
    pipeName: pipeNameForRuntimeId(runtimeId),
    token: encodeBase64Url(token),
  };
  return { descriptor, token, runtimeId };
}

/** Serialize a descriptor to its on-disk JSON form. */
export function serializeDescriptor(descriptor: RuntimeDescriptor): string {
  return JSON.stringify(descriptor);
}

/**
 * Parse and validate an untrusted descriptor text into a trusted descriptor plus
 * its raw token and runtime id, or `null`. Bounded, exact-key, and round-trip-
 * verified for the token and pipe name; a stale, truncated, or malformed
 * descriptor fails closed.
 */
export function parseDescriptor(text: unknown): ParsedDescriptor | null {
  if (typeof text !== 'string' || text.length === 0 || text.length > MAX_DESCRIPTOR_BYTES) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return null;
  }
  const keys = Object.keys(parsed);
  if (keys.length !== 3) {
    return null;
  }
  const record = parsed as Record<string, unknown>;
  const version = record['version'];
  const pipeName = record['pipeName'];
  const token = record['token'];
  if (version !== 2 || typeof pipeName !== 'string' || typeof token !== 'string') {
    return null;
  }
  const runtimeId = runtimeIdFromPipeName(pipeName);
  if (runtimeId === null) {
    return null;
  }
  const rawToken = decodeBase64UrlExact(token, TOKEN_BYTES);
  if (rawToken === null) {
    return null;
  }
  return {
    descriptor: { version: 2, pipeName, token },
    token: rawToken,
    runtimeId,
  };
}

/* ------------------------------------------------------------------ *
 * Pure ACL / path evaluation
 * ------------------------------------------------------------------ */

/** An ACE type the snapshot can represent: an allow or a deny entry. */
export type AceType = 'ALLOW' | 'DENY';

/** One DACL ACE from the native snapshot, addressed by canonical SID. */
export interface AclSnapshotAce {
  readonly type: AceType;
  /** The exact ACE_HEADER AceFlags inheritance/propagation bitset (0x00–0x1F). */
  readonly flags: number;
  /** The ACCESS_MASK as an unsigned 32-bit value. */
  readonly mask: number;
  /** The principal's canonical SID (normalized lowercase). */
  readonly sid: string;
}

/** The DACL state reported by the snapshot. Only PRESENT can ever be accepted. */
export type DaclState = 'PRESENT' | 'NULL' | 'ABSENT';

/** A canonical OWNER + DACL snapshot as parsed from the native `--acl` helper. */
export interface AclSnapshot {
  readonly ownerSid: string;
  readonly daclState: DaclState;
  /** `true` iff SE_DACL_PROTECTED was set (no inheritance from the parent). */
  readonly daclProtected: boolean;
  readonly aces: readonly AclSnapshotAce[];
}

/** The current operator, from `whoami /user`: an account name and its SID. */
export interface OperatorIdentity {
  readonly name: string;
  readonly sid: string;
}

export const CONTROL_ANCHOR_REJECTION = Object.freeze({
  ANCHOR_PATH_UNRESOLVED: 'ANCHOR_PATH_UNRESOLVED',
  COMPONENT_UNREADABLE: 'COMPONENT_UNREADABLE',
  REPARSE_POINT: 'REPARSE_POINT',
  WHOAMI_FAILED: 'WHOAMI_FAILED',
  OPERATOR_UNREADABLE: 'OPERATOR_UNREADABLE',
  // Owner + DACL snapshot gate (Decision 062 Amendment B): one build-provenanced
  // native helper reads a canonical-SID OWNER + DACL snapshot; every invariant
  // below is proven over SIDs, never localized account names.
  HELPER_PROVENANCE_MISSING: 'HELPER_PROVENANCE_MISSING',
  HELPER_MISSING: 'HELPER_MISSING',
  HELPER_HASH_MISMATCH: 'HELPER_HASH_MISMATCH',
  SNAPSHOT_QUERY_FAILED: 'SNAPSHOT_QUERY_FAILED',
  SNAPSHOT_MALFORMED: 'SNAPSHOT_MALFORMED',
  // Owner policy: the OWNER must be the exact runtime operator SID.
  OWNER_IS_SYSTEM: 'OWNER_IS_SYSTEM',
  OWNER_MISMATCH: 'OWNER_MISMATCH',
  // DACL policy: present, protected, non-empty, no inherited ACE, principals
  // exactly within operator + SYSTEM by SID, and the operator SID present.
  DACL_ABSENT: 'DACL_ABSENT',
  DACL_UNPROTECTED: 'DACL_UNPROTECTED',
  NO_ENTRIES: 'NO_ENTRIES',
  INHERITED_PRINCIPAL: 'INHERITED_PRINCIPAL',
  FOREIGN_PRINCIPAL: 'FOREIGN_PRINCIPAL',
  RUNTIME_PRINCIPAL_ABSENT: 'RUNTIME_PRINCIPAL_ABSENT',
  // Descriptor-only policy: the creator always grants SYSTEM, so its absence
  // proves the file was not created by the provenanced creator.
  SYSTEM_PRINCIPAL_ABSENT: 'SYSTEM_PRINCIPAL_ABSENT',
} as const);

export type ControlAnchorRejection =
  (typeof CONTROL_ANCHOR_REJECTION)[keyof typeof CONTROL_ANCHOR_REJECTION];

/** Case/space-normalized principal for comparison. */
function normalizePrincipal(value: string): string {
  return value.trim().toLowerCase();
}

/**
 * Parse `whoami /user` output into the operator's name and SID. The SID column
 * is the stable signal; the account name is the first token on the SID's line.
 */
export function parseWhoamiUser(stdout: string): OperatorIdentity | null {
  const sidPattern = /\bS-1-\d+(?:-\d+)+\b/;
  const lines = stdout.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (line === undefined) {
      continue;
    }
    const match = sidPattern.exec(line);
    if (match === null) {
      continue;
    }
    const sid = match[0];
    const parts = line.trim().split(/\s+/);
    const name = parts[0];
    if (name !== undefined && name.length > 0 && name !== sid) {
      return { name: normalizePrincipal(name), sid: normalizePrincipal(sid) };
    }
  }
  return null;
}

/* ------------------------------------------------------------------ *
 * Canonical OWNER + DACL snapshot (Amendment B, grammar V2)
 * ------------------------------------------------------------------ *
 *
 * The native helper's `--acl <path>` mode emits a bounded, deterministic,
 * locale-independent snapshot (see tools/control-owner/agentbridge-win-owner.c):
 *
 *     AGENTBRIDGE-ACL-V2\n
 *     OWNER <sid>\n
 *     DACL <PRESENT|NULL|ABSENT> <PROTECTED|UNPROTECTED>\n
 *     ACES <count>\n
 *     ACE <ALLOW|DENY> 0xXX 0xXXXXXXXX <sid>\n   (x count, PRESENT only)
 *
 * Every SID is canonical (ConvertSidToStringSidW); no account name ever appears.
 * The parser below is total and bounded: any deviation — wrong magic, a
 * non-canonical SID, an unhandled ACE token, an unsupported flag bit, a count
 * mismatch, a NULL/ABSENT DACL with ACEs, trailing bytes, or over-length input —
 * yields `null` (fail closed).
 */

const SNAPSHOT_MAGIC = 'AGENTBRIDGE-ACL-V2';
/** Hard cap on a snapshot we are willing to parse (the runner also caps output). */
const MAX_SNAPSHOT_BYTES = 128 * 1024;
/** Hard cap on ACE lines, matching the helper's own ACL_MAX_ACES. */
const MAX_SNAPSHOT_ACES = 256;
/** An 8-hex-digit access mask with the exact `0x` prefix the helper emits. */
const ACE_MASK_PATTERN = /^0x[0-9A-Fa-f]{8}$/;
/** A 2-hex-digit ACE flags byte with the exact `0x` prefix the helper emits. */
const ACE_FLAGS_PATTERN = /^0x[0-9A-Fa-f]{2}$/;
/** Only the inheritance/propagation flag bits are representable. */
const SUPPORTED_ACE_FLAGS = 0x1f;
/** ACE_HEADER AceFlags bits consulted by the evaluators. */
const INHERITED_ACE = 0x10;

/** Parse one `ACE <type> <flags> <mask> <sid>` line, or `null` (fail closed). */
function parseAceLine(line: string): AclSnapshotAce | null {
  const parts = line.split(' ');
  if (parts.length !== 5 || parts[0] !== 'ACE') {
    return null;
  }
  const [, typeToken, flagsToken, maskToken, sidToken] = parts;
  if (typeToken !== 'ALLOW' && typeToken !== 'DENY') {
    return null;
  }
  if (flagsToken === undefined || !ACE_FLAGS_PATTERN.test(flagsToken)) {
    return null;
  }
  const flags = Number.parseInt(flagsToken, 16);
  if (!Number.isInteger(flags) || (flags & ~SUPPORTED_ACE_FLAGS) !== 0) {
    return null;
  }
  if (maskToken === undefined || !ACE_MASK_PATTERN.test(maskToken)) {
    return null;
  }
  const mask = Number.parseInt(maskToken, 16);
  if (!Number.isInteger(mask)) {
    return null;
  }
  if (sidToken === undefined || !CANONICAL_SID_PATTERN.test(sidToken)) {
    return null;
  }
  return {
    type: typeToken,
    flags,
    mask,
    sid: normalizePrincipal(sidToken),
  };
}

/**
 * Parse the native `--acl` snapshot into a trusted {@link AclSnapshot}, or `null`
 * (fail closed). Total and bounded: exact grammar, canonical SIDs only, an exact
 * ACE-count match, and a rejected trailing byte.
 */
export function parseAclSnapshot(stdout: string): AclSnapshot | null {
  if (typeof stdout !== 'string' || stdout.length === 0 || stdout.length > MAX_SNAPSHOT_BYTES) {
    return null;
  }
  const lines = stdout.split('\n');
  // The helper terminates every line with LF, so the final split element must be
  // exactly the empty string; anything else is trailing garbage.
  if (lines[lines.length - 1] !== '') {
    return null;
  }
  lines.pop();
  // Four header lines are mandatory: magic, OWNER, DACL, ACES.
  if (lines.length < 4) {
    return null;
  }
  if (lines[0] !== SNAPSHOT_MAGIC) {
    return null;
  }

  const ownerLine = lines[1] ?? '';
  if (!ownerLine.startsWith('OWNER ')) {
    return null;
  }
  const ownerSidRaw = ownerLine.slice('OWNER '.length);
  if (!CANONICAL_SID_PATTERN.test(ownerSidRaw)) {
    return null;
  }
  const ownerSid = normalizePrincipal(ownerSidRaw);

  const daclMatch = /^DACL (PRESENT|NULL|ABSENT) (PROTECTED|UNPROTECTED)$/.exec(lines[2] ?? '');
  if (daclMatch === null) {
    return null;
  }
  const daclState = daclMatch[1] as DaclState;
  const daclProtected = daclMatch[2] === 'PROTECTED';

  const acesLine = lines[3] ?? '';
  if (!acesLine.startsWith('ACES ')) {
    return null;
  }
  const countToken = acesLine.slice('ACES '.length);
  if (!/^\d+$/.test(countToken)) {
    return null;
  }
  const count = Number(countToken);
  if (!Number.isInteger(count) || count < 0 || count > MAX_SNAPSHOT_ACES) {
    return null;
  }

  const aceLines = lines.slice(4);
  if (aceLines.length !== count) {
    return null;
  }
  // A NULL or ABSENT DACL must carry no ACEs; a present DACL may be empty.
  if (daclState !== 'PRESENT' && count !== 0) {
    return null;
  }

  const aces: AclSnapshotAce[] = [];
  for (let index = 0; index < aceLines.length; index += 1) {
    const line = aceLines[index];
    if (line === undefined) {
      return null;
    }
    const ace = parseAceLine(line);
    if (ace === null) {
      return null;
    }
    aces.push(ace);
  }

  return { ownerSid, daclState, daclProtected, aces };
}

type SnapshotEvaluation =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: ControlAnchorRejection };

/**
 * The owner/DACL policy shared by the anchor and the descriptor evaluators:
 * owner = exact operator (never SYSTEM), DACL PRESENT and PROTECTED, non-empty,
 * no inherited ACE, every principal within {operator, SYSTEM} by canonical SID,
 * and the operator present. Returns which of the two allowed principals were
 * seen so a caller can add a stricter membership requirement.
 */
function evaluateRestrictedDacl(
  operator: OperatorIdentity,
  snapshot: AclSnapshot,
): SnapshotEvaluation & { readonly systemPresent?: boolean } {
  if (snapshot.ownerSid === SYSTEM_SID) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.OWNER_IS_SYSTEM };
  }
  if (snapshot.ownerSid !== operator.sid) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH };
  }
  if (snapshot.daclState !== 'PRESENT') {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.DACL_ABSENT };
  }
  if (!snapshot.daclProtected) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.DACL_UNPROTECTED };
  }
  if (snapshot.aces.length === 0) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.NO_ENTRIES };
  }
  let operatorPresent = false;
  let systemPresent = false;
  for (let index = 0; index < snapshot.aces.length; index += 1) {
    const ace = snapshot.aces[index];
    if (ace === undefined) {
      return { ok: false, reason: CONTROL_ANCHOR_REJECTION.SNAPSHOT_MALFORMED };
    }
    if ((ace.flags & INHERITED_ACE) !== 0) {
      return { ok: false, reason: CONTROL_ANCHOR_REJECTION.INHERITED_PRINCIPAL };
    }
    if (ace.sid === operator.sid) {
      operatorPresent = true;
    } else if (ace.sid === SYSTEM_SID) {
      systemPresent = true;
    } else {
      return { ok: false, reason: CONTROL_ANCHOR_REJECTION.FOREIGN_PRINCIPAL };
    }
  }
  if (!operatorPresent) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.RUNTIME_PRINCIPAL_ABSENT };
  }
  return { ok: true, systemPresent };
}

/**
 * Decide whether the ANCHOR snapshot is acceptable, fail-closed over SIDs only.
 *
 * Owner: the OWNER SID must equal the exact runtime operator SID; SYSTEM (which
 * may own then rewrite the DACL) and any foreign owner are rejected.
 *
 * DACL: it must be PRESENT (neither NULL nor absent), PROTECTED (no inheritance
 * from the parent, so a later-widened parent can never enter it), and non-empty;
 * no ACE may be inherited; every ACE principal must be the operator or SYSTEM by
 * canonical SID; and the operator SID must be present. SYSTEM is permitted, not
 * required. No file-inheritance (OBJECT_INHERIT_ACE) requirement is placed on the
 * anchor: the descriptor never relies on inheriting the anchor's ACEs because the
 * creator sets an explicit protected DACL on every descriptor. The allow/deny
 * type and access mask are carried in the snapshot but do NOT gate authorization
 * — an operator ACE counts as present regardless of allow/deny. Token possession
 * (mutual HMAC) remains the actual authenticator.
 */
export function evaluateAnchorSnapshot(
  operator: OperatorIdentity,
  snapshot: AclSnapshot,
): SnapshotEvaluation {
  const evaluation = evaluateRestrictedDacl(operator, snapshot);
  return evaluation.ok ? { ok: true } : evaluation;
}

/**
 * Decide whether a DESCRIPTOR file's snapshot is acceptable. Same owner and DACL
 * policy as the anchor (exact operator owner, PRESENT + PROTECTED, non-empty, no
 * inherited ACE, no foreign principal, operator present) PLUS the SYSTEM
 * principal must be present: the provenanced creator always grants exactly
 * operator + SYSTEM, so a descriptor missing either was not created by it. An
 * unprotected descriptor is rejected rather than trusted — it would keep
 * inheriting from its parent after this one-time verification.
 */
export function evaluateDescriptorSnapshot(
  operator: OperatorIdentity,
  snapshot: AclSnapshot,
): SnapshotEvaluation {
  const evaluation = evaluateRestrictedDacl(operator, snapshot);
  if (!evaluation.ok) {
    return evaluation;
  }
  if (evaluation.systemPresent !== true) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.SYSTEM_PRINCIPAL_ABSENT };
  }
  return { ok: true };
}

/** One path component's `lstat` view; `null` when it could not be read. */
export interface PathProbe {
  readonly isSymbolicLink: boolean;
  readonly isReparsePoint: boolean;
}

export type LstatProbe = (path: string) => PathProbe | null;

/** Enumerate a path's ancestors, root-first, bounded by {@link MAX_PATH_DEPTH}. */
export function enumeratePathComponents(anchorPath: string): string[] {
  const components: string[] = [];
  let current = resolve(anchorPath);
  for (let depth = 0; depth < MAX_PATH_DEPTH; depth += 1) {
    components.push(current);
    const parent = dirname(current);
    if (parent === current) {
      break;
    }
    current = parent;
  }
  components.reverse();
  return components;
}

/**
 * Reject the path if any component is unreadable or a symlink/reparse point.
 * Fails closed: an unreadable component is treated as a rejection, not absence.
 */
export function evaluatePathSafety(
  components: readonly string[],
  probe: LstatProbe,
): { readonly ok: true } | { readonly ok: false; readonly reason: ControlAnchorRejection } {
  for (let index = 0; index < components.length; index += 1) {
    const component = components[index];
    if (component === undefined) {
      return { ok: false, reason: CONTROL_ANCHOR_REJECTION.COMPONENT_UNREADABLE };
    }
    const info = probe(component);
    if (info === null) {
      return { ok: false, reason: CONTROL_ANCHOR_REJECTION.COMPONENT_UNREADABLE };
    }
    if (info.isSymbolicLink || info.isReparsePoint) {
      return { ok: false, reason: CONTROL_ANCHOR_REJECTION.REPARSE_POINT };
    }
  }
  return { ok: true };
}

/* ------------------------------------------------------------------ *
 * OS adapters (execFile / fs) — narrow and injectable
 * ------------------------------------------------------------------ */

export type ProcessResult =
  | { readonly ok: true; readonly stdout: string }
  | { readonly ok: false };

/** Runs one absolute executable with an explicit argv; never a shell. */
export type ProcessRunner = (exe: string, args: readonly string[]) => Promise<ProcessResult>;

/**
 * The production process runner: `child_process.execFile`, `shell:false`,
 * absolute exe path (no PATH lookup, no PowerShell, no cmd), explicit trusted
 * argv and cwd, controlled minimal environment, finite timeout, bounded output,
 * and a required exit code 0.
 */
export function defaultProcessRunner(systemRoot: string): ProcessRunner {
  const system32 = join(systemRoot, 'System32');
  return (exe: string, args: readonly string[]): Promise<ProcessResult> =>
    new Promise<ProcessResult>((resolvePromise) => {
      execFile(
        exe,
        [...args],
        {
          cwd: system32,
          env: { SystemRoot: systemRoot, windir: systemRoot },
          timeout: PROCESS_TIMEOUT_MS,
          maxBuffer: PROCESS_MAX_BUFFER,
          windowsHide: true,
          shell: false,
          encoding: 'utf8',
        },
        (error: unknown, stdout: string) => {
          if (error !== null && error !== undefined) {
            resolvePromise({ ok: false });
            return;
          }
          resolvePromise({ ok: true, stdout });
        },
      );
    });
}

/** The production `lstat` probe. Detects a symlink; other reparse tags are not distinguished. */
export function defaultLstatProbe(path: string): PathProbe | null {
  try {
    const stats = lstatSync(path);
    return { isSymbolicLink: stats.isSymbolicLink(), isReparsePoint: false };
  } catch {
    return null;
  }
}

/**
 * Absolute path of `whoami.exe` — the only hardcoded system executable. The two
 * build-provenanced native artifacts (the read-only owner+DACL helper and the
 * create-only descriptor creator) are the other executables, but their filenames
 * are read from generated build metadata (never a source literal).
 */
function whoamiPath(systemRoot: string): string {
  return join(systemRoot, 'System32', 'whoami.exe');
}

/* ------------------------------------------------------------------ *
 * Owner + DACL snapshot gate — the build-provenanced read-only executable
 * ------------------------------------------------------------------ *
 *
 * The path scan proves the anchor is reached without a symlink/reparse; it does
 * not prove who owns or may access the anchor. Decision 062 Amendment B closes
 * that gap with ONE snapshot: the anchor OWNER SID must equal the exact runtime
 * operator SID (SYSTEM is an allowed DACL principal but never an allowed owner,
 * because an owner can rewrite the DACL), and the protected DACL principals must
 * be exactly operator + SYSTEM by canonical SID.
 *
 * The snapshot is read by a single, minimal, source-in-repo native helper built
 * from reviewed C by the trusted Windows build (`tools/control-owner/`). Its
 * identity and integrity are rooted in GENERATED BUILD METADATA — the helper's
 * filename and the SHA-256 of the exact compiled binary — emitted as a built JS
 * module beside the binary and loaded module-relative here. There is no committed
 * hash literal, no `.sha256` sidecar, and no env/argv/registry/network authority.
 * Before the helper is ever executed its bytes are hashed and compared to that
 * expected hash; any absence, mismatch, query failure, or non-canonical result
 * fails closed.
 */

/** The build-generated provenance of the owner helper (its trust root). */
export interface OwnerHelperProvenance {
  readonly filename: string;
  readonly sha256: string;
}

/** Injection seams for the owner gate; production defaults use the real build output. */
export interface OwnerVerifierDeps {
  readonly loadProvenance?: () => Promise<OwnerHelperProvenance | null>;
  readonly resolveHelperPath?: (filename: string) => string;
  readonly readHelperBytes?: (helperPath: string) => Buffer | null;
  readonly hashBytes?: (bytes: Buffer) => string;
}

export type AnchorSnapshotVerification =
  | { readonly ok: true; readonly ownerSid: string }
  | { readonly ok: false; readonly reason: ControlAnchorRejection };

export type DescriptorAclVerification =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: ControlAnchorRejection };

/** A lowercase 64-hex SHA-256 digest. */
const HELPER_SHA256_PATTERN = /^[0-9a-f]{64}$/;
/** A safe helper basename: no path separators, drive letters, or traversal. */
const HELPER_FILENAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
/** A single canonical SID and nothing else. */
const CANONICAL_SID_PATTERN = /^S-1-\d+(?:-\d+)+$/;

/** SHA-256 of bytes as lowercase hex. */
function sha256Hex(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** Constant-time equality of two same-form lowercase hex digests. */
function digestsEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  try {
    return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
  } catch {
    return false;
  }
}

/**
 * Load one generated provenance module the trusted build wrote beside a native
 * binary (module-relative to this compiled runtime) and read the named binding.
 * Any failure or shape violation yields `null`, which callers treat as
 * fail-closed. Each artifact has its OWN module and its OWN binding name, so a
 * swapped or cross-wired provenance file can never satisfy the other's lookup.
 */
async function loadProvenanceModule(
  basename: string,
  binding: string,
): Promise<OwnerHelperProvenance | null> {
  try {
    const href = new URL(`./native/${basename}`, import.meta.url).href;
    const loaded = (await import(href)) as unknown;
    if (typeof loaded !== 'object' || loaded === null) {
      return null;
    }
    const provenance = (loaded as Record<string, unknown>)[binding];
    if (typeof provenance !== 'object' || provenance === null) {
      return null;
    }
    const record = provenance as { filename?: unknown; sha256?: unknown };
    if (typeof record.filename !== 'string' || typeof record.sha256 !== 'string') {
      return null;
    }
    return { filename: record.filename, sha256: record.sha256 };
  } catch {
    return null;
  }
}

/** The owner helper's generated provenance module (its trust root). */
function defaultLoadProvenance(): Promise<OwnerHelperProvenance | null> {
  return loadProvenanceModule('owner-helper-provenance.js', 'OWNER_HELPER_PROVENANCE');
}

/** Resolve a native artifact's absolute path from the trusted runtime module location. */
function defaultResolveNativePath(filename: string): string {
  return fileURLToPath(new URL(`./native/${filename}`, import.meta.url));
}

/** Read a native artifact's exact bytes, or `null` if it is absent/unreadable. */
function defaultReadNativeBytes(path: string): Buffer | null {
  try {
    return readFileSync(path);
  } catch {
    return null;
  }
}

/**
 * Parse the helper's stdout as exactly one canonical SID, normalized. Any extra
 * output, extra lines, or non-canonical text fails closed (`null`).
 */
export function parseOwnerHelperSid(stdout: string): string | null {
  const trimmed = stdout.replace(/\r?\n$/, '');
  if (!CANONICAL_SID_PATTERN.test(trimmed)) {
    return null;
  }
  return normalizePrincipal(trimmed);
}

/**
 * Resolve, hash-verify, and run the read-only helper in `--acl` mode against one
 * path, returning the parsed snapshot or the fail-closed rejection.
 */
async function readAclSnapshotVerified(
  targetPath: string,
  runProcess: ProcessRunner,
  deps: OwnerVerifierDeps,
): Promise<
  { readonly ok: true; readonly snapshot: AclSnapshot } | { readonly ok: false; readonly reason: ControlAnchorRejection }
> {
  const provenance = await (deps.loadProvenance ?? defaultLoadProvenance)();
  if (
    provenance === null ||
    !HELPER_SHA256_PATTERN.test(provenance.sha256) ||
    !HELPER_FILENAME_PATTERN.test(provenance.filename)
  ) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.HELPER_PROVENANCE_MISSING };
  }

  const helperPath = (deps.resolveHelperPath ?? defaultResolveNativePath)(provenance.filename);
  const bytes = (deps.readHelperBytes ?? defaultReadNativeBytes)(helperPath);
  if (bytes === null) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.HELPER_MISSING };
  }

  const actualHash = (deps.hashBytes ?? sha256Hex)(bytes);
  if (!digestsEqual(actualHash, provenance.sha256)) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.HELPER_HASH_MISMATCH };
  }

  const query = await runProcess(helperPath, ['--acl', targetPath]);
  if (!query.ok) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.SNAPSHOT_QUERY_FAILED };
  }

  const snapshot = parseAclSnapshot(query.stdout);
  if (snapshot === null) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.SNAPSHOT_MALFORMED };
  }
  return { ok: true, snapshot };
}

/**
 * Verify the anchor OWNER + DACL from a single canonical snapshot, fail-closed.
 * The helper is resolved module-relative, hash-verified against generated
 * provenance, then run read-only via the supplied bounded runner with exactly the
 * `--acl <anchor-path>` arguments. Its output is parsed totally (canonical SIDs
 * only) and evaluated by {@link evaluateAnchorSnapshot}.
 */
export async function verifyAnchorSnapshot(
  operator: OperatorIdentity,
  anchorPath: string,
  runProcess: ProcessRunner,
  deps: OwnerVerifierDeps = {},
): Promise<AnchorSnapshotVerification> {
  const read = await readAclSnapshotVerified(anchorPath, runProcess, deps);
  if (!read.ok) {
    return { ok: false, reason: read.reason };
  }
  const evaluation = evaluateAnchorSnapshot(operator, read.snapshot);
  if (!evaluation.ok) {
    return { ok: false, reason: evaluation.reason };
  }
  return { ok: true, ownerSid: read.snapshot.ownerSid };
}

/**
 * Verify one exact identity-named descriptor file through the same provenanced
 * read-only snapshot path, evaluated by {@link evaluateDescriptorSnapshot}.
 */
export async function verifyDescriptorSnapshot(
  operator: OperatorIdentity,
  descriptorPath: string,
  runProcess: ProcessRunner,
  deps: OwnerVerifierDeps = {},
): Promise<DescriptorAclVerification> {
  const read = await readAclSnapshotVerified(descriptorPath, runProcess, deps);
  if (!read.ok) {
    return { ok: false, reason: read.reason };
  }
  return evaluateDescriptorSnapshot(operator, read.snapshot);
}

export interface VerifyControlAnchorDeps {
  readonly env?: NodeJS.ProcessEnv;
  readonly anchorPath?: string;
  readonly systemRoot?: string;
  readonly runProcess?: ProcessRunner;
  readonly lstat?: LstatProbe;
  readonly owner?: OwnerVerifierDeps;
}

export type ControlAnchorVerification =
  | { readonly ok: true; readonly anchorPath: string }
  | { readonly ok: false; readonly reason: ControlAnchorRejection };

/** Resolve the current operator through the bounded `whoami /user` read. */
async function resolveOperator(
  systemRoot: string,
  runProcess: ProcessRunner,
): Promise<
  { readonly ok: true; readonly operator: OperatorIdentity } | { readonly ok: false; readonly reason: ControlAnchorRejection }
> {
  const whoami = await runProcess(whoamiPath(systemRoot), ['/user']);
  if (!whoami.ok) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.WHOAMI_FAILED };
  }
  const operator = parseWhoamiUser(whoami.stdout);
  if (operator === null) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.OPERATOR_UNREADABLE };
  }
  return { ok: true, operator };
}

/**
 * Verify the control anchor end to end, read-only and fail-closed. Never mutates
 * ACLs and never creates the directory. Uses only the read-only subprocesses
 * (whoami and the build-provenanced owner+DACL helper) and `lstat`.
 */
export async function verifyControlAnchor(
  deps: VerifyControlAnchorDeps = {},
): Promise<ControlAnchorVerification> {
  const env = deps.env ?? process.env;
  const anchorPath = deps.anchorPath ?? resolveControlAnchorPath(env);
  if (anchorPath === null || anchorPath.trim().length === 0) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.ANCHOR_PATH_UNRESOLVED };
  }
  const systemRoot = deps.systemRoot ?? env['SystemRoot'] ?? 'C:\\Windows';
  const runProcess = deps.runProcess ?? defaultProcessRunner(systemRoot);
  const lstat = deps.lstat ?? defaultLstatProbe;

  // 1. No symlink/reparse component on the path to the anchor.
  const pathSafety = evaluatePathSafety(enumeratePathComponents(anchorPath), lstat);
  if (!pathSafety.ok) {
    return { ok: false, reason: pathSafety.reason };
  }

  // 2. Current operator identity (the trusted operator SID, from whoami /user).
  const operator = await resolveOperator(systemRoot, runProcess);
  if (!operator.ok) {
    return { ok: false, reason: operator.reason };
  }

  // 3. One canonical OWNER + DACL snapshot from the build-provenanced helper is
  //    the single security truth source.
  const snapshot = await verifyAnchorSnapshot(operator.operator, anchorPath, runProcess, deps.owner);
  if (!snapshot.ok) {
    return { ok: false, reason: snapshot.reason };
  }

  return { ok: true, anchorPath };
}

/**
 * Resolve the operator and verify one exact identity-named descriptor file's
 * actual owner + DACL read-only, fail-closed. Runs the same two read-only
 * executables as the anchor gate (whoami and the provenanced helper).
 */
export async function verifyDescriptorAcl(
  descriptorPath: string,
  deps: VerifyControlAnchorDeps = {},
): Promise<DescriptorAclVerification> {
  const env = deps.env ?? process.env;
  const systemRoot = deps.systemRoot ?? env['SystemRoot'] ?? 'C:\\Windows';
  const runProcess = deps.runProcess ?? defaultProcessRunner(systemRoot);
  const operator = await resolveOperator(systemRoot, runProcess);
  if (!operator.ok) {
    return { ok: false, reason: operator.reason };
  }
  return verifyDescriptorSnapshot(operator.operator, descriptorPath, runProcess, deps.owner);
}

/* ------------------------------------------------------------------ *
 * Descriptor store I/O — identity-named files inside the verified anchor
 * ------------------------------------------------------------------ */

/** Injection seams for descriptor reads, removals, and anchor enumeration. */
export interface DescriptorFileDeps {
  /** Basenames inside the anchor; throws when the anchor cannot be listed. */
  readonly listAnchor?: (anchorPath: string) => readonly string[];
  readonly readFile?: (path: string) => string;
  readonly removeFile?: (path: string) => void;
}

function defaultListAnchor(anchorPath: string): readonly string[] {
  return readdirSync(anchorPath);
}
/**
 * Bounded descriptor read: at most {@link MAX_DESCRIPTOR_BYTES} + 1 bytes are
 * ever read from a candidate, so an oversized file in the anchor can neither be
 * loaded whole nor pass the parser's length cap (the extra byte makes an
 * over-cap file fail closed instead of being silently truncated).
 */
function defaultReadFile(path: string): string {
  const fd = openSync(path, 'r');
  try {
    const buffer = Buffer.alloc(MAX_DESCRIPTOR_BYTES + 1);
    const bytesRead = readSync(fd, buffer, 0, buffer.length, 0);
    return buffer.subarray(0, bytesRead).toString('utf8');
  } finally {
    closeSync(fd);
  }
}
function defaultRemoveFile(path: string): void {
  unlinkSync(path);
}

/** Read and validate one descriptor file by exact path, or `null` if absent/malformed. */
export function readDescriptorFile(
  descriptorPath: string,
  deps: DescriptorFileDeps = {},
): ParsedDescriptor | null {
  const read = deps.readFile ?? defaultReadFile;
  let text: string;
  try {
    text = read(descriptorPath);
  } catch {
    return null;
  }
  return parseDescriptor(text);
}

/**
 * Best-effort removal of one exact identity-named descriptor file. Returns
 * whether the unlink succeeded; a missing or locked file is not fatal here.
 */
export function removeDescriptorFile(descriptorPath: string, deps: DescriptorFileDeps = {}): boolean {
  const remove = deps.removeFile ?? defaultRemoveFile;
  try {
    remove(descriptorPath);
    return true;
  } catch {
    return false;
  }
}

/** One identity-named descriptor file found in the anchor. */
export interface DescriptorCandidate {
  readonly runtimeId: string;
  readonly filename: string;
  readonly path: string;
}

export type CandidateEnumeration =
  | {
      readonly ok: true;
      readonly candidates: readonly DescriptorCandidate[];
      /** More identity-named files existed than the bounded cap allowed. */
      readonly truncated: boolean;
    }
  | { readonly ok: false };

/**
 * Enumerate the identity-named descriptor candidates in the anchor. Only
 * basenames of the exact form `runtime-descriptor-<32 hex>.json` are candidates;
 * anything else in the directory is ignored. The result is sorted by runtime id
 * purely for deterministic iteration — order is never authority — and capped at
 * {@link MAX_DESCRIPTOR_CANDIDATES}; a directory holding more is reported as
 * truncated so a discoverer can fail closed on an anomalous anchor.
 */
export function enumerateDescriptorCandidates(
  anchorPath: string,
  deps: DescriptorFileDeps = {},
): CandidateEnumeration {
  const list = deps.listAnchor ?? defaultListAnchor;
  let names: readonly string[];
  try {
    names = list(anchorPath);
  } catch {
    return { ok: false };
  }
  const matched: DescriptorCandidate[] = [];
  for (const name of names) {
    const runtimeId = runtimeIdFromDescriptorFilename(name);
    if (runtimeId === null) {
      continue;
    }
    matched.push({ runtimeId, filename: name, path: join(anchorPath, name) });
  }
  matched.sort((a, b) => (a.runtimeId < b.runtimeId ? -1 : a.runtimeId > b.runtimeId ? 1 : 0));
  const truncated = matched.length > MAX_DESCRIPTOR_CANDIDATES;
  return {
    ok: true,
    candidates: truncated ? matched.slice(0, MAX_DESCRIPTOR_CANDIDATES) : matched,
    truncated,
  };
}

/**
 * Read one candidate safely. A candidate is VALID only when its contents parse
 * and the runtime id inside (the pipe name's suffix) equals the runtime id in the
 * filename; a file whose name and contents disagree is malformed — it could
 * otherwise make one live pipe appear under two names. Malformed candidates are
 * ignored and never deleted: no pipe can be probed to prove them dead.
 */
export function readDescriptorCandidate(
  candidate: DescriptorCandidate,
  deps: DescriptorFileDeps = {},
): { readonly kind: 'valid'; readonly parsed: ParsedDescriptor } | { readonly kind: 'malformed' } {
  const parsed = readDescriptorFile(candidate.path, deps);
  if (parsed === null || parsed.runtimeId !== candidate.runtimeId) {
    return { kind: 'malformed' };
  }
  return { kind: 'valid', parsed };
}

/* ------------------------------------------------------------------ *
 * Pipe liveness — the kernel-owned deadness signal
 * ------------------------------------------------------------------ */

/**
 * The liveness of one named pipe as observed by a bounded connect attempt.
 *
 * - `ABSENT`: the kernel reports no pipe of that name (ENOENT). A listening
 *   server instance exists exactly while a live process holds it, so this is the
 *   strong deadness signal — and the ONLY one that authorizes cleanup.
 * - `PRESENT`: a connection was accepted; some process is serving that name.
 * - `UNKNOWN`: any other outcome (access denied, busy, timeout, transport
 *   error). Never treated as dead.
 */
export type PipeLiveness = 'ABSENT' | 'PRESENT' | 'UNKNOWN';

export type PipeProbe = (pipePath: string) => Promise<PipeLiveness>;

/**
 * The production pipe probe: one `net.connect` to the pipe path with a finite
 * deadline. Connects and immediately destroys the socket; no bytes are sent, so
 * the probe has no protocol side effect. ENOENT maps to `ABSENT`; every other
 * error maps to `UNKNOWN`.
 */
export function defaultPipeProbe(timeoutMs: number = PIPE_PROBE_TIMEOUT_MS): PipeProbe {
  return (pipePath: string): Promise<PipeLiveness> =>
    new Promise<PipeLiveness>((resolvePromise) => {
      const state = { settled: false };
      let socket: net.Socket;
      const finish = (liveness: PipeLiveness): void => {
        if (state.settled) {
          return;
        }
        state.settled = true;
        clearTimeout(timer);
        socket.destroy();
        resolvePromise(liveness);
      };
      const timer = setTimeout(() => {
        finish('UNKNOWN');
      }, timeoutMs);
      try {
        socket = net.connect(pipePath);
      } catch {
        clearTimeout(timer);
        state.settled = true;
        resolvePromise('UNKNOWN');
        return;
      }
      socket.on('connect', () => {
        finish('PRESENT');
      });
      socket.on('error', (error: NodeJS.ErrnoException) => {
        finish(error.code === 'ENOENT' ? 'ABSENT' : 'UNKNOWN');
      });
    });
}

/* ------------------------------------------------------------------ *
 * Stale descriptor sweep (runtime startup) and discovery (CLI)
 * ------------------------------------------------------------------ */

export interface StaleSweepResult {
  /** Identity-named files examined (bounded). */
  readonly examined: number;
  /** Runtime ids whose file was removed because its pipe was ABSENT. */
  readonly removed: readonly string[];
  /** Runtime ids retained because their pipe was PRESENT or UNKNOWN. */
  readonly retained: readonly string[];
  /** Runtime ids whose file was malformed (ignored, never deleted). */
  readonly malformed: readonly string[];
  /** Runtime ids proven dead whose unlink nevertheless failed (left in place). */
  readonly unremovable: readonly string[];
}

/**
 * Remove foreign descriptors proven dead. For each identity-named candidate
 * other than `ownRuntimeId`: parse it safely; if valid, probe the pipe its
 * contents name (which, by the name/content consistency rule, is the pipe for
 * its own id); remove exactly that file iff the probe answers `ABSENT`.
 *
 * Never removes a PRESENT/UNKNOWN peer, never removes a malformed file, never
 * touches any pathname but the exact candidate being adjudicated, and never
 * consults a PID, a timestamp, or a lexicographic position. Best-effort: an
 * unlistable anchor sweeps nothing.
 */
export async function sweepStaleDescriptors(
  anchorPath: string,
  ownRuntimeId: string | null,
  probe: PipeProbe,
  deps: DescriptorFileDeps = {},
): Promise<StaleSweepResult> {
  const removed: string[] = [];
  const retained: string[] = [];
  const malformed: string[] = [];
  const unremovable: string[] = [];
  const enumeration = enumerateDescriptorCandidates(anchorPath, deps);
  if (!enumeration.ok) {
    return { examined: 0, removed, retained, malformed, unremovable };
  }
  let examined = 0;
  for (const candidate of enumeration.candidates) {
    if (candidate.runtimeId === ownRuntimeId) {
      continue;
    }
    examined += 1;
    const read = readDescriptorCandidate(candidate, deps);
    if (read.kind === 'malformed') {
      malformed.push(candidate.runtimeId);
      continue;
    }
    const liveness = await probe(pipePathFromName(read.parsed.descriptor.pipeName));
    if (liveness !== 'ABSENT') {
      retained.push(candidate.runtimeId);
      continue;
    }
    if (removeDescriptorFile(candidate.path, deps)) {
      removed.push(candidate.runtimeId);
    } else {
      unremovable.push(candidate.runtimeId);
    }
  }
  return { examined, removed, retained, malformed, unremovable };
}

export const DISCOVERY_UNAVAILABLE = Object.freeze({
  /** The anchor could not be enumerated. */
  ANCHOR_UNREADABLE: 'ANCHOR_UNREADABLE',
  /** No identity-named descriptor exists. */
  NO_CANDIDATES: 'NO_CANDIDATES',
  /** Candidates exist but none has a PRESENT pipe. */
  NO_LIVE_CANDIDATES: 'NO_LIVE_CANDIDATES',
  /** More candidates than the bounded cap — an anomalous anchor; fail closed. */
  TOO_MANY_CANDIDATES: 'TOO_MANY_CANDIDATES',
} as const);

export type DiscoveryUnavailableReason =
  (typeof DISCOVERY_UNAVAILABLE)[keyof typeof DISCOVERY_UNAVAILABLE];

export interface DiscoveryCounts {
  readonly candidates: number;
  readonly malformed: number;
  readonly live: number;
  readonly dead: number;
  readonly unknown: number;
}

export type DiscoveryOutcome =
  | { readonly kind: 'FOUND'; readonly parsed: ParsedDescriptor; readonly counts: DiscoveryCounts }
  | {
      readonly kind: 'UNAVAILABLE';
      readonly reason: DiscoveryUnavailableReason;
      readonly counts: DiscoveryCounts;
    }
  | {
      readonly kind: 'AMBIGUOUS';
      /** Runtime ids of every PRESENT candidate; none is chosen. */
      readonly live: readonly string[];
      readonly counts: DiscoveryCounts;
    };

/**
 * Discover the one live control runtime. Enumerates the bounded candidate set,
 * parses each deterministically (malformed files are ignored, never a blocker),
 * probes each valid candidate's pipe, and decides:
 *
 * - exactly one PRESENT candidate ⇒ `FOUND` (the caller then runs the mutual-HMAC
 *   handshake with that candidate's token — the protocol's only message is the
 *   authoritative command, so authentication is attempted against a single
 *   runtime, never broadcast);
 * - zero PRESENT candidates ⇒ `UNAVAILABLE`;
 * - two or more PRESENT candidates ⇒ `AMBIGUOUS` (fail closed; nothing is chosen
 *   by mtime, PID, order, or last-writer-wins).
 *
 * Dead (ABSENT) candidates are ignored here; removing them is the runtime's job.
 */
export async function discoverControlRuntime(
  anchorPath: string,
  probe: PipeProbe,
  deps: DescriptorFileDeps = {},
): Promise<DiscoveryOutcome> {
  const enumeration = enumerateDescriptorCandidates(anchorPath, deps);
  const zero: DiscoveryCounts = { candidates: 0, malformed: 0, live: 0, dead: 0, unknown: 0 };
  if (!enumeration.ok) {
    return { kind: 'UNAVAILABLE', reason: DISCOVERY_UNAVAILABLE.ANCHOR_UNREADABLE, counts: zero };
  }
  if (enumeration.truncated) {
    return {
      kind: 'UNAVAILABLE',
      reason: DISCOVERY_UNAVAILABLE.TOO_MANY_CANDIDATES,
      counts: { ...zero, candidates: enumeration.candidates.length },
    };
  }
  if (enumeration.candidates.length === 0) {
    return { kind: 'UNAVAILABLE', reason: DISCOVERY_UNAVAILABLE.NO_CANDIDATES, counts: zero };
  }
  let malformed = 0;
  let dead = 0;
  let unknown = 0;
  const live: { readonly runtimeId: string; readonly parsed: ParsedDescriptor }[] = [];
  for (const candidate of enumeration.candidates) {
    const read = readDescriptorCandidate(candidate, deps);
    if (read.kind === 'malformed') {
      malformed += 1;
      continue;
    }
    const liveness = await probe(pipePathFromName(read.parsed.descriptor.pipeName));
    if (liveness === 'PRESENT') {
      live.push({ runtimeId: candidate.runtimeId, parsed: read.parsed });
    } else if (liveness === 'ABSENT') {
      dead += 1;
    } else {
      unknown += 1;
    }
  }
  const counts: DiscoveryCounts = {
    candidates: enumeration.candidates.length,
    malformed,
    live: live.length,
    dead,
    unknown,
  };
  const single = live[0];
  if (live.length === 1 && single !== undefined) {
    return { kind: 'FOUND', parsed: single.parsed, counts };
  }
  if (live.length === 0) {
    return { kind: 'UNAVAILABLE', reason: DISCOVERY_UNAVAILABLE.NO_LIVE_CANDIDATES, counts };
  }
  return { kind: 'AMBIGUOUS', live: live.map((entry) => entry.runtimeId), counts };
}

/* ------------------------------------------------------------------ *
 * Descriptor creation — the build-provenanced create-only executable
 * ------------------------------------------------------------------ *
 *
 * Decision 062 Amendment C. This gate mirrors the read-only owner gate exactly —
 * generated provenance, module-relative resolution, SHA-256 of the exact bytes
 * before execution — but for a SEPARATE binary with a SEPARATE provenance module
 * and a SEPARATE exported binding, so neither artifact's trust root can ever
 * satisfy the other's.
 *
 * Transport is a security boundary: the descriptor carries the runtime token, so
 * it travels on stdin only. The creator's arguments are exactly the verified
 * anchor path and the strictly validated runtime id; the token never appears in
 * an argument, an environment variable, or a log line, and the creator writes
 * nothing to stdout, so a captured stream can never contain it.
 */

/** Why a descriptor could not be created. Every value is fail-closed. */
export const DESCRIPTOR_CREATION_REJECTION = Object.freeze({
  CREATOR_PROVENANCE_MISSING: 'CREATOR_PROVENANCE_MISSING',
  CREATOR_MISSING: 'CREATOR_MISSING',
  CREATOR_HASH_MISMATCH: 'CREATOR_HASH_MISMATCH',
  /** The runtime id handed to the creator is not `[0-9a-f]{32}`. */
  RUNTIME_ID_MALFORMED: 'RUNTIME_ID_MALFORMED',
  /** The serialized descriptor is empty or exceeds the transport/creator cap. */
  DESCRIPTOR_TOO_LARGE: 'DESCRIPTOR_TOO_LARGE',
  /** The process could not be started at all (spawn/EACCES/ENOENT). */
  CREATOR_SPAWN_FAILED: 'CREATOR_SPAWN_FAILED',
  /** It did not settle within the finite deadline and was killed. */
  CREATOR_TIMEOUT: 'CREATOR_TIMEOUT',
  /** It ran and refused: nonzero exit (CREATE_NEW collision included), a signal, or undeliverable stdin. */
  CREATOR_FAILED: 'CREATOR_FAILED',
} as const);

export type DescriptorCreationRejection =
  (typeof DESCRIPTOR_CREATION_REJECTION)[keyof typeof DESCRIPTOR_CREATION_REJECTION];

export type DescriptorCreation =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: DescriptorCreationRejection };

/** Outcome of one bounded creator invocation; never carries the child's output. */
export type CreatorRunResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly reason:
        | typeof DESCRIPTOR_CREATION_REJECTION.CREATOR_SPAWN_FAILED
        | typeof DESCRIPTOR_CREATION_REJECTION.CREATOR_TIMEOUT
        | typeof DESCRIPTOR_CREATION_REJECTION.CREATOR_FAILED;
    };

/**
 * Runs one absolute create-only executable with an explicit argv and a bounded
 * stdin payload; never a shell. Deliberately a DISTINCT type from
 * {@link ProcessRunner}, which is read-only, accepts no input, and returns stdout:
 * the read-only contract is not widened to carry a payload, and this one cannot
 * return captured bytes, so neither runner can be used for the other's job.
 */
export type CreatorRunner = (
  exe: string,
  args: readonly string[],
  input: Buffer,
) => Promise<CreatorRunResult>;

/** Node's error code when a child overruns `maxBuffer` (an output fault, not a timeout). */
const MAXBUFFER_CODE = 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER';

/**
 * The production creator runner: the SAME process primitive the read-only gate
 * uses — `child_process.execFile`, `shell:false`, absolute exe path (no PATH
 * lookup, no cmd, no PowerShell), explicit trusted argv and cwd, controlled
 * minimal environment, `windowsHide`, a finite timeout, and a bounded output
 * buffer — plus a bounded stdin payload. `execFile` settles exactly once and owns
 * its own timer and listeners, so there is no hand-rolled settlement race.
 *
 * Terminal-cause precedence is explicit: an output overrun is an output fault; a
 * child killed on the deadline is a timeout even though it also exits nonzero; a
 * numeric exit status or a foreign signal is a refusal; anything else (the process
 * never started) is a spawn failure. The child's stdout/stderr are captured only
 * so they can be bounded and discarded: this returns ok/reason and nothing else.
 */
export function defaultCreatorRunner(systemRoot: string): CreatorRunner {
  const system32 = join(systemRoot, 'System32');
  return (exe: string, args: readonly string[], input: Buffer): Promise<CreatorRunResult> =>
    new Promise<CreatorRunResult>((resolvePromise) => {
      let child: ReturnType<typeof execFile>;
      try {
        child = execFile(
          exe,
          [...args],
          {
            cwd: system32,
            env: { SystemRoot: systemRoot, windir: systemRoot },
            timeout: PROCESS_TIMEOUT_MS,
            maxBuffer: PROCESS_MAX_BUFFER,
            windowsHide: true,
            shell: false,
            encoding: 'buffer',
          },
          (error: unknown) => {
            if (error === null || error === undefined) {
              resolvePromise({ ok: true });
              return;
            }
            const failure = error as { code?: unknown; killed?: unknown; signal?: unknown };
            if (failure.code === MAXBUFFER_CODE) {
              resolvePromise({ ok: false, reason: DESCRIPTOR_CREATION_REJECTION.CREATOR_FAILED });
              return;
            }
            if (failure.killed === true) {
              resolvePromise({ ok: false, reason: DESCRIPTOR_CREATION_REJECTION.CREATOR_TIMEOUT });
              return;
            }
            if (typeof failure.code === 'number' || typeof failure.signal === 'string') {
              resolvePromise({ ok: false, reason: DESCRIPTOR_CREATION_REJECTION.CREATOR_FAILED });
              return;
            }
            resolvePromise({ ok: false, reason: DESCRIPTOR_CREATION_REJECTION.CREATOR_SPAWN_FAILED });
          },
        );
      } catch {
        // Windows can reject a non-executable image synchronously instead of
        // through the callback. A process that never started is a spawn failure,
        // and this runner always answers with a result, never a throw.
        resolvePromise({ ok: false, reason: DESCRIPTOR_CREATION_REJECTION.CREATOR_SPAWN_FAILED });
        return;
      }

      const stdinPipe = child.stdin;
      if (stdinPipe === null) {
        // Nothing to deliver the descriptor through; the callback above still
        // settles this promise from the child's own outcome.
        return;
      }
      stdinPipe.on('error', () => {
        // A child that exited before reading (EPIPE) is judged by its exit status,
        // not by our write failing; swallow so it cannot become an unhandled error.
      });
      // `end` honours backpressure internally and flushes the complete payload; the
      // creator reads to EOF, so the descriptor is delivered whole or not at all.
      stdinPipe.end(input);
    });
}

/** Injection seams for the creator gate; production defaults use the real build output. */
export interface DescriptorCreatorDeps {
  readonly loadProvenance?: () => Promise<OwnerHelperProvenance | null>;
  readonly resolveCreatorPath?: (filename: string) => string;
  readonly readCreatorBytes?: (creatorPath: string) => Buffer | null;
  readonly hashBytes?: (bytes: Buffer) => string;
  readonly runCreator?: CreatorRunner;
  readonly systemRoot?: string;
}

/** The descriptor creator's generated provenance module (its own trust root). */
function defaultLoadCreatorProvenance(): Promise<OwnerHelperProvenance | null> {
  return loadProvenanceModule('descriptor-creator-provenance.js', 'DESCRIPTOR_CREATOR_PROVENANCE');
}

/**
 * Create one identity-named descriptor through the build-provenanced create-only
 * native artifact.
 *
 * The creator is resolved module-relative from generated provenance, its exact
 * bytes are SHA-256-verified before it is executed, and it is then run with
 * exactly two arguments — the already verified anchor path and the strictly
 * validated runtime id — and the serialized descriptor on stdin. It derives the
 * runtime operator from its own token, refuses to run as SYSTEM, derives the
 * filename itself from the validated id, and uses `CREATE_NEW`, so an existing
 * pathname is an error rather than an overwrite.
 *
 * Returns fail-closed on every fault. Success means only "the creator reported
 * it created the file"; the caller must still verify the file that actually
 * exists (owner + DACL through the read-only helper, and contents by read-back)
 * before serving.
 */
export async function createDescriptorFileNative(
  anchorPath: string,
  runtimeId: string,
  descriptorBytes: Buffer,
  deps: DescriptorCreatorDeps = {},
): Promise<DescriptorCreation> {
  if (!isRuntimeId(runtimeId)) {
    return { ok: false, reason: DESCRIPTOR_CREATION_REJECTION.RUNTIME_ID_MALFORMED };
  }
  if (descriptorBytes.length === 0 || descriptorBytes.length > MAX_DESCRIPTOR_BYTES) {
    return { ok: false, reason: DESCRIPTOR_CREATION_REJECTION.DESCRIPTOR_TOO_LARGE };
  }

  const provenance = await (deps.loadProvenance ?? defaultLoadCreatorProvenance)();
  if (
    provenance === null ||
    !HELPER_SHA256_PATTERN.test(provenance.sha256) ||
    !HELPER_FILENAME_PATTERN.test(provenance.filename)
  ) {
    return { ok: false, reason: DESCRIPTOR_CREATION_REJECTION.CREATOR_PROVENANCE_MISSING };
  }

  const creatorPath = (deps.resolveCreatorPath ?? defaultResolveNativePath)(provenance.filename);
  const bytes = (deps.readCreatorBytes ?? defaultReadNativeBytes)(creatorPath);
  if (bytes === null) {
    return { ok: false, reason: DESCRIPTOR_CREATION_REJECTION.CREATOR_MISSING };
  }
  const actualHash = (deps.hashBytes ?? sha256Hex)(bytes);
  if (!digestsEqual(actualHash, provenance.sha256)) {
    return { ok: false, reason: DESCRIPTOR_CREATION_REJECTION.CREATOR_HASH_MISMATCH };
  }

  const systemRoot = deps.systemRoot ?? process.env['SystemRoot'] ?? 'C:\\Windows';
  const runCreator = deps.runCreator ?? defaultCreatorRunner(systemRoot);
  // The anchor path and the validated runtime id are the ONLY arguments. The
  // descriptor bytes travel on stdin.
  const run = await runCreator(creatorPath, [anchorPath, runtimeId], descriptorBytes);
  if (!run.ok) {
    return { ok: false, reason: run.reason };
  }
  return { ok: true };
}
