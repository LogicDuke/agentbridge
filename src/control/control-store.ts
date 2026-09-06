/**
 * Decision 062 Windows control-anchor security model and per-process descriptor
 * lifecycle.
 *
 * ## Verify-before-use, fail-closed
 *
 * Before a descriptor is written or read, the deployment-anchored control
 * directory (conceptually `%LOCALAPPDATA%\AgentBridge\control\`) is verified:
 *
 * - every path component is `lstat`-checked and any symlink/reparse condition is
 *   rejected;
 * - the anchor ACL is read (read-only) and its principals must be **exactly** the
 *   runtime operator plus SYSTEM — an inherited entry or any foreign principal
 *   fails closed;
 * - the anchor **OWNER SID** must equal the exact runtime operator SID (Decision
 *   062 Amendment A). SYSTEM is an allowed DACL principal but **never** an allowed
 *   owner, because an owner can rewrite the DACL. The owner SID is read by a
 *   single build-provenanced native helper whose bytes are SHA-256-verified
 *   against generated build metadata before it is ever run; any mismatch, absence,
 *   query failure, or non-canonical result fails closed. A display name can never
 *   satisfy the SID comparison, and DACL membership can never satisfy ownership;
 * - the current operator identity comes from `whoami /user`.
 *
 * This gate is **implementation only**: it never mutates ACLs and never
 * provisions the production directory (a later, separate authority gate). It also
 * makes **no atomic pathname proof** — `icacls` reports account *names*,
 * corroborated here against the runtime's own name and SID from `whoami`, and
 * Node's `lstat` distinguishes a symlink but not every reparse tag. These
 * limitations are preserved deliberately; authorization never depends on them
 * alone — token possession (mutual HMAC) is the actual authenticator.
 *
 * ## Token / descriptor lifecycle
 *
 * The runtime token is 256 bits from {@link crypto.randomBytes}, process-lifetime
 * only, rotated every start, and represented base64url **only** inside the
 * hardened descriptor file. It is never an environment variable, argv, Scheduled
 * Task field, log line, error message, and is never sent raw over the pipe (it is
 * an HMAC key). A stale crash descriptor is safely replaced before serving; an
 * orderly shutdown removes it best-effort.
 */

import { execFile } from 'node:child_process';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { lstatSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { decodeBase64UrlExact, encodeBase64Url } from './control-codec.js';

const randomBytesFn = randomBytes;

/** 256-bit runtime token. */
const TOKEN_BYTES = 32;
/** 128-bit pipe-name randomness, rendered as 32 lowercase hex characters. */
const PIPE_ID_BYTES = 16;
/** Hard cap on a descriptor file we are willing to parse. */
const MAX_DESCRIPTOR_BYTES = 4096;
/** Finite deadline and output cap for the two allowed read-only subprocesses. */
const PROCESS_TIMEOUT_MS = 5000;
const PROCESS_MAX_BUFFER = 1024 * 1024;
/** Defensive cap on path depth while enumerating ancestors. */
const MAX_PATH_DEPTH = 64;

/** Well-known SYSTEM principal, by name and SID. Compared case-insensitively. */
const SYSTEM_IDENTITIES: readonly string[] = Object.freeze([
  'nt authority\\system',
  's-1-5-18',
]);

/** The current descriptor's fixed filename inside the anchor directory. */
const DESCRIPTOR_FILENAME = 'runtime-descriptor.json';

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

/** The descriptor file path inside an anchor directory. */
export function descriptorPathFor(anchorPath: string): string {
  return join(anchorPath, DESCRIPTOR_FILENAME);
}

/** The Windows named-pipe path for a descriptor's pipe name. */
export function pipePathFromName(pipeName: string): string {
  return `\\\\.\\pipe\\${pipeName}`;
}

/* ------------------------------------------------------------------ *
 * Descriptor model
 * ------------------------------------------------------------------ */

/** The hardened per-process descriptor written into the verified anchor. */
export interface RuntimeDescriptor {
  readonly version: 1;
  readonly pid: number;
  readonly pipeName: string;
  /** base64url of the 256-bit token — hardened storage only, never elsewhere. */
  readonly token: string;
}

const PIPE_NAME_PATTERN = /^agentbridge-control-[0-9a-f]{32}$/;

/**
 * Mint a fresh descriptor and its raw token. The token rotates every call
 * (fresh `randomBytes`), the pipe name is per-process unpredictable (128-bit),
 * and the raw token is returned separately so the caller can key HMAC without
 * re-decoding it.
 */
export function createRuntimeDescriptor(pid: number): {
  readonly descriptor: RuntimeDescriptor;
  readonly token: Buffer;
} {
  const token = randomBytesFn(TOKEN_BYTES);
  const pipeName = `agentbridge-control-${randomBytesFn(PIPE_ID_BYTES).toString('hex')}`;
  const descriptor: RuntimeDescriptor = {
    version: 1,
    pid,
    pipeName,
    token: encodeBase64Url(token),
  };
  return { descriptor, token };
}

/** Serialize a descriptor to its on-disk JSON form. */
export function serializeDescriptor(descriptor: RuntimeDescriptor): string {
  return JSON.stringify(descriptor);
}

/**
 * Parse and validate an untrusted descriptor text into a trusted descriptor plus
 * its raw token, or `null`. Bounded, exact-key, and round-trip-verified for the
 * token and pipe name; a stale, truncated, or malformed descriptor fails closed.
 */
export function parseDescriptor(text: unknown): {
  readonly descriptor: RuntimeDescriptor;
  readonly token: Buffer;
} | null {
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
  if (keys.length !== 4) {
    return null;
  }
  const record = parsed as Record<string, unknown>;
  const version = record['version'];
  const pid = record['pid'];
  const pipeName = record['pipeName'];
  const token = record['token'];
  if (
    version !== 1 ||
    typeof pid !== 'number' ||
    !Number.isInteger(pid) ||
    pid < 0 ||
    typeof pipeName !== 'string' ||
    !PIPE_NAME_PATTERN.test(pipeName) ||
    typeof token !== 'string'
  ) {
    return null;
  }
  const rawToken = decodeBase64UrlExact(token, TOKEN_BYTES);
  if (rawToken === null) {
    return null;
  }
  return {
    descriptor: { version: 1, pid, pipeName, token },
    token: rawToken,
  };
}

/* ------------------------------------------------------------------ *
 * Pure ACL / path evaluation
 * ------------------------------------------------------------------ */

/** One ACL entry as read from `icacls`: a principal and whether it is inherited. */
export interface AclEntry {
  readonly principal: string;
  readonly inherited: boolean;
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
  ICACLS_FAILED: 'ICACLS_FAILED',
  ACL_UNREADABLE: 'ACL_UNREADABLE',
  NO_ENTRIES: 'NO_ENTRIES',
  INHERITED_PRINCIPAL: 'INHERITED_PRINCIPAL',
  FOREIGN_PRINCIPAL: 'FOREIGN_PRINCIPAL',
  RUNTIME_PRINCIPAL_ABSENT: 'RUNTIME_PRINCIPAL_ABSENT',
  // Owner-SID gate (F1, Decision 062 Amendment A): the anchor's OWNER must be
  // the exact runtime operator SID, proven by the build-provenanced owner helper.
  HELPER_PROVENANCE_MISSING: 'HELPER_PROVENANCE_MISSING',
  HELPER_MISSING: 'HELPER_MISSING',
  HELPER_HASH_MISMATCH: 'HELPER_HASH_MISMATCH',
  OWNER_QUERY_FAILED: 'OWNER_QUERY_FAILED',
  OWNER_SID_MALFORMED: 'OWNER_SID_MALFORMED',
  OWNER_IS_SYSTEM: 'OWNER_IS_SYSTEM',
  OWNER_MISMATCH: 'OWNER_MISMATCH',
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

/** Parse one `NAME:(flags)...` ACE row; `null` when it is not a valid ACE. */
function parseAce(text: string): AclEntry | null {
  const boundary = text.indexOf(':(');
  if (boundary <= 0) {
    return null;
  }
  const name = text.slice(0, boundary).trim();
  const flags = text.slice(boundary + 1);
  if (name.length === 0) {
    return null;
  }
  // The inherited-from-parent marker is the standalone group `(I)`; `(OI)`,
  // `(CI)`, `(IO)`, `(NP)` are propagation flags, not inheritance.
  const inherited = /\(I\)/.test(flags);
  return { principal: normalizePrincipal(name), inherited };
}

/**
 * Parse `icacls <anchor>` output into ACL entries, or `null` if the output is
 * incomplete or contains an unparseable ACE (fail closed). The `anchorPath`
 * prefix on the first row is stripped before parsing its ACE.
 */
export function parseIcaclsEntries(stdout: string, anchorPath: string): AclEntry[] | null {
  const lines = stdout.split(/\r?\n/);
  const entries: AclEntry[] = [];
  let sawSummary = false;
  for (let index = 0; index < lines.length; index += 1) {
    const raw = lines[index];
    if (raw === undefined) {
      continue;
    }
    const line = raw.replace(/\s+$/, '');
    if (line.length === 0) {
      continue;
    }
    if (/processed\s+\d+\s+files/i.test(line)) {
      sawSummary = true;
      continue;
    }
    let rest = line;
    if (rest.startsWith(anchorPath)) {
      rest = rest.slice(anchorPath.length);
    }
    rest = rest.trim();
    if (rest.length === 0) {
      continue;
    }
    const ace = parseAce(rest);
    if (ace === null) {
      return null;
    }
    entries.push(ace);
  }
  if (!sawSummary) {
    return null;
  }
  return entries;
}

/**
 * Decide whether an anchor ACL is acceptable: no inherited entry, every
 * principal is the runtime operator or SYSTEM, and the runtime operator is
 * present. Fails closed on the first violation.
 */
export function evaluateAnchorAcl(
  operator: OperatorIdentity,
  entries: readonly AclEntry[],
): { readonly ok: true } | { readonly ok: false; readonly reason: ControlAnchorRejection } {
  if (entries.length === 0) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.NO_ENTRIES };
  }
  const runtimeAllowed: readonly string[] = [operator.name, operator.sid];
  let runtimePresent = false;
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry === undefined) {
      return { ok: false, reason: CONTROL_ANCHOR_REJECTION.ACL_UNREADABLE };
    }
    if (entry.inherited) {
      return { ok: false, reason: CONTROL_ANCHOR_REJECTION.INHERITED_PRINCIPAL };
    }
    const isRuntime = runtimeAllowed.includes(entry.principal);
    const isSystem = SYSTEM_IDENTITIES.includes(entry.principal);
    if (!isRuntime && !isSystem) {
      return { ok: false, reason: CONTROL_ANCHOR_REJECTION.FOREIGN_PRINCIPAL };
    }
    if (isRuntime) {
      runtimePresent = true;
    }
  }
  if (!runtimePresent) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.RUNTIME_PRINCIPAL_ABSENT };
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

/** Absolute paths of the two — and only two — authorized executables. */
function whoamiPath(systemRoot: string): string {
  return join(systemRoot, 'System32', 'whoami.exe');
}
function icaclsPath(systemRoot: string): string {
  return join(systemRoot, 'System32', 'icacls.exe');
}

/* ------------------------------------------------------------------ *
 * Owner-SID gate — the third, build-provenanced read-only executable
 * ------------------------------------------------------------------ *
 *
 * The ACL scan above proves who may *access* the anchor; it does not prove who
 * *owns* it, and an owner can rewrite the DACL at will. Decision 062 Amendment A
 * closes that gap: the anchor OWNER SID must equal the exact runtime operator SID
 * (SYSTEM is an allowed DACL principal but never an allowed owner).
 *
 * The owner SID is read by a single, minimal, source-in-repo native helper built
 * from reviewed C by the trusted Windows build (`tools/control-owner/`). Its
 * identity and integrity are rooted in GENERATED BUILD METADATA — the helper's
 * filename and the SHA-256 of the exact compiled binary — emitted as a built JS
 * module beside the binary and loaded module-relative here. There is no committed
 * hash literal, no `.sha256` sidecar, and no env/argv/registry/network authority.
 * Before the helper is ever executed its bytes are hashed and compared to that
 * expected hash; any absence, mismatch, query failure, or non-canonical result
 * fails closed. This adds a third executable (whoami, icacls, owner helper) and
 * no more.
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

export type OwnerVerification =
  | { readonly ok: true; readonly ownerSid: string }
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
 * Load the generated owner-helper provenance module that the trusted build wrote
 * beside the binary (module-relative to this compiled runtime). Any failure or
 * shape violation yields `null`, which the caller treats as fail-closed.
 */
async function defaultLoadProvenance(): Promise<OwnerHelperProvenance | null> {
  try {
    const href = new URL('./native/owner-helper-provenance.js', import.meta.url).href;
    const loaded = (await import(href)) as unknown;
    if (typeof loaded !== 'object' || loaded === null) {
      return null;
    }
    const provenance = (loaded as { OWNER_HELPER_PROVENANCE?: unknown }).OWNER_HELPER_PROVENANCE;
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

/** Resolve the helper's absolute path from the trusted runtime module location. */
function defaultResolveHelperPath(filename: string): string {
  return fileURLToPath(new URL(`./native/${filename}`, import.meta.url));
}

/** Read the helper's exact bytes, or `null` if it is absent/unreadable. */
function defaultReadHelperBytes(helperPath: string): Buffer | null {
  try {
    return readFileSync(helperPath);
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
 * Verify the anchor OWNER SID equals the runtime operator SID, fail-closed. The
 * helper is resolved module-relative, hash-verified against generated provenance,
 * then run read-only via the supplied bounded runner with exactly one absolute
 * anchor-path argument. SYSTEM ownership is rejected even though SYSTEM is an
 * allowed DACL principal; a display name can never satisfy the SID comparison.
 */
export async function verifyAnchorOwner(
  operator: OperatorIdentity,
  anchorPath: string,
  runProcess: ProcessRunner,
  deps: OwnerVerifierDeps = {},
): Promise<OwnerVerification> {
  const provenance = await (deps.loadProvenance ?? defaultLoadProvenance)();
  if (
    provenance === null ||
    !HELPER_SHA256_PATTERN.test(provenance.sha256) ||
    !HELPER_FILENAME_PATTERN.test(provenance.filename)
  ) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.HELPER_PROVENANCE_MISSING };
  }

  const helperPath = (deps.resolveHelperPath ?? defaultResolveHelperPath)(provenance.filename);
  const bytes = (deps.readHelperBytes ?? defaultReadHelperBytes)(helperPath);
  if (bytes === null) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.HELPER_MISSING };
  }

  const actualHash = (deps.hashBytes ?? sha256Hex)(bytes);
  if (!digestsEqual(actualHash, provenance.sha256)) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.HELPER_HASH_MISMATCH };
  }

  const query = await runProcess(helperPath, [anchorPath]);
  if (!query.ok) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.OWNER_QUERY_FAILED };
  }

  const ownerSid = parseOwnerHelperSid(query.stdout);
  if (ownerSid === null) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.OWNER_SID_MALFORMED };
  }
  if (SYSTEM_IDENTITIES.includes(ownerSid)) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.OWNER_IS_SYSTEM };
  }
  if (ownerSid !== operator.sid) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH };
  }
  return { ok: true, ownerSid };
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

/**
 * Verify the control anchor end to end, read-only and fail-closed. Never mutates
 * ACLs and never creates the directory. Uses only the three authorized read-only
 * subprocesses (whoami, icacls, and the build-provenanced owner helper) and
 * `lstat`.
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

  // 2. Current operator identity (name + SID).
  const whoami = await runProcess(whoamiPath(systemRoot), ['/user']);
  if (!whoami.ok) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.WHOAMI_FAILED };
  }
  const operator = parseWhoamiUser(whoami.stdout);
  if (operator === null) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.OPERATOR_UNREADABLE };
  }

  // 3. Anchor ACL (read-only).
  const icacls = await runProcess(icaclsPath(systemRoot), [anchorPath]);
  if (!icacls.ok) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.ICACLS_FAILED };
  }
  const entries = parseIcaclsEntries(icacls.stdout, anchorPath);
  if (entries === null) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.ACL_UNREADABLE };
  }

  // 4. Principals must be exactly runtime operator + SYSTEM, none inherited.
  const acl = evaluateAnchorAcl(operator, entries);
  if (!acl.ok) {
    return { ok: false, reason: acl.reason };
  }

  // 5. Owner SID must be the exact runtime operator SID (SYSTEM owner rejected).
  //    Uses the same bounded runner and the build-provenanced owner helper — the
  //    third and only other read-only executable.
  const owner = await verifyAnchorOwner(operator, anchorPath, runProcess, deps.owner);
  if (!owner.ok) {
    return { ok: false, reason: owner.reason };
  }

  return { ok: true, anchorPath };
}

/* ------------------------------------------------------------------ *
 * Descriptor file I/O — write only after verification
 * ------------------------------------------------------------------ */

export interface DescriptorFileDeps {
  readonly readFile?: (path: string) => string;
  readonly writeFile?: (path: string, data: string) => void;
  readonly removeFile?: (path: string) => void;
}

function defaultReadFile(path: string): string {
  return readFileSync(path, { encoding: 'utf8' });
}
function defaultWriteFile(path: string, data: string): void {
  writeFileSync(path, data, { encoding: 'utf8', mode: 0o600 });
}
function defaultRemoveFile(path: string): void {
  unlinkSync(path);
}

/**
 * Write the descriptor into the (already verified) anchor, replacing any stale
 * crash descriptor. Throws on I/O failure so startup fails closed.
 */
export function writeDescriptorFile(
  anchorPath: string,
  descriptor: RuntimeDescriptor,
  deps: DescriptorFileDeps = {},
): void {
  const write = deps.writeFile ?? defaultWriteFile;
  write(descriptorPathFor(anchorPath), serializeDescriptor(descriptor));
}

/** Read and validate the current descriptor, or `null` if absent/malformed. */
export function readDescriptorFile(
  anchorPath: string,
  deps: DescriptorFileDeps = {},
): { readonly descriptor: RuntimeDescriptor; readonly token: Buffer } | null {
  const read = deps.readFile ?? defaultReadFile;
  let text: string;
  try {
    text = read(descriptorPathFor(anchorPath));
  } catch {
    return null;
  }
  return parseDescriptor(text);
}

/** Best-effort removal of the descriptor (orderly shutdown / stale rotation). */
export function removeDescriptorFile(anchorPath: string, deps: DescriptorFileDeps = {}): void {
  const remove = deps.removeFile ?? defaultRemoveFile;
  try {
    remove(descriptorPathFor(anchorPath));
  } catch {
    // Best-effort only; a missing or locked descriptor is not fatal.
  }
}
