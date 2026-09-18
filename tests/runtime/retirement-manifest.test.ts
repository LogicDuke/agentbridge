import { describe, expect, it } from 'vitest';

import { GOVERNANCE_HOLD, EVIDENCE_ID_PREFIX } from '../../src/domain/retirement-assessment.js';
import { sha256Canonical } from '../../src/runtime/retirement-assessment-store.js';
import {
  GOVERNANCE_SOURCE_ROLE,
  MANIFEST_BOUNDS,
  MANIFEST_FAILURE,
  MANIFEST_HOLD_REASON,
  readGovernanceRunManifest,
  verifyGovernanceRunManifest,
} from '../../src/runtime/retirement-manifest.js';

const CANDIDATE_SHA = 'a'.repeat(40);
const MAIN_SHA = 'c'.repeat(40);
const BOOT_MS = Date.UTC(2026, 8, 18, 12, 0, 0);
const GENERATED_AT = '2026-09-18T06:00:00.000Z';

function manifestObject(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    candidateRef: 'refs/heads/repair/example',
    candidateSha: CANDIDATE_SHA,
    authoritativeMainSha: MAIN_SHA,
    generatedAt: GENERATED_AT,
    gateId: 'prerun-gate-0001',
    sources: [
      {
        role: GOVERNANCE_SOURCE_ROLE.DEFERRED_FINDINGS_REGISTER,
        driveFileId: '1aTHtQzmInQXkQ6OjfWapCeFKJW_LTHh8ey78yw3k9vM',
        title: 'AGENTBRIDGE_DEFERRED_FINDINGS_REGISTER',
        modifiedTime: '2026-09-18T02:18:02.748Z',
        sha256: EVIDENCE_ID_PREFIX + '1'.repeat(64),
      },
      {
        role: GOVERNANCE_SOURCE_ROLE.CURRENT_STATE_CHECKPOINT,
        driveFileId: '1sD6C44meJzyXr0XCVhjI3npToYjQy_rd03fe3DvZdrA',
        title: 'AGENTBRIDGE_CURRENT_STATE_V2_23',
        modifiedTime: '2026-09-18T02:26:52.242Z',
        sha256: EVIDENCE_ID_PREFIX + '2'.repeat(64),
      },
    ],
    holdResult: GOVERNANCE_HOLD.NO_HOLD,
    reasonCodes: [],
    matchingEntries: [],
    git: { path: 'C:\\Program Files\\Git\\cmd\\git.exe', sha256: EVIDENCE_ID_PREFIX + '3'.repeat(64) },
    ...overrides,
  };
}

/** Build the text plus the digest a correct PRE-RUN gate would publish. */
function signed(overrides: Record<string, unknown> = {}): {
  readonly text: string;
  readonly digest: string;
} {
  const object = manifestObject(overrides);
  const accepted = readGovernanceRunManifest(object);
  if (accepted === null) {
    throw new Error('fixture manifest must be schema-valid');
  }
  const digest = sha256Canonical(accepted);
  if (digest === null) {
    throw new Error('fixture manifest must be canonicalizable');
  }
  return { text: JSON.stringify(object), digest };
}

function verify(
  overrides: Record<string, unknown> = {},
  inputOverrides: Partial<{ text: string; digest: string; bootEpochMs: number }> = {},
): ReturnType<typeof verifyGovernanceRunManifest> {
  const base = signed(overrides);
  return verifyGovernanceRunManifest({
    manifestText: inputOverrides.text ?? base.text,
    expectedDigest: inputOverrides.digest ?? base.digest,
    candidateSha: CANDIDATE_SHA,
    authoritativeMainSha: MAIN_SHA,
    bootEpochMs: inputOverrides.bootEpochMs ?? BOOT_MS,
  });
}

describe('readGovernanceRunManifest', () => {
  it('accepts a well-formed manifest and freezes it', () => {
    const manifest = readGovernanceRunManifest(manifestObject());
    expect(manifest).not.toBeNull();
    expect(Object.isFrozen(manifest)).toBe(true);
    expect(manifest?.holdResult).toBe(GOVERNANCE_HOLD.NO_HOLD);
  });

  it('rejects a HOLD carrying no reason — an unexplained hold', () => {
    expect(
      readGovernanceRunManifest(manifestObject({ holdResult: GOVERNANCE_HOLD.HOLD, reasonCodes: [] })),
    ).toBeNull();
  });

  it('rejects a NO_HOLD carrying hold reasons — a self-contradiction', () => {
    expect(
      readGovernanceRunManifest(
        manifestObject({
          holdResult: GOVERNANCE_HOLD.NO_HOLD,
          reasonCodes: [MANIFEST_HOLD_REASON.REGISTER_OPEN_OBLIGATION],
        }),
      ),
    ).toBeNull();
  });

  it('rejects an unknown source role and an unknown hold reason', () => {
    const sources = manifestObject()['sources'] as readonly Record<string, unknown>[];
    const firstSource = sources[0] ?? {};
    expect(
      readGovernanceRunManifest(
        manifestObject({ sources: [{ ...firstSource, role: 'not-a-role' }] }),
      ),
    ).toBeNull();
    expect(
      readGovernanceRunManifest(
        manifestObject({ holdResult: GOVERNANCE_HOLD.HOLD, reasonCodes: ['NOT_A_REASON'] }),
      ),
    ).toBeNull();
  });

  it('rejects a malformed git digest', () => {
    expect(
      readGovernanceRunManifest(manifestObject({ git: { path: '/usr/bin/git', sha256: 'nope' } })),
    ).toBeNull();
  });

  it('never throws on hostile input', () => {
    for (const value of [null, undefined, 0, '', [], new Proxy({}, {})]) {
      expect(() => readGovernanceRunManifest(value)).not.toThrow();
    }
  });
});

describe('verifyGovernanceRunManifest — the verified path', () => {
  it('verifies a correct manifest and yields its hold result', () => {
    const result = verify();
    expect(result.failures).toEqual([]);
    expect(result.manifest).not.toBeNull();
    expect(result.holdResult).toBe(GOVERNANCE_HOLD.NO_HOLD);
  });

  it('carries a verified HOLD through unchanged', () => {
    const result = verify({
      holdResult: GOVERNANCE_HOLD.HOLD,
      reasonCodes: [MANIFEST_HOLD_REASON.REGISTER_OPEN_OBLIGATION],
      matchingEntries: ['§14.8 — expanded binding condition for future src/adapters/** runtime wiring'],
    });
    expect(result.failures).toEqual([]);
    expect(result.holdResult).toBe(GOVERNANCE_HOLD.HOLD);
  });

  it('is insensitive to key order and whitespace in the supplied text', () => {
    // The digest binds the document's *content*, not its spelling.
    const base = signed();
    const reordered = JSON.stringify(
      Object.fromEntries(Object.entries(JSON.parse(base.text) as object).reverse()),
      null,
      2,
    );
    const result = verifyGovernanceRunManifest({
      manifestText: reordered,
      expectedDigest: base.digest,
      candidateSha: CANDIDATE_SHA,
      authoritativeMainSha: MAIN_SHA,
      bootEpochMs: BOOT_MS,
    });
    expect(result.failures).toEqual([]);
    expect(result.holdResult).toBe(GOVERNANCE_HOLD.NO_HOLD);
  });
});

describe('verifyGovernanceRunManifest — every failure is indeterminate, never NO_HOLD', () => {
  it('unparseable text', () => {
    const result = verify({}, { text: 'not json' });
    expect(result.failures).toContain(MANIFEST_FAILURE.TEXT_UNPARSEABLE);
    expect(result.holdResult).toBeNull();
  });

  it('empty text', () => {
    const result = verify({}, { text: '' });
    expect(result.failures).toContain(MANIFEST_FAILURE.TEXT_UNPARSEABLE);
    expect(result.holdResult).toBeNull();
  });

  it('oversized text is refused before parsing', () => {
    const result = verify({}, { text: 'x'.repeat(MANIFEST_BOUNDS.MAX_MANIFEST_TEXT_LENGTH + 1) });
    expect(result.failures).toContain(MANIFEST_FAILURE.TEXT_UNPARSEABLE);
  });

  it('schema-invalid document', () => {
    const result = verify({}, { text: JSON.stringify({ candidateRef: 'refs/heads/x' }) });
    expect(result.failures).toContain(MANIFEST_FAILURE.SCHEMA_INVALID);
    expect(result.holdResult).toBeNull();
  });

  it('a single mutated byte breaks the digest', () => {
    const base = signed();
    const mutated = JSON.parse(base.text) as Record<string, unknown>;
    mutated['gateId'] = 'prerun-gate-0002';
    const result = verifyGovernanceRunManifest({
      manifestText: JSON.stringify(mutated),
      expectedDigest: base.digest,
      candidateSha: CANDIDATE_SHA,
      authoritativeMainSha: MAIN_SHA,
      bootEpochMs: BOOT_MS,
    });
    expect(result.failures).toContain(MANIFEST_FAILURE.DIGEST_MISMATCH);
    expect(result.holdResult).toBeNull();
  });

  it('a malformed expected digest', () => {
    const result = verify({}, { digest: 'nope' });
    expect(result.failures).toContain(MANIFEST_FAILURE.EXPECTED_DIGEST_INVALID);
    expect(result.holdResult).toBeNull();
  });

  it('candidate SHA drift', () => {
    const result = verify({ candidateSha: 'f'.repeat(40) });
    expect(result.failures).toContain(MANIFEST_FAILURE.CANDIDATE_SHA_MISMATCH);
    expect(result.holdResult).toBeNull();
  });

  it('authoritative main SHA drift', () => {
    const result = verify({ authoritativeMainSha: 'e'.repeat(40) });
    expect(result.failures).toContain(MANIFEST_FAILURE.MAIN_SHA_MISMATCH);
    expect(result.holdResult).toBeNull();
  });

  it('generatedAt older than the 24-hour window', () => {
    const result = verify({}, { bootEpochMs: BOOT_MS + MANIFEST_BOUNDS.FRESHNESS_WINDOW_MS });
    expect(result.failures).toContain(MANIFEST_FAILURE.GENERATED_AT_OUT_OF_WINDOW);
    expect(result.holdResult).toBeNull();
  });

  it('generatedAt in the future', () => {
    const result = verify({}, { bootEpochMs: Date.UTC(2026, 8, 18, 5, 0, 0) });
    expect(result.failures).toContain(MANIFEST_FAILURE.GENERATED_AT_OUT_OF_WINDOW);
    expect(result.holdResult).toBeNull();
  });

  it('accepts the exact window boundary and rejects one millisecond past it', () => {
    const atBoundary = verify({}, { bootEpochMs: Date.parse(GENERATED_AT) + MANIFEST_BOUNDS.FRESHNESS_WINDOW_MS });
    expect(atBoundary.failures).toEqual([]);
    const pastBoundary = verify({}, { bootEpochMs: Date.parse(GENERATED_AT) + MANIFEST_BOUNDS.FRESHNESS_WINDOW_MS + 1 });
    expect(pastBoundary.failures).toContain(MANIFEST_FAILURE.GENERATED_AT_OUT_OF_WINDOW);
  });

  it('a leniently-spelled timestamp is out of window, not parsed', () => {
    // `Date.parse` would accept these; the strict reader does not.
    for (const generatedAt of ['2026-09-18', '2026-09-18T06:00:00', 'Sep 18 2026 06:00:00 GMT']) {
      const result = verify({ generatedAt });
      expect(result.failures, generatedAt).toContain(MANIFEST_FAILURE.GENERATED_AT_OUT_OF_WINDOW);
    }
  });

  it('a rolled-over calendar date is out of window', () => {
    expect(verify({ generatedAt: '2026-02-31T06:00:00.000Z' }).failures).toContain(
      MANIFEST_FAILURE.GENERATED_AT_OUT_OF_WINDOW,
    );
  });

  it('a missing required source role', () => {
    const sources = manifestObject()['sources'] as readonly unknown[];
    const result = verify({ sources: [sources[0]] });
    expect(result.failures).toContain(MANIFEST_FAILURE.REQUIRED_SOURCE_MISSING);
    expect(result.holdResult).toBeNull();
  });

  it('collects every failure rather than stopping at the first', () => {
    const result = verify({ candidateSha: 'f'.repeat(40), authoritativeMainSha: 'e'.repeat(40) });
    expect(result.failures).toContain(MANIFEST_FAILURE.CANDIDATE_SHA_MISMATCH);
    expect(result.failures).toContain(MANIFEST_FAILURE.MAIN_SHA_MISMATCH);
  });

  it('never throws, for any input shape', () => {
    for (const text of ['', '{', 'null', '[]', '"x"', '{"a":']) {
      expect(() =>
        verifyGovernanceRunManifest({
          manifestText: text,
          expectedDigest: 'nope',
          candidateSha: CANDIDATE_SHA,
          authoritativeMainSha: MAIN_SHA,
          bootEpochMs: BOOT_MS,
        }),
      ).not.toThrow();
    }
  });
});
