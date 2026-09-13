import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { createRuntimeDescriptor } from '../../src/control/control-store.js';
import * as helperPair from '../../tools/control-owner/helper-pair.mjs';

/**
 * D062_CONTRACT_DOC_CURRENT — the architecture contract tracks the implementation.
 *
 * `docs/architecture/D3-cockpit-dashboard-host.md` is the ONLY document that
 * states the D062 control-channel contract, and it drifted twice: a protocol
 * commit changed the descriptor version, the native artifact set, and the
 * authentication primitives while touching no document, so the contract stayed
 * correct for exactly one commit and nothing could fail.
 *
 * These assertions are **implementation-derived**, never a whole-document
 * snapshot: the expected values are read from the live descriptor factory and
 * the live artifact-basename exports, so the guard tracks the code instead of a
 * frozen string. Prose, rationale and ordering are deliberately NOT bound —
 * only the three machine-checkable constants, plus the absence of the one
 * retired primitive name. A fourth native artifact is caught automatically,
 * because every artifact must export a basename to get a provenance pair.
 */

const D3_DOC = fileURLToPath(
  new URL('../../docs/architecture/D3-cockpit-dashboard-host.md', import.meta.url),
);

/** How the document spells a small count, indexed by the count itself. */
const COUNT_WORDS = Object.freeze(['zero', 'one', 'two', 'three', 'four', 'five']);

const doc = readFileSync(D3_DOC, 'utf8');

/** The live on-disk descriptor version, from the factory that mints them. */
const liveVersion = createRuntimeDescriptor().descriptor.version;

/** Every native artifact the helper-pair module publishes a basename for. */
const liveArtifacts = Object.values(helperPair).filter(
  (value): value is string => typeof value === 'string' && value.endsWith('.exe'),
);

describe('D062 architecture contract (D3) tracks the implementation', () => {
  it('states the live descriptor version everywhere it states one', () => {
    const stated = [...doc.matchAll(/version:\s*(\d+)/g)].map((match) => Number(match[1]));
    expect(stated.length).toBeGreaterThan(0);
    for (const version of stated) {
      expect(version).toBe(liveVersion);
    }
  });

  it('titles the descriptor lifecycle section with the live version', () => {
    const heading = /^### Descriptor lifecycle v(\d+)\b/m.exec(doc);
    expect(heading).not.toBeNull();
    expect(Number(heading?.[1])).toBe(liveVersion);
  });

  it('names every provisioned native artifact, and states their live count', () => {
    expect(liveArtifacts.length).toBeGreaterThan(0);
    for (const artifact of liveArtifacts) {
      expect(doc).toContain(artifact);
    }
    const countWord = COUNT_WORDS[liveArtifacts.length];
    if (countWord === undefined) {
      throw new Error(`no count word for ${String(liveArtifacts.length)} artifacts`);
    }
    expect(doc).toContain(`${countWord} native artifact/provenance pairs`);
  });

  it('names the live server-direction primitive and no retired one', () => {
    expect(doc).toContain('Ed25519');
    expect(doc).not.toMatch(/mutual[-\s]HMAC/i);
  });
});
