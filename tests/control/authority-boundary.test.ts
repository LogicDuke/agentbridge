import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

/**
 * D062 authority-boundary source scans over `src/control/` (and the one wiring
 * edit in `src/runtime/live-cockpit.ts`). These pin the frozen product boundary:
 * exactly one command, no generic event surface, no Git/GitHub/provider/Policy,
 * no shell, and strict token discipline. Ratification R-1 of
 * AGENTBRIDGE_DECISION_062_AMENDMENT_RUNTIME_AUTHENTICATION_2026-09-12 (PR #85 F3)
 * reads a single canonical OWNER + DACL snapshot from the build-provenanced native
 * helper and removes the localized `icacls` read entirely — leaving exactly two
 * read-only executables (whoami and the owner+DACL helper) and no more; the
 * helper's identity lives in generated build metadata, never as a hardcoded
 * source `.exe` literal.
 */

const controlDir = fileURLToPath(new URL('../../src/control/', import.meta.url));

interface Source {
  readonly file: string;
  readonly text: string;
}

/** Remove block and line comments so scans target code, not documentation. */
function stripComments(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

function controlSources(): readonly Source[] {
  return readdirSync(controlDir)
    .filter((name) => name.endsWith('.ts'))
    .map((name) => ({ file: name, text: stripComments(readFileSync(join(controlDir, name), 'utf8')) }));
}

function textOf(file: string): string {
  return stripComments(readFileSync(join(controlDir, file), 'utf8'));
}

describe('D062 authority boundary — one command, no widened event surface', () => {
  const forbidden: readonly RegExp[] = [
    /applyWorkflowEvent/,
    /openWorkflow/,
    /\.apply\s*\(/,
    /HUMAN_GATE_OPENED/, // minted internally by the orchestrator, never here
    /CLOSE_REQUESTED/,
    /HEAD_OBSERVED/,
    /INVOCATION_REQUESTED/,
    /INVOCATION_REPORTED/,
    /EVIDENCE_ADMITTED/,
    /REVIEW_ADMITTED/,
  ];

  it('the control layer never widens beyond openHumanGate', () => {
    for (const { file, text } of controlSources()) {
      for (const pattern of forbidden) {
        expect(text, `${file} must not match ${String(pattern)}`).not.toMatch(pattern);
      }
    }
  });

  it('the dispatcher calls only openHumanGate', () => {
    const dispatch = textOf('control-dispatch.ts');
    expect(dispatch).toMatch(/openHumanGate\(\)/);
  });
});

describe('D062 authority boundary — no Git/GitHub/provider/Policy/network', () => {
  const forbidden: readonly RegExp[] = [
    /octokit/i,
    /simple-git/,
    /node:https/,
    /node:http\b/,
    /node:dgram/,
    /node:tls/,
    /\bfetch\s*\(/,
    /WebSocket/,
    /XMLHttpRequest/,
    /\bgit\s+(?:push|commit|merge|rebase|checkout)\b/,
    /provider/i,
    /policy/i,
  ];

  it('references no forbidden capability', () => {
    for (const { file, text } of controlSources()) {
      for (const pattern of forbidden) {
        expect(text, `${file} must not match ${String(pattern)}`).not.toMatch(pattern);
      }
    }
  });
});

describe('D062 authority boundary — no shell, two read-only executables', () => {
  const forbiddenShell: readonly RegExp[] = [
    /powershell/i,
    /\bpwsh\b/,
    /cmd\.exe/i,
    /-EncodedCommand/i,
    /\bexecSync\b/,
    /\bspawnSync\b/,
    /\bspawn\s*\(/,
    /(?<![.\w])exec\s*\(/, // bare exec(); .exec( (RegExp) and execFile( do not match
    /\bfork\s*\(/,
    /\bshell\s*:\s*true/,
  ];

  it('uses no shell or general process runner', () => {
    for (const { file, text } of controlSources()) {
      for (const pattern of forbiddenShell) {
        expect(text, `${file} must not match ${String(pattern)}`).not.toMatch(pattern);
      }
    }
  });

  it('the only hardcoded executable is whoami.exe under System32, shell:false', () => {
    const store = textOf('control-store.ts');
    expect(store).toMatch(/whoami\.exe/);
    // Ratification R-1 removed the localized icacls read from the authorization path.
    expect(store).not.toMatch(/icacls/i);
    expect(store).toMatch(/System32/);
    expect(store).toMatch(/shell:\s*false/);
    // No other .exe literal is referenced anywhere in the control layer. The
    // owner+DACL helper is deliberately NOT hardcoded: its filename is read from
    // generated build metadata, so it never appears as a source literal here.
    for (const { file, text } of controlSources()) {
      const exeMatches = text.match(/[A-Za-z0-9]+\.exe(?![A-Za-z0-9])/g) ?? [];
      for (const match of exeMatches) {
        expect(['whoami.exe'], `${file} references ${match}`).toContain(match);
      }
    }
  });
});

describe('D062 authority boundary — owner-SID gate is provenance-rooted and hash-verified', () => {
  it('reads the owner helper identity from generated build metadata, not env or a sidecar', () => {
    const store = textOf('control-store.ts');
    // Trust root is the generated provenance JS module (a built artifact).
    expect(store).toMatch(/owner-helper-provenance/);
    // The expected hash is never a mutable .sha256 sidecar nor an env/argv value.
    expect(store).not.toMatch(/['"][^'"]*\.sha256['"]/);
    expect(store).not.toMatch(/process\.env\[[^\]]*(?:SHA|HASH|HELPER)/i);
    expect(store).not.toMatch(/process\.env\.\w*(?:SHA|HASH|HELPER)/i);
  });

  it('hash-verifies the helper bytes before it can be executed', () => {
    const store = textOf('control-store.ts');
    expect(store).toMatch(/createHash\(\s*['"]sha256['"]\s*\)/);
    expect(store).toMatch(/timingSafeEqual/);
    expect(store).toMatch(/HELPER_HASH_MISMATCH/);
    expect(store).toMatch(/HELPER_MISSING/);
    expect(store).toMatch(/HELPER_PROVENANCE_MISSING/);
  });

  it('requires the anchor OWNER SID to equal the operator SID and rejects SYSTEM ownership', () => {
    const store = textOf('control-store.ts');
    expect(store).toMatch(/verifyAnchorSnapshot/);
    expect(store).toMatch(/OWNER_IS_SYSTEM/);
    expect(store).toMatch(/OWNER_MISMATCH/);
  });
});

describe('D062 authority boundary — token discipline', () => {
  it('never logs the token and never places it in env or argv', () => {
    for (const { file, text } of controlSources()) {
      const lines = text.split(/\r?\n/);
      for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index] ?? '';
        const mentionsToken = /token/i.test(line);
        if (mentionsToken) {
          expect(/console\.\w+\s*\(/.test(line), `${file}:${String(index + 1)} logs token`).toBe(
            false,
          );
          expect(/argv/i.test(line), `${file}:${String(index + 1)} puts token in argv`).toBe(false);
        }
        // No environment-variable assignment anywhere in the control layer.
        expect(
          /process\.env(?:\.\w+|\[[^\]]*\])\s*=[^=]/.test(line),
          `${file}:${String(index + 1)} assigns process.env`,
        ).toBe(false);
      }
    }
  });
});
