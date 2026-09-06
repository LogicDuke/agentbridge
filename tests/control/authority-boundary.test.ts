import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

/**
 * D062 authority-boundary source scans over `src/control/` (and the one wiring
 * edit in `src/runtime/live-cockpit.ts`). These pin the frozen product boundary:
 * exactly one command, no generic event surface, no Git/GitHub/provider/Policy,
 * no shell, exactly two read-only subprocesses, and strict token discipline.
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

describe('D062 authority boundary — no shell, exactly two read-only subprocesses', () => {
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

  it('the only executables are whoami.exe and icacls.exe under System32, shell:false', () => {
    const store = textOf('control-store.ts');
    expect(store).toMatch(/whoami\.exe/);
    expect(store).toMatch(/icacls\.exe/);
    expect(store).toMatch(/System32/);
    expect(store).toMatch(/shell:\s*false/);
    // No other .exe is referenced anywhere in the control layer.
    for (const { file, text } of controlSources()) {
      const exeMatches = text.match(/[A-Za-z0-9]+\.exe(?![A-Za-z0-9])/g) ?? [];
      for (const match of exeMatches) {
        expect(['whoami.exe', 'icacls.exe'], `${file} references ${match}`).toContain(match);
      }
    }
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
