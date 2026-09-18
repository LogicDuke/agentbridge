import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

/**
 * Architecture invariants for Autoflow Job #1 (Decision 065 Revision 2;
 * Decision 065 Amendment 1 Clauses A, B, C).
 *
 * These are the structural claims the amendment makes. Each is asserted against
 * the source rather than merely documented in it, because a boundary nothing
 * checks is a boundary the next edit moves without noticing.
 */

function read(relative: string): string {
  return readFileSync(fileURLToPath(new URL(`../../${relative}`, import.meta.url)), 'utf8');
}

/** The module's executable code, with comments stripped. */
function code(relative: string): string {
  return read(relative)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/.*/g, '');
}

describe('Amendment 1 B — the producer stays echo-only', () => {
  const producer = code('src/cockpit-snapshot/producer.ts');

  it('performs no classification, canonicalization, hashing, or digesting', () => {
    for (const forbidden of [
      'classifyRetirementCandidate',
      'canonicalizeAssessmentBody',
      'sha256Canonical',
      'createHash',
      'node:crypto',
      'digest',
    ]) {
      expect(producer, `producer must not reach ${forbidden}`).not.toContain(forbidden);
    }
  });

  it('verifies no evidenceId and opens no gate', () => {
    for (const forbidden of ['readEvidenceId', 'openHumanGate', 'HUMAN_GATE', 'evaluateEvidence']) {
      expect(producer, forbidden).not.toContain(forbidden);
    }
  });

  it('originates no WorkflowEvent and imports no transition', () => {
    for (const forbidden of [
      'applyWorkflowEvent',
      'openWorkflow',
      'WORKFLOW_EVENT_KIND',
      'WorkflowEvent',
    ]) {
      expect(producer, forbidden).not.toContain(forbidden);
    }
  });

  it('invokes no Git, GitHub, process, network, filesystem, clock, or environment', () => {
    for (const forbidden of [
      'node:fs',
      'node:https',
      'node:http',
      'node:child_process',
      'process-transport',
      'invokeAgentProcess',
      'fetch(',
      'Date.now',
      'new Date',
      'process.env',
    ]) {
      expect(producer, forbidden).not.toContain(forbidden);
    }
  });

  it('holds no store, writer, orchestrator, or observer handle', () => {
    for (const forbidden of [
      'RetirementAssessmentStore',
      'AutoflowOrchestrator',
      'AutoflowRuntime',
      'createRetirementAssessmentStore',
      'RetirementGitObserver',
    ]) {
      expect(producer, forbidden).not.toContain(forbidden);
    }
  });

  it('takes the verified list as data on its observation input', () => {
    expect(producer).toContain('retirementAssessments');
    expect(producer).toContain('defaultOptionalList(observation.retirementAssessments)');
  });
});

describe('Decision 065 §3 — the digest lives only in the runtime layer', () => {
  it('the domain kernel computes no SHA-256', () => {
    const domain = code('src/domain/retirement-assessment.ts');
    expect(domain).not.toContain('node:crypto');
    expect(domain).not.toContain('createHash');
  });

  it('D1 computes no SHA-256', () => {
    const d1 = code('src/cockpit/read-model.ts');
    expect(d1).not.toContain('node:crypto');
    expect(d1).not.toContain('createHash');
    expect(d1).not.toContain('sha256Canonical');
  });

  it('D4 computes no SHA-256', () => {
    const d4 = code('src/cockpit/autoflow-projection.ts');
    expect(d4).not.toContain('node:crypto');
    expect(d4).not.toContain('createHash');
    expect(d4).not.toContain('sha256Canonical');
  });

  it('exactly one runtime module computes it', () => {
    const store = code('src/runtime/retirement-assessment-store.ts');
    expect(store).toContain("from 'node:crypto'");
    for (const other of [
      'src/runtime/retirement-manifest.ts',
      'src/runtime/retirement-assessment-runner.ts',
      'src/runtime/retirement-github-client.ts',
    ]) {
      expect(code(other), `${other} must reuse the one digest primitive`).not.toContain(
        'createHash',
      );
    }
  });
});

describe('Amendment 1 A — transport containment', () => {
  it('only the observer names the transport', () => {
    for (const other of [
      'src/runtime/retirement-manifest.ts',
      'src/runtime/retirement-assessment-runner.ts',
      'src/runtime/retirement-github-client.ts',
      'src/runtime/retirement-assessment-store.ts',
      'src/autoflow/orchestrator.ts',
      'src/cockpit-snapshot/producer.ts',
      'src/cockpit/read-model.ts',
      'src/cockpit/autoflow-projection.ts',
      'src/cockpit-host/render.ts',
    ]) {
      expect(read(other), other).not.toContain('invokeAgentProcess');
      expect(read(other), other).not.toContain('process-transport');
    }
  });

  it('the observer never exports or returns the transport', () => {
    const observer = code('src/runtime/retirement-git-observer.ts');
    // Imported once, bound to one module-local const, and never re-exported.
    expect(observer).toContain('const transport = invokeAgentProcess;');
    expect(observer).not.toContain('export { invokeAgentProcess');
    expect(observer).not.toContain('return transport');
    expect(observer).not.toContain('transport,');
  });

  it('src/adapters/** is untouched by Job #1', () => {
    for (const adapter of [
      'src/adapters/agent-transport.ts',
      'src/adapters/process-transport.ts',
    ]) {
      const source = read(adapter);
      expect(source, adapter).not.toContain('retirement');
      expect(source, adapter).not.toContain('Retirement');
      expect(source, adapter).not.toContain('Job #1');
    }
  });
});

describe('Amendment 1 B-6 — the frozen Cockpit host', () => {
  it('src/cockpit-host/server.ts knows nothing about Job #1', () => {
    const server = read('src/cockpit-host/server.ts');
    expect(server).not.toContain('retirement');
    expect(server).not.toContain('Retirement');
  });

  it('the renderer invokes the pure D4 sub-projection itself', () => {
    const render = code('src/cockpit-host/render.ts');
    expect(render).toContain('projectCockpitRetirementAssessments(snapshot.retirementAssessments');
  });
});

describe('the Cockpit barrel exports no second projection function', () => {
  it('re-exports the sub-projection types only, never its function', () => {
    const barrel = code('src/cockpit/index.ts');
    expect(barrel).toContain('CockpitRetirementProjection');
    // The D1 surface invariant: `projectCockpitEvidenceFreshness` stays the one
    // non-reader function the barrel exports.
    expect(barrel).not.toContain('projectCockpitRetirementAssessments,');
    expect(barrel).not.toContain('  projectCockpitRetirementAssessments\n');
  });
});

describe('Amendment 1 C — T4 / F3 is not repaired here', () => {
  it('no Job #1 module claims descendant-process termination', () => {
    for (const relative of [
      'src/runtime/retirement-git-observer.ts',
      'src/runtime/retirement-assessment-runner.ts',
    ]) {
      const source = code(relative);
      for (const forbidden of ['process.kill', 'taskkill', 'process-group', 'killTree']) {
        expect(source, `${relative}: ${forbidden}`).not.toContain(forbidden);
      }
    }
  });
});

describe('Decision 065 Exclusions', () => {
  it('no Job #1 module persists, replays, or reaches Drive', () => {
    for (const relative of [
      'src/domain/retirement-assessment.ts',
      'src/runtime/retirement-manifest.ts',
      'src/runtime/retirement-assessment-store.ts',
      'src/runtime/retirement-git-observer.ts',
      'src/runtime/retirement-github-client.ts',
      'src/runtime/retirement-assessment-runner.ts',
    ]) {
      const source = code(relative);
      for (const forbidden of [
        'googleapis',
        'drive.google.com',
        'writeFileSync',
        'appendFileSync',
        'localStorage',
      ]) {
        expect(source, `${relative}: ${forbidden}`).not.toContain(forbidden);
      }
    }
  });

  it('no Job #1 module reads a token or credential', () => {
    for (const relative of [
      'src/runtime/retirement-github-client.ts',
      'src/runtime/retirement-assessment-runner.ts',
      'src/runtime/retirement-git-observer.ts',
    ]) {
      const source = code(relative);
      for (const forbidden of ['TOKEN', 'SECRET', 'PASSWORD', 'Authorization', 'credential']) {
        expect(source, `${relative}: ${forbidden}`).not.toContain(forbidden);
      }
    }
  });

  it('the domain kernel performs no I/O of any kind', () => {
    const domain = code('src/domain/retirement-assessment.ts');
    for (const forbidden of [
      'node:',
      'process.',
      'Date.now',
      'new Date',
      'Math.random',
      'fetch(',
    ]) {
      expect(domain, forbidden).not.toContain(forbidden);
    }
  });
});
