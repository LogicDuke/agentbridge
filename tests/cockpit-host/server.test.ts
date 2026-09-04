import type { AddressInfo } from 'node:net';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createCockpitServer, HOST, PORT } from '../../src/cockpit-host/server.js';

let base = '';
let boundAddress = '';
const server = createCockpitServer();

beforeAll(async () => {
  await new Promise<void>((resolve) => {
    // Listen on an ephemeral port on loopback to avoid clashing with the fixed port.
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('expected an AddressInfo from server.address()');
  }
  const info: AddressInfo = address;
  boundAddress = info.address;
  base = `http://127.0.0.1:${String(info.port)}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) {
        resolve();
      } else {
        reject(error);
      }
    });
  });
});

describe('Cockpit D3 host constants', () => {
  it('binds the literal loopback address', () => {
    expect(HOST).toBe('127.0.0.1');
    expect(boundAddress).toBe('127.0.0.1');
  });

  it('declares a fixed non-privileged port', () => {
    expect(PORT).toBeGreaterThanOrEqual(1024);
  });
});

describe('Cockpit D3 routes', () => {
  it('GET / returns 200 HTML identifying read-only Stage-A data', async () => {
    const response = await fetch(`${base}/`);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('text/html; charset=utf-8');
    const body = await response.text();
    expect(body).toContain('READ ONLY');
    expect(body).toContain('STAGE A');
    // Stage B: the fixture carries a serialized WorkflowState, so the served
    // page shows the populated Autoflow panel rather than the absence copy.
    expect(body).toContain('Autoflow');
    expect(body).not.toContain('Not projected yet');
    expect(body).toContain('wf-stage-a-0001');
    expect(body).toContain('Tree SHA');
  });

  it('GET /styles.css returns 200 CSS', async () => {
    const response = await fetch(`${base}/styles.css`);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('text/css; charset=utf-8');
    const body = await response.text();
    expect(body).toContain('body');
  });

  it('POST / returns 405 with an Allow: GET header (no mutation route)', async () => {
    const response = await fetch(`${base}/`, { method: 'POST' });
    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('GET');
  });

  it('rejects every non-GET method with 405', async () => {
    for (const method of ['PUT', 'DELETE', 'PATCH']) {
      const response = await fetch(`${base}/`, { method });
      expect(response.status).toBe(405);
    }
  });

  it('unknown route returns 404', async () => {
    const response = await fetch(`${base}/does-not-exist`);
    expect(response.status).toBe(404);
  });
});

describe('Cockpit D3 security headers', () => {
  it('sends a strict CSP that blocks scripts and permits only the local stylesheet', async () => {
    const response = await fetch(`${base}/`);
    const csp = response.headers.get('content-security-policy') ?? '';
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'none'");
    expect(csp).toContain("style-src 'self'");
  });

  it('sends X-Content-Type-Options: nosniff on every response', async () => {
    const rootResponse = await fetch(`${base}/`);
    expect(rootResponse.headers.get('x-content-type-options')).toBe('nosniff');
    const missingResponse = await fetch(`${base}/nope`);
    expect(missingResponse.headers.get('x-content-type-options')).toBe('nosniff');
  });
});
