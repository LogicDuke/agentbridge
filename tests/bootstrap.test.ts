import { describe, expect, it } from 'vitest';

import { agentBridgeVersion } from '../src/index.js';

describe('AgentBridge bootstrap', () => {
  it('loads the TypeScript module under the test runner', () => {
    expect(agentBridgeVersion).toBe('0.0.0');
  });
});
