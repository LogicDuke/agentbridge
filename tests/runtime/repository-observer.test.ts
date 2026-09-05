import { describe, expect, it } from 'vitest';

import {
  createConfiguredRepositoryObserver,
  type RepositoryObservation,
} from '../../src/runtime/repository-observer.js';

const VALID: RepositoryObservation = {
  repositoryId: 'repo-agentbridge',
  observedHeadSha: '7af903053bfba65edf42abf11cb52e0a75b8db7c',
  defaultBranchRef: 'refs/heads/main',
};

describe('createConfiguredRepositoryObserver', () => {
  it('returns the configured values exactly', () => {
    const observer = createConfiguredRepositoryObserver(VALID);
    const observation = observer.observe();
    expect(observation.repositoryId).toBe('repo-agentbridge');
    expect(observation.observedHeadSha).toBe('7af903053bfba65edf42abf11cb52e0a75b8db7c');
    expect(observation.defaultBranchRef).toBe('refs/heads/main');
  });

  it('accepts a null defaultBranchRef', () => {
    const observer = createConfiguredRepositoryObserver({ ...VALID, defaultBranchRef: null });
    expect(observer.observe().defaultBranchRef).toBeNull();
  });

  it('returns an immutable, stable observation on every call', () => {
    const observer = createConfiguredRepositoryObserver(VALID);
    const first = observer.observe();
    const second = observer.observe();
    expect(first).toBe(second);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(observer)).toBe(true);
  });

  it('exposes no I/O capability — only observe()', () => {
    const observer = createConfiguredRepositoryObserver(VALID);
    const keys = Object.keys(observer);
    expect(keys).toStrictEqual(['observe']);
  });

  it('fails on invalid config: empty repositoryId', () => {
    expect(() => createConfiguredRepositoryObserver({ ...VALID, repositoryId: '' })).toThrow();
  });

  it('fails on invalid config: empty observedHeadSha', () => {
    expect(() => createConfiguredRepositoryObserver({ ...VALID, observedHeadSha: '   ' })).toThrow();
  });

  it('fails on invalid config: non-string, non-null defaultBranchRef', () => {
    expect(() =>
      createConfiguredRepositoryObserver({
        ...VALID,
        defaultBranchRef: 123 as unknown as string,
      }),
    ).toThrow();
  });
});
