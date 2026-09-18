/**
 * Job #1 GitHub dependency-clearance client — **GET only** (Decision 065
 * Revision 2, "Deterministic observer" and "Dependency clearance").
 *
 * Establishes F8: whether anything on GitHub still depends on the retirement
 * candidate. It is read-only by construction, not by convention:
 *
 * - **No method parameter exists.** Every request is a GET because GET is the
 *   only verb this module can express — there is no `method` field on any type
 *   here, so a POST, PATCH, PUT, or DELETE is unconstructible rather than merely
 *   unused (Decision 065 §15).
 * - **No caller URL exists.** Paths come from {@link GITHUB_ENDPOINTS}, a fixed
 *   template table. A caller supplies a validated branch name at most; it never
 *   supplies a URL, a host, a scheme, a port, or a query string.
 * - **No body, and no `Authorization` header.** The client is unauthenticated
 *   against a public repository. It holds no token, reads no credential
 *   environment variable, and has nowhere to put one.
 * - **Host pinned.** `api.github.com:443` over TLS, in the production transport.
 *
 * ## Bounds
 *
 * At most 20 requests per run, 15 s per request, a 2 MiB response bound,
 * `per_page=100`, and Link pagination followed at most 5 pages. Exceeding any
 * bound — like every other failure — yields an **indeterminate** fact.
 *
 * ## Fail-closed
 *
 * Any non-200 (other than the one modelled 404), rate limit, malformed or
 * truncated body, non-terminating pagination, or contradiction makes F8
 * indeterminate, hence `BLOCKED`. "We could not check GitHub" never becomes
 * "GitHub is clear".
 */

import { request as httpsRequest } from 'node:https';

import { readCanonicalBranchRef } from '../domain/repair-job.js';
import {
  determinate,
  INDETERMINATE,
  type RetirementFact,
} from '../domain/retirement-assessment.js';

const objectFreeze = Object.freeze;
const objectSetPrototypeOf = Object.setPrototypeOf;
const objectDefineProperty = Object.defineProperty;

function freezeRecord<T extends object>(record: T): Readonly<T> {
  objectSetPrototypeOf(record, null);
  return objectFreeze(record);
}

function append<T>(list: T[], value: T): void {
  const descriptor: PropertyDescriptor = {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  };
  objectSetPrototypeOf(descriptor, null);
  objectDefineProperty(list, list.length, descriptor);
}

/** The exact bounds Decision 065 fixes for the GitHub path. */
export const GITHUB_LIMITS = objectFreeze({
  /** Requests permitted across one whole run, across every endpoint. */
  MAX_REQUESTS_PER_RUN: 20,
  /** Per-request deadline in milliseconds. */
  TIMEOUT_MS: 15_000,
  /** Response body bound in bytes. Exceeding it is indeterminate, never truncated. */
  MAX_RESPONSE_BYTES: 2 * 1024 * 1024,
  /** Page size requested on every list endpoint. */
  PER_PAGE: 100,
  /** Link-header pages followed. A 6th `next` link is indeterminate. */
  MAX_PAGES: 5,
} as const);

/** The pinned production host. There is no configuration point that widens it. */
export const GITHUB_HOST = 'api.github.com';
/** The pinned production port. TLS only. */
export const GITHUB_PORT = 443;

/**
 * The fixed endpoint template table. These four templates are the entire
 * reachable request surface; there is no fifth, and no caller-composed path.
 */
export const GITHUB_ENDPOINTS = objectFreeze({
  REPOSITORY: '/repos/{owner}/{repo}',
  OPEN_PULL_REQUESTS: '/repos/{owner}/{repo}/pulls?state=open&per_page={perPage}',
  OPEN_ISSUES: '/repos/{owner}/{repo}/issues?state=open&per_page={perPage}',
  BRANCH: '/repos/{owner}/{repo}/branches/{branch}',
} as const);

/* ------------------------------------------------------------------------- *
 * The GET transport seam
 * ------------------------------------------------------------------------- */

/** One GET response, already bounded and decoded. */
export interface GitHubResponse {
  readonly statusCode: number;
  readonly body: string;
  /** The `Link` header verbatim, or `null`. Only `rel="next"` is ever read. */
  readonly linkHeader: string | null;
  /** `true` when the body exceeded {@link GITHUB_LIMITS.MAX_RESPONSE_BYTES}. */
  readonly truncated: boolean;
}

/**
 * The GET seam: given a path **this module built from its own template table**,
 * perform one unauthenticated GET and return the bounded response.
 *
 * This is a `path -> response` function, never a `url -> response` one: it cannot
 * express a host, a scheme, a port, a method, a header set, or a body. Tests
 * substitute a fake server through {@link GitHubClientConfig.get}; production
 * omits it and gets {@link createHttpsGet} pinned to `api.github.com:443`.
 */
export type GitHubGet = (path: string) => Promise<GitHubResponse | null>;

/**
 * The production GET transport: TLS to `api.github.com:443`, no credential of
 * any kind, bounded body, hard deadline.
 *
 * Returns `null` on any transport-level failure — DNS, TLS, socket, timeout,
 * abort — because a failed request is an indeterminate observation, not an
 * exception to be caught somewhere far away and mistaken for "nothing found".
 */
export function createHttpsGet(): GitHubGet {
  return async (path: string): Promise<GitHubResponse | null> =>
    new Promise<GitHubResponse | null>((resolve) => {
      let settled = false;
      const finish = (value: GitHubResponse | null): void => {
        if (!settled) {
          settled = true;
          resolve(value);
        }
      };
      let clientRequest;
      try {
        clientRequest = httpsRequest(
          {
            host: GITHUB_HOST,
            port: GITHUB_PORT,
            path,
            // The verb is a literal. There is no parameter, and no branch here
            // that could select another.
            method: 'GET',
            headers: {
              // GitHub requires a User-Agent. No Authorization header is set,
              // here or anywhere else in this module.
              'User-Agent': 'agentbridge-job1-readonly-observer',
              Accept: 'application/vnd.github+json',
            },
            timeout: GITHUB_LIMITS.TIMEOUT_MS,
          },
          (response): void => {
            const chunks: Buffer[] = [];
            let total = 0;
            let truncated = false;
            response.on('data', (chunk: Buffer): void => {
              total += chunk.length;
              if (total > GITHUB_LIMITS.MAX_RESPONSE_BYTES) {
                truncated = true;
                response.destroy();
                return;
              }
              append(chunks, chunk);
            });
            response.on('end', (): void => {
              const linkValue = response.headers['link'];
              finish({
                statusCode: response.statusCode ?? 0,
                body: Buffer.concat(chunks).toString('utf8'),
                linkHeader: typeof linkValue === 'string' ? linkValue : null,
                truncated,
              });
            });
            response.on('error', (): void => {
              finish(null);
            });
          },
        );
      } catch {
        finish(null);
        return;
      }
      clientRequest.on('error', (): void => {
        finish(null);
      });
      clientRequest.on('timeout', (): void => {
        clientRequest.destroy();
        finish(null);
      });
      // No body is ever written: `end()` with no argument closes the request.
      clientRequest.end();
    });
}

/* ------------------------------------------------------------------------- *
 * Observation value shapes
 * ------------------------------------------------------------------------- */

/** One open pull request, reduced to the two refs dependency clearance needs. */
export interface PullRequestRef {
  readonly number: number;
  /** The head ref name as GitHub reports it (branch name, not a full ref). */
  readonly headRef: string;
  readonly baseRef: string;
}

/** One open issue, reduced to the text dependency clearance scans. */
export interface IssueRef {
  readonly number: number;
  readonly title: string;
  readonly body: string;
}

/** The subset of the branch resource F8 reads. `null` models a modelled 404. */
export interface BranchInfo {
  readonly name: string;
  readonly commitSha: string;
  readonly protected: boolean;
}

/** The subset of the repository resource F8 reads. */
export interface RepositoryInfo {
  readonly defaultBranch: string;
}

/* ------------------------------------------------------------------------- *
 * Configuration
 * ------------------------------------------------------------------------- */

/** Everything the client needs. No token, and no URL, appear in this type. */
export interface GitHubClientConfig {
  readonly owner: string;
  readonly repo: string;
  /** Test seam only. Omit in production to pin `api.github.com:443` over TLS. */
  readonly get?: GitHubGet;
}

/**
 * The public client surface: four named read-only queries.
 *
 * No member takes a method, a URL, a header, or a body, and none exists that
 * writes. `requestCount` exposes the shared budget for assertions.
 */
export interface RetirementGitHubClient {
  repository(): Promise<RetirementFact<RepositoryInfo>>;
  openPullRequests(): Promise<RetirementFact<readonly PullRequestRef[]>>;
  openIssues(): Promise<RetirementFact<readonly IssueRef[]>>;
  /** `determinate(null)` models a 404 — the branch genuinely does not exist. */
  branch(branchRef: string): Promise<RetirementFact<BranchInfo | null>>;
  requestCount(): number;
}

/** Percent-encode one path segment. Owner/repo/branch names reach a path here. */
function encodeSegment(value: string): string {
  return encodeURIComponent(value);
}

/** Extract the `rel="next"` target from a `Link` header, or `null`. */
function nextLink(linkHeader: string | null): string | null {
  if (linkHeader === null) {
    return null;
  }
  const parts = linkHeader.split(',');
  for (let index = 0; index < parts.length; index += 1) {
    const part = parts[index];
    if (part === undefined || !part.includes('rel="next"')) {
      continue;
    }
    const open = part.indexOf('<');
    const close = part.indexOf('>');
    if (open === -1 || close === -1 || close <= open + 1) {
      return null;
    }
    return part.slice(open + 1, close);
  }
  return null;
}

/**
 * Reduce an absolute `next` URL to a path this client may request.
 *
 * GitHub returns an absolute URL in `Link`. Following it verbatim would be
 * exactly the "caller URL" this module refuses to have, so the host is checked
 * against the pinned one and only the path+query is kept. A `next` pointing
 * anywhere else is refused (`null`), which makes the pagination indeterminate.
 */
function pathFromNext(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:' || parsed.host !== GITHUB_HOST) {
    return null;
  }
  return parsed.pathname + parsed.search;
}

/** Create the one GET-only dependency-clearance client. */
export function createRetirementGitHubClient(
  config: GitHubClientConfig,
): RetirementGitHubClient {
  const get: GitHubGet = config.get ?? createHttpsGet();
  const ownerSegment = encodeSegment(config.owner);
  const repoSegment = encodeSegment(config.repo);
  let requests = 0;

  const base = (template: string): string =>
    template
      .replace('{owner}', ownerSegment)
      .replace('{repo}', repoSegment)
      .replace('{perPage}', String(GITHUB_LIMITS.PER_PAGE));

  /** One budgeted GET. Returns `null` on any failure or budget exhaustion. */
  const fetchOnce = async (path: string): Promise<GitHubResponse | null> => {
    if (requests >= GITHUB_LIMITS.MAX_REQUESTS_PER_RUN) {
      return null;
    }
    requests += 1;
    let response: GitHubResponse | null;
    try {
      response = await get(path);
    } catch {
      return null;
    }
    if (response === null || response.truncated) {
      return null;
    }
    return response;
  };

  /** Parse a JSON array body, or `null`. */
  const parseArray = (body: string): readonly unknown[] | null => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(body) as unknown;
    } catch {
      return null;
    }
    return Array.isArray(parsed) ? (parsed as readonly unknown[]) : null;
  };

  /**
   * Follow a paginated list endpoint to completion, all-or-nothing.
   *
   * A `next` link still present after {@link GITHUB_LIMITS.MAX_PAGES} pages makes
   * the whole reading indeterminate — a bounded prefix of the open-PR list would
   * understate the dependencies on the candidate, and understating is exactly the
   * direction that wrongly favours retirement.
   */
  const collect = async <T>(
    firstPath: string,
    read: (element: unknown) => T | null,
  ): Promise<readonly T[] | null> => {
    const items: T[] = [];
    let path: string | null = firstPath;
    for (let page = 0; page < GITHUB_LIMITS.MAX_PAGES; page += 1) {
      if (path === null) {
        return objectFreeze(items);
      }
      const response = await fetchOnce(path);
      if (response === null || response.statusCode !== 200) {
        return null;
      }
      const elements = parseArray(response.body);
      if (elements === null) {
        return null;
      }
      for (let index = 0; index < elements.length; index += 1) {
        const item = read(elements[index]);
        if (item === null) {
          return null;
        }
        append(items, item);
      }
      const next = nextLink(response.linkHeader);
      path = next === null ? null : pathFromNext(next);
      if (next !== null && path === null) {
        // A next link that does not reduce to a pinned-host path: refuse rather
        // than follow it, and refuse rather than silently stop early.
        return null;
      }
    }
    // The loop ended with pages remaining.
    return path === null ? objectFreeze(items) : null;
  };

  const readOwn = (value: unknown, key: string): unknown => {
    if (typeof value !== 'object' || value === null) {
      return undefined;
    }
    try {
      return Object.hasOwn(value, key) ? (value as Record<string, unknown>)[key] : undefined;
    } catch {
      return undefined;
    }
  };

  const readPullRequest = (element: unknown): PullRequestRef | null => {
    const number = readOwn(element, 'number');
    const head = readOwn(element, 'head');
    const baseNode = readOwn(element, 'base');
    const headRef = readOwn(head, 'ref');
    const baseRef = readOwn(baseNode, 'ref');
    if (
      typeof number !== 'number' ||
      !Number.isSafeInteger(number) ||
      typeof headRef !== 'string' ||
      typeof baseRef !== 'string'
    ) {
      return null;
    }
    return freezeRecord({ number, headRef, baseRef });
  };

  const readIssue = (element: unknown): IssueRef | null => {
    const number = readOwn(element, 'number');
    const title = readOwn(element, 'title');
    const body = readOwn(element, 'body');
    if (typeof number !== 'number' || !Number.isSafeInteger(number) || typeof title !== 'string') {
      return null;
    }
    // GitHub sends `null` for an empty issue body; that is legitimate absence.
    if (body !== null && typeof body !== 'string') {
      return null;
    }
    return freezeRecord({ number, title, body: body ?? '' });
  };

  const repository = async (): Promise<RetirementFact<RepositoryInfo>> => {
    const response = await fetchOnce(base(GITHUB_ENDPOINTS.REPOSITORY));
    if (response === null || response.statusCode !== 200) {
      return INDETERMINATE;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(response.body) as unknown;
    } catch {
      return INDETERMINATE;
    }
    const defaultBranch = readOwn(parsed, 'default_branch');
    return typeof defaultBranch === 'string' && defaultBranch.length > 0
      ? determinate(freezeRecord({ defaultBranch }))
      : INDETERMINATE;
  };

  const openPullRequests = async (): Promise<RetirementFact<readonly PullRequestRef[]>> => {
    const items = await collect(base(GITHUB_ENDPOINTS.OPEN_PULL_REQUESTS), readPullRequest);
    return items === null ? INDETERMINATE : determinate(items);
  };

  const openIssues = async (): Promise<RetirementFact<readonly IssueRef[]>> => {
    const items = await collect(base(GITHUB_ENDPOINTS.OPEN_ISSUES), readIssue);
    return items === null ? INDETERMINATE : determinate(items);
  };

  const branch = async (branchRef: string): Promise<RetirementFact<BranchInfo | null>> => {
    // The operand is validated as a canonical ref first, then reduced to the
    // short name GitHub's path expects. Nothing else reaches the path.
    const canonical = readCanonicalBranchRef(branchRef);
    if (canonical === null) {
      return INDETERMINATE;
    }
    const shortName = canonical.slice('refs/heads/'.length);
    const path = base(GITHUB_ENDPOINTS.BRANCH).replace('{branch}', encodeSegment(shortName));
    const response = await fetchOnce(path);
    if (response === null) {
      return INDETERMINATE;
    }
    // 404 is a modelled answer: the branch genuinely does not exist on the
    // remote. Every other non-200 is a fault.
    if (response.statusCode === 404) {
      return determinate(null);
    }
    if (response.statusCode !== 200) {
      return INDETERMINATE;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(response.body) as unknown;
    } catch {
      return INDETERMINATE;
    }
    const name = readOwn(parsed, 'name');
    const commitSha = readOwn(readOwn(parsed, 'commit'), 'sha');
    const isProtected = readOwn(parsed, 'protected');
    if (
      typeof name !== 'string' ||
      typeof commitSha !== 'string' ||
      typeof isProtected !== 'boolean'
    ) {
      return INDETERMINATE;
    }
    return determinate(freezeRecord({ name, commitSha, protected: isProtected }));
  };

  return objectFreeze<RetirementGitHubClient>({
    repository,
    openPullRequests,
    openIssues,
    branch,
    requestCount: (): number => requests,
  });
}
