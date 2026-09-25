/**
 * Job #1 GitHub observation client — Decision 065 Revision 2 GitHub clause
 * (Autoflow Job #1, WF3 clean rebuild slice 3; DDR-SLICE3-TIER3 Revision 1,
 * Commander-ratified).
 *
 * A dedicated, GET-only, unauthenticated observer of ONE configured public
 * repository. It returns typed observations or a typed INDETERMINATE; it never
 * classifies, never computes F8/F10, and never turns a service or transport
 * failure into a negative fact.
 *
 * ## Authority (closed)
 *
 * Host `api.github.com`, port 443, TLS, method GET, no body, no credentials,
 * a fixed header set, and exactly four endpoint families:
 *
 *     REPOSITORY   GET /repos/{owner}/{repo}
 *     BRANCH       GET /repos/{owner}/{repo}/branches/{branch}
 *     OPEN_PULLS   GET /repos/{owner}/{repo}/pulls?state=open&per_page=100&page={page}
 *     OPEN_ISSUES  GET /repos/{owner}/{repo}/issues?state=open&per_page=100&page={page}
 *
 * No caller supplies a URL, host, path, method, header, body, or limit.
 *
 * ## Total completion
 *
 * Every request attempt settles exactly once through one latch. The absolute
 * 15 s deadline starts immediately before `request()` and covers DNS, connect,
 * TLS, headers, and body (PRRT_kwDOTzqfcs6jv8eq). A body crossing 2 MiB settles
 * at the crossing chunk, never waiting for a later end/error/close
 * (PRRT_kwDOTzqfcs6jv8em). Listeners stay attached after settlement and are
 * inert, so a late `error` from `destroy()` is always handled.
 *
 * ## Continuation is evidence, never a target
 *
 * A `rel=next` link is validated and must prove page n+1 of the same listing of
 * the same repository; the client then requests page n+1 from its own template.
 * A malformed or unusable continuation is INDETERMINATE, never a clean end of
 * pagination (PRRT_kwDOTzqfcs6jv8ev).
 */

import { Agent, request } from 'node:https';

import { readCanonicalBranchRef, readOwnProperty } from '../domain/repair-job.js';

const objectFreeze = Object.freeze;
const isSafeInteger = Number.isSafeInteger;
const isArray = Array.isArray;

/** The Decision 065 bounds. None is a parameter. */
export const GITHUB_LIMITS = objectFreeze({
  /** Requests one client instance (one run) may attempt, across every family. */
  MAX_REQUESTS_PER_RUN: 20,
  /** Absolute wall-clock budget of one HTTP request attempt. */
  REQUEST_DEADLINE_MS: 15_000,
  /** Accepted body bytes of one response. */
  MAX_RESPONSE_BYTES: 2_097_152,
  /** Page size of every listing. */
  PER_PAGE: 100,
  /** Pages one listing may follow. */
  MAX_PAGES: 5,
} as const);

/** Why an observation is indeterminate. A closed vocabulary; no member is a negative fact. */
export type GitHubIndeterminateCause =
  | 'INVALID_INPUT'
  | 'BUDGET_EXHAUSTED'
  | 'DEADLINE'
  | 'TRANSPORT_ERROR'
  | 'ABORTED'
  | 'INCOMPLETE'
  | 'TOO_LARGE'
  | 'ENCODING'
  | 'STATUS'
  | 'MALFORMED_BODY'
  | 'MALFORMED_CONTINUATION'
  | 'PAGE_LIMIT';

/** One observation. `httpStatus` is non-null only for cause `STATUS`. */
export type GitHubObservation<T> =
  | { readonly kind: 'DETERMINATE'; readonly value: T }
  | {
      readonly kind: 'INDETERMINATE';
      readonly cause: GitHubIndeterminateCause;
      readonly httpStatus: number | null;
    };

export interface GitHubRepositoryFacts {
  readonly defaultBranch: string;
}

export type GitHubBranchFacts =
  | { readonly present: true; readonly sha: string; readonly protected: boolean }
  | { readonly present: false };

export interface GitHubPullRequestFacts {
  readonly number: number;
  readonly headRef: string;
  readonly headRepoFullName: string | null;
  readonly baseRef: string;
}

export interface GitHubIssueFacts {
  readonly number: number;
  readonly title: string;
  readonly body: string | null;
  readonly isPullRequest: boolean;
}

/** Exactly one method per endpoint family. Promises never reject. */
export interface RetirementGitHubClient {
  /** REPOSITORY. */
  readRepository(): Promise<GitHubObservation<GitHubRepositoryFacts>>;
  /** BRANCH, for a full `refs/heads/...` ref. */
  readBranch(candidateRef: string): Promise<GitHubObservation<GitHubBranchFacts>>;
  /** OPEN_PULLS, all pages or nothing. */
  listOpenPullRequests(): Promise<GitHubObservation<readonly GitHubPullRequestFacts[]>>;
  /** OPEN_ISSUES, all pages or nothing; pull-request-backed records included as observed. */
  listOpenIssues(): Promise<GitHubObservation<readonly GitHubIssueFacts[]>>;
}

/* ------------------------------------------------------------------------- *
 * Fixed transport
 * ------------------------------------------------------------------------- */

const GITHUB_HOST = 'api.github.com';
const GITHUB_ORIGIN_PREFIX = 'https://api.github.com/';
const BRANCH_REF_PREFIX = 'refs/heads/';

/** The complete request header set. `Host` is supplied by Node from the constant hostname. */
const REQUEST_HEADERS = objectFreeze({
  Accept: 'application/vnd.github+json',
  'User-Agent': 'agentbridge-job1',
  'X-GitHub-Api-Version': '2022-11-28',
  'Accept-Encoding': 'identity',
  Connection: 'close',
});

/** Module-private agent: no keep-alive, no proxy configuration. */
const AGENT = new Agent({ keepAlive: false });

const MAX_REF_LENGTH = 1_024;
const MAX_FULL_NAME_LENGTH = 256;
const MAX_TITLE_LENGTH = 1_024;
const MAX_BODY_LENGTH = 65_536;
const MAX_LISTING_RECORDS = GITHUB_LIMITS.PER_PAGE * GITHUB_LIMITS.MAX_PAGES;

const OWNER_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const REPO_PATTERN = /^[A-Za-z0-9._-]{1,100}$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const CONTENT_LENGTH_PATTERN = /^[0-9]+$/;
const REPOSITORY_ID_PATTERN = /^[1-9][0-9]{0,15}$/;
const PAGE_PATTERN = /^[1-9][0-9]{0,2}$/;
const FORBIDDEN_URL_CHARACTER = /[#%\\\s]/;
const TOKEN_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/* ------------------------------------------------------------------------- *
 * Observations
 * ------------------------------------------------------------------------- */

function determinate<T>(value: T): GitHubObservation<T> {
  return objectFreeze({ kind: 'DETERMINATE', value });
}

/** An indeterminate observation; assignable to every `GitHubObservation<T>`. */
function indeterminate(
  cause: GitHubIndeterminateCause,
  httpStatus: number | null = null,
): GitHubObservation<never> {
  return objectFreeze({ kind: 'INDETERMINATE', cause, httpStatus });
}

/** Does `value` contain a C0 control character or DEL? */
function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) {
      return true;
    }
  }
  return false;
}

/** Lower-case ASCII letters only, so no non-ASCII code point can fold into a match. */
function asciiLower(value: string): string {
  return value.replace(/[A-Z]/g, (letter) => String.fromCharCode(letter.charCodeAt(0) + 32));
}

/* ------------------------------------------------------------------------- *
 * One request attempt — the settle-once latch
 * ------------------------------------------------------------------------- */

type Attempt =
  | { readonly ok: true; readonly status: number; readonly text: string; readonly link: unknown }
  | { readonly ok: false; readonly cause: GitHubIndeterminateCause; readonly httpStatus: number | null };

function failed(cause: GitHubIndeterminateCause, httpStatus: number | null = null): Attempt {
  return { ok: false, cause, httpStatus };
}

/**
 * One GET of a path this module built. Resolves exactly once and never rejects.
 * `allowNotFound` admits a 404 (BRANCH only) without reading its body.
 */
function attempt(path: string, allowNotFound: boolean): Promise<Attempt> {
  return new Promise<Attempt>((resolve) => {
    let settled = false;
    let req: { destroy(): unknown } | null = null;
    let res: { destroy(): unknown } | null = null;

    const settle = (outcome: Attempt): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(deadline);
      // Destruction failure cannot un-settle; the outcome is already fixed.
      try {
        req?.destroy();
      } catch {
        /* inert */
      }
      try {
        res?.destroy();
      } catch {
        /* inert */
      }
      resolve(outcome);
    };

    // Started immediately before request(): DNS, connect, TLS, headers, and body
    // all spend this one budget. No inactivity timeout is relied on.
    const deadline = setTimeout(() => {
      settle(failed('DEADLINE'));
    }, GITHUB_LIMITS.REQUEST_DEADLINE_MS);

    try {
      const outgoing = request(
        {
          protocol: 'https:',
          hostname: GITHUB_HOST,
          port: 443,
          method: 'GET',
          path,
          headers: REQUEST_HEADERS,
          agent: AGENT,
          rejectUnauthorized: true,
          servername: GITHUB_HOST,
        },
        (response) => {
          res = response;
          response.on('error', () => {
            settle(failed('TRANSPORT_ERROR'));
          });
          response.on('aborted', () => {
            settle(failed('ABORTED'));
          });
          response.on('close', () => {
            settle(failed('INCOMPLETE'));
          });
          if (settled) {
            response.destroy();
            return;
          }

          const status = response.statusCode ?? 0;
          const link = response.headers.link;
          if (allowNotFound && status === 404) {
            settle({ ok: true, status, text: '', link });
            return;
          }
          if (status !== 200) {
            settle(failed('STATUS', status));
            return;
          }
          const encoding = response.headers['content-encoding'];
          if (encoding !== undefined && asciiLower(encoding.trim()) !== 'identity') {
            settle(failed('ENCODING'));
            return;
          }
          const declaredText = response.headers['content-length'];
          let declared: number | null = null;
          if (declaredText !== undefined) {
            if (!CONTENT_LENGTH_PATTERN.test(declaredText)) {
              settle(failed('MALFORMED_BODY'));
              return;
            }
            declared = Number(declaredText);
            if (declared > GITHUB_LIMITS.MAX_RESPONSE_BYTES) {
              settle(failed('TOO_LARGE'));
              return;
            }
          }

          const chunks: Buffer[] = [];
          let total = 0;
          response.on('data', (chunk: Buffer) => {
            if (settled) {
              return;
            }
            total += chunk.length;
            if (total > GITHUB_LIMITS.MAX_RESPONSE_BYTES) {
              // Settle now; the overflow chunk is not retained and no later
              // end/error/close is awaited.
              settle(failed('TOO_LARGE'));
              return;
            }
            chunks.push(chunk);
          });
          response.on('end', () => {
            if (settled) {
              return;
            }
            if (declared !== null && total !== declared) {
              settle(failed('INCOMPLETE'));
              return;
            }
            let text: string;
            try {
              text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, total));
            } catch {
              settle(failed('MALFORMED_BODY'));
              return;
            }
            settle({ ok: true, status, text, link });
          });
        },
      );
      req = outgoing;
      outgoing.on('error', () => {
        settle(failed('TRANSPORT_ERROR'));
      });
      outgoing.on('close', () => {
        if (res === null) {
          settle(failed('INCOMPLETE'));
        }
      });
      outgoing.end();
    } catch {
      settle(failed('TRANSPORT_ERROR'));
    }
  });
}

/* ------------------------------------------------------------------------- *
 * Link header (RFC 8288 subset) — returns the rel=next target, or a verdict
 * ------------------------------------------------------------------------- */

type Continuation =
  | { readonly kind: 'END' }
  | { readonly kind: 'NEXT'; readonly uri: string }
  | { readonly kind: 'MALFORMED' };

const END: Continuation = objectFreeze({ kind: 'END' });
const MALFORMED: Continuation = objectFreeze({ kind: 'MALFORMED' });

function isOws(character: string | undefined): boolean {
  return character === ' ' || character === '\t';
}

function isTokenCharacter(character: string | undefined): boolean {
  return character !== undefined && TOKEN_PATTERN.test(character);
}

/**
 * Parse a whole Link header value. A page is terminal ONLY when the header is
 * absent or well-formed with zero rel=next; every other shape is MALFORMED.
 */
function readContinuation(header: unknown): Continuation {
  if (header === undefined) {
    return END;
  }
  if (typeof header !== 'string') {
    return MALFORMED;
  }
  const nexts: string[] = [];
  let at = 0;
  const skipOws = (): void => {
    while (isOws(header[at])) {
      at += 1;
    }
  };
  const readToken = (): string | null => {
    const start = at;
    while (isTokenCharacter(header[at])) {
      at += 1;
    }
    return at > start ? header.slice(start, at) : null;
  };

  for (;;) {
    skipOws();
    if (header[at] !== '<') {
      return MALFORMED;
    }
    at += 1;
    const uriStart = at;
    while (at < header.length && !/[<>,\s]/.test(header[at] ?? '')) {
      at += 1;
    }
    if (at === uriStart || header[at] !== '>') {
      return MALFORMED;
    }
    const uri = header.slice(uriStart, at);
    at += 1;

    let params = 0;
    let rel: string | null = null;
    for (;;) {
      skipOws();
      if (header[at] !== ';') {
        break;
      }
      at += 1;
      skipOws();
      const name = readToken();
      if (name === null || header[at] !== '=') {
        return MALFORMED;
      }
      at += 1;
      let value: string | null;
      if (header[at] === '"') {
        at += 1;
        const valueStart = at;
        while (at < header.length && header[at] !== '"' && header[at] !== '\\') {
          at += 1;
        }
        if (header[at] !== '"') {
          return MALFORMED;
        }
        value = header.slice(valueStart, at);
        at += 1;
      } else {
        value = readToken();
        if (value === null) {
          return MALFORMED;
        }
      }
      params += 1;
      if (asciiLower(name) === 'rel') {
        if (rel !== null) {
          return MALFORMED;
        }
        rel = value;
      }
    }
    if (params === 0) {
      return MALFORMED;
    }
    if (rel !== null) {
      const relations = rel.split(' ');
      for (const relation of relations) {
        // Relations are separated by single spaces and each must itself be a
        // token; anything else (tab, comma, a URI, an empty item) is malformed,
        // never an ignorable non-next relation.
        if (!TOKEN_PATTERN.test(relation)) {
          return MALFORMED;
        }
        // Relation types compare case-insensitively (RFC 8288), so "Next" is never
        // mistaken for "no next".
        if (asciiLower(relation) === 'next') {
          nexts.push(uri);
        }
      }
    }

    skipOws();
    if (at === header.length) {
      break;
    }
    if (header[at] !== ',') {
      return MALFORMED;
    }
    at += 1;
  }

  if (nexts.length === 0) {
    return END;
  }
  const [only] = nexts;
  return nexts.length === 1 && only !== undefined ? objectFreeze({ kind: 'NEXT', uri: only }) : MALFORMED;
}

/* ------------------------------------------------------------------------- *
 * Hostile JSON readers
 * ------------------------------------------------------------------------- */

function parseJson(text: string): { readonly value: unknown } | null {
  try {
    return { value: JSON.parse(text) as unknown };
  } catch {
    return null;
  }
}

function asRecord(value: unknown): object | null {
  return typeof value === 'object' && value !== null && !isArray(value) ? value : null;
}

function readBoundedString(value: unknown, min: number, max: number): string | null {
  return typeof value === 'string' && value.length >= min && value.length <= max ? value : null;
}

function readPositiveInteger(value: unknown): number | null {
  return typeof value === 'number' && isSafeInteger(value) && value >= 1 ? value : null;
}

function readPullRequest(element: unknown): GitHubPullRequestFacts | null {
  const record = asRecord(element);
  if (record === null) {
    return null;
  }
  const number = readPositiveInteger(readOwnProperty(record, 'number'));
  const head = asRecord(readOwnProperty(record, 'head'));
  const base = asRecord(readOwnProperty(record, 'base'));
  if (number === null || head === null || base === null) {
    return null;
  }
  const headRef = readBoundedString(readOwnProperty(head, 'ref'), 1, MAX_REF_LENGTH);
  const baseRef = readBoundedString(readOwnProperty(base, 'ref'), 1, MAX_REF_LENGTH);
  const headRepo = readOwnProperty(head, 'repo');
  let headRepoFullName: string | null = null;
  if (headRepo !== null) {
    const repoRecord = asRecord(headRepo);
    headRepoFullName =
      repoRecord === null
        ? null
        : readBoundedString(readOwnProperty(repoRecord, 'full_name'), 1, MAX_FULL_NAME_LENGTH);
    if (headRepoFullName === null) {
      return null;
    }
  }
  if (headRef === null || baseRef === null) {
    return null;
  }
  return objectFreeze({ number, headRef, headRepoFullName, baseRef });
}

function readIssue(element: unknown): GitHubIssueFacts | null {
  const record = asRecord(element);
  if (record === null) {
    return null;
  }
  const number = readPositiveInteger(readOwnProperty(record, 'number'));
  const title = readBoundedString(readOwnProperty(record, 'title'), 0, MAX_TITLE_LENGTH);
  const rawBody = readOwnProperty(record, 'body');
  const body = rawBody === null ? null : readBoundedString(rawBody, 0, MAX_BODY_LENGTH);
  if (number === null || title === null || (rawBody !== null && body === null)) {
    return null;
  }
  const pullRequest = readOwnProperty(record, 'pull_request');
  const isPullRequest = pullRequest !== undefined && pullRequest !== null;
  return objectFreeze({ number, title, body, isPullRequest });
}

/* ------------------------------------------------------------------------- *
 * Client
 * ------------------------------------------------------------------------- */

type Listing = 'pulls' | 'issues';

/**
 * Build the client for one configured repository, or `null` when `owner` or
 * `repo` is not a valid GitHub name (no client, no request).
 */
export function createRetirementGitHubClient(config: {
  readonly owner: string;
  readonly repo: string;
}): RetirementGitHubClient | null {
  const configRecord = asRecord(config);
  if (configRecord === null) {
    return null;
  }
  const owner = readOwnProperty(configRecord, 'owner');
  const repo = readOwnProperty(configRecord, 'repo');
  if (
    typeof owner !== 'string' ||
    typeof repo !== 'string' ||
    !OWNER_PATTERN.test(owner) ||
    !REPO_PATTERN.test(repo) ||
    repo === '.' ||
    repo === '..'
  ) {
    return null;
  }

  const repositoryPath = `/repos/${owner}/${repo}`;
  const fullName = asciiLower(`${owner}/${repo}`);
  let requests = 0;
  let provenRepositoryId: number | null = null;

  /** Spend one request of the run budget, or refuse before any network activity. */
  const fetchPath = (path: string, allowNotFound: boolean): Promise<Attempt> => {
    if (requests >= GITHUB_LIMITS.MAX_REQUESTS_PER_RUN) {
      return Promise.resolve(failed('BUDGET_EXHAUSTED'));
    }
    requests += 1;
    return attempt(path, allowNotFound);
  };

  const listingPath = (listing: Listing, page: number): string =>
    listing === 'pulls'
      ? `${repositoryPath}/pulls?state=open&per_page=100&page=${String(page)}`
      : `${repositoryPath}/issues?state=open&per_page=100&page=${String(page)}`;

  /**
   * Is `uri` evidence of exactly page `expectedPage` of `listing` for this
   * repository? The URI is never requested.
   */
  const provesNextPage = (uri: string, listing: Listing, expectedPage: number): boolean => {
    if (!uri.startsWith(GITHUB_ORIGIN_PREFIX) || FORBIDDEN_URL_CHARACTER.test(uri) || hasControlCharacter(uri)) {
      return false;
    }
    let url: URL;
    try {
      url = new URL(uri);
    } catch {
      return false;
    }
    // The raw path must be exactly what the parser kept: a dot segment the parser
    // would normalize away is refused, not resolved.
    const rawPath = uri.slice(GITHUB_ORIGIN_PREFIX.length - 1).split('?', 1)[0];
    if (
      url.protocol !== 'https:' ||
      url.hostname !== GITHUB_HOST ||
      url.port !== '' ||
      url.username !== '' ||
      url.password !== '' ||
      url.hash !== '' ||
      rawPath !== url.pathname
    ) {
      return false;
    }

    const segments = url.pathname.split('/');
    if (segments.length === 5 && segments[0] === '' && segments[1] === 'repos') {
      if (asciiLower(`${segments[2] ?? ''}/${segments[3] ?? ''}`) !== fullName || segments[4] !== listing) {
        return false;
      }
    } else if (segments.length === 4 && segments[0] === '' && segments[1] === 'repositories') {
      const id = segments[2] ?? '';
      if (
        !REPOSITORY_ID_PATTERN.test(id) ||
        provenRepositoryId === null ||
        Number(id) !== provenRepositoryId ||
        segments[3] !== listing
      ) {
        return false;
      }
    } else {
      return false;
    }

    const seen = new Set<string>();
    for (const [key, value] of new URLSearchParams(url.search)) {
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      if (key === 'state') {
        if (value !== 'open') {
          return false;
        }
      } else if (key === 'per_page') {
        if (value !== String(GITHUB_LIMITS.PER_PAGE)) {
          return false;
        }
      } else if (key === 'page') {
        if (!PAGE_PATTERN.test(value) || Number(value) !== expectedPage) {
          return false;
        }
      } else {
        return false;
      }
    }
    return seen.has('state') && seen.has('per_page') && seen.has('page');
  };

  /** Follow one listing to completion: all pages or nothing. */
  const list = async <T extends { readonly number: number }>(
    listing: Listing,
    readElement: (element: unknown) => T | null,
  ): Promise<GitHubObservation<readonly T[]>> => {
    const records: T[] = [];
    const numbers = new Set<number>();
    for (let page = 1; ; page += 1) {
      const response = await fetchPath(listingPath(listing, page), false);
      if (!response.ok) {
        return indeterminate(response.cause, response.httpStatus);
      }
      const parsed = parseJson(response.text);
      if (parsed === null || !isArray(parsed.value) || parsed.value.length > GITHUB_LIMITS.PER_PAGE) {
        return indeterminate('MALFORMED_BODY');
      }
      for (const element of parsed.value as readonly unknown[]) {
        const record = readElement(element);
        if (record === null || numbers.has(record.number)) {
          return indeterminate('MALFORMED_BODY');
        }
        numbers.add(record.number);
        records.push(record);
      }
      if (records.length > MAX_LISTING_RECORDS) {
        return indeterminate('MALFORMED_BODY');
      }

      const continuation = readContinuation(response.link);
      if (continuation.kind === 'END') {
        return determinate(objectFreeze(records));
      }
      if (continuation.kind === 'MALFORMED' || !provesNextPage(continuation.uri, listing, page + 1)) {
        return indeterminate('MALFORMED_CONTINUATION');
      }
      if (page >= GITHUB_LIMITS.MAX_PAGES) {
        return indeterminate('PAGE_LIMIT');
      }
    }
  };

  const readRepository = async (): Promise<GitHubObservation<GitHubRepositoryFacts>> => {
    const response = await fetchPath(repositoryPath, false);
    if (!response.ok) {
      return indeterminate(response.cause, response.httpStatus);
    }
    if (readContinuation(response.link).kind !== 'END') {
      return indeterminate('MALFORMED_CONTINUATION');
    }
    const parsed = parseJson(response.text);
    const record = parsed === null ? null : asRecord(parsed.value);
    if (record === null) {
      return indeterminate('MALFORMED_BODY');
    }
    const id = readPositiveInteger(readOwnProperty(record, 'id'));
    const observedFullName = readOwnProperty(record, 'full_name');
    const defaultBranch = readOwnProperty(record, 'default_branch');
    if (
      id === null ||
      typeof observedFullName !== 'string' ||
      asciiLower(observedFullName) !== fullName ||
      typeof defaultBranch !== 'string' ||
      readCanonicalBranchRef(BRANCH_REF_PREFIX + defaultBranch) === null
    ) {
      return indeterminate('MALFORMED_BODY');
    }
    if (provenRepositoryId !== null && provenRepositoryId !== id) {
      // A different id than the one proven: this observation proves nothing and
      // the proven id is cleared. A later valid observation may prove one again.
      provenRepositoryId = null;
      return indeterminate('MALFORMED_BODY');
    }
    provenRepositoryId = id;
    return determinate(objectFreeze({ defaultBranch }));
  };

  const readBranch = async (candidateRef: string): Promise<GitHubObservation<GitHubBranchFacts>> => {
    const ref = readCanonicalBranchRef(candidateRef);
    if (ref === null) {
      return indeterminate('INVALID_INPUT');
    }
    const name = ref.slice(BRANCH_REF_PREFIX.length);
    const response = await fetchPath(`${repositoryPath}/branches/${name}`, true);
    if (!response.ok) {
      return indeterminate(response.cause, response.httpStatus);
    }
    if (readContinuation(response.link).kind !== 'END') {
      return indeterminate('MALFORMED_CONTINUATION');
    }
    if (response.status === 404) {
      return determinate(objectFreeze({ present: false as const }));
    }
    const parsed = parseJson(response.text);
    const record = parsed === null ? null : asRecord(parsed.value);
    const commit = record === null ? null : asRecord(readOwnProperty(record, 'commit'));
    if (record === null || commit === null) {
      return indeterminate('MALFORMED_BODY');
    }
    const sha = readOwnProperty(commit, 'sha');
    const isProtected = readOwnProperty(record, 'protected');
    if (
      readOwnProperty(record, 'name') !== name ||
      typeof sha !== 'string' ||
      !SHA_PATTERN.test(sha) ||
      typeof isProtected !== 'boolean'
    ) {
      return indeterminate('MALFORMED_BODY');
    }
    return determinate(objectFreeze({ present: true as const, sha, protected: isProtected }));
  };

  /** Promises never reject: any unexpected throw is an indeterminate observation. */
  const guard = <T>(observation: Promise<GitHubObservation<T>>): Promise<GitHubObservation<T>> =>
    observation.catch(() => indeterminate('TRANSPORT_ERROR'));

  return objectFreeze({
    readRepository: () => guard(readRepository()),
    readBranch: (candidateRef: string) => guard(readBranch(candidateRef)),
    listOpenPullRequests: () => guard(list('pulls', readPullRequest)),
    listOpenIssues: () => guard(list('issues', readIssue)),
  });
}
