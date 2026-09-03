import { readFileSync } from 'node:fs';

/**
 * The pinned executable import closure of the Cockpit host, as `src/`-relative,
 * '/'-separated tree names: every host source, the Cockpit boundary the host
 * imports, and the domain kernel the boundary imports. The purity suite proves
 * the real closure (walked from `src/cockpit-host/**` through every runtime
 * relative import) equals this list, so a new executable dependency must be
 * enrolled here explicitly; the network-policy suite proves the detector
 * accepts exactly these files as one tree.
 */
export const EXPECTED_HOST_CLOSURE: readonly string[] = [
  'cockpit-host/escape.ts',
  'cockpit-host/fixtures/stage-a.ts',
  'cockpit-host/render.ts',
  'cockpit-host/server.ts',
  'cockpit-host/styles.ts',
  'cockpit/evidence-freshness-projection.ts',
  'cockpit/index.ts',
  'cockpit/read-model.ts',
  'domain/evidence-freshness.ts',
  'domain/evidence.ts',
  'domain/repair-job.ts',
  'domain/review.ts',
];

const SRC_ROOT_URL = new URL('../../../src/', import.meta.url);

/** The pinned closure's sources, read from `src/`, in the tree entry's form (`file` relative to `src/`). */
export function readHostClosure(): readonly { readonly file: string; readonly text: string }[] {
  return EXPECTED_HOST_CLOSURE.map((file) => ({ file, text: readFileSync(new URL(file, SRC_ROOT_URL), 'utf8') }));
}
