/**
 * Executable entry for the `agentbridge-control` CLI (`npm run control` →
 * `node dist/control/cli-main.js`). This file is an entry point ONLY: it is never
 * imported as a library, so it runs unconditionally with no entry-identity
 * predicate — no `import.meta.url` / `argv[1]` / realpath comparison that a
 * junction, symlink, alias retarget, or path rename could turn into a silent
 * exit 0. The reusable flow lives in `./cli.js` (the same entry-script-over-
 * library shape as the provisioning gate under `tools/control-owner`).
 */

import { cliMain } from './cli.js';

void cliMain();
