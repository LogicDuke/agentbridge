/*
 * Type declaration for the launch-time provisioning gate's pure, path-injected
 * pair-validation helper, so the strict-TypeScript lifecycle regression can import
 * and exercise the REAL function (not a copy). The gate itself (ensure-helper.mjs)
 * lives under tools/ and is plain Node ESM; only this validation seam is public.
 */

/** Result of a lifecycle pair-validity check: skip when valid, else rebuild. */
export interface HelperPairValidity {
  readonly valid: boolean;
  readonly reason: string;
}

/** Paths + expected helper filename for a single pair-validity decision. */
export interface HelperPairInput {
  readonly exePath: string;
  readonly provenancePath: string;
  readonly expectedFilename: string;
}

/**
 * Decide whether the helper/provenance pair on disk is valid for lifecycle
 * purposes (mirrors the runtime's acceptance criteria; never executes provenance).
 */
export declare function validateHelperPair(input: HelperPairInput): HelperPairValidity;
