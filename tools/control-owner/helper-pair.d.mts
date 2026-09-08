/*
 * Type declaration for the canonical pair validator seam, so the strict-TypeScript
 * lifecycle regression can import and exercise the REAL canonical encoder and
 * validator (not copies). The module (helper-pair.mjs) lives under tools/ and is
 * plain Node ESM with no entry-point behavior; the gate script (ensure-helper.mjs)
 * consumes it and has no exports of its own.
 */

/** Result of a lifecycle pair-validity check: skip when valid, else rebuild. */
export interface HelperPairValidity {
  readonly valid: boolean;
  readonly reason: string;
}

/** Paths for a single canonical pair-validity decision. */
export interface HelperPairInput {
  readonly exePath: string;
  readonly provenancePath: string;
}

/**
 * Decide whether the helper/provenance pair on disk is the canonical pair —
 * on-disk provenance bytes equal `encodeProvenance(sha256(helper bytes))`, exactly.
 * Never imports/parses provenance; the runtime remains the security authority.
 */
export declare function validateHelperPair(input: HelperPairInput): HelperPairValidity;

/** The one native helper's filename (re-exported from provenance-format.mjs). */
export declare const OWNER_HELPER_BASENAME: string;

/** The generated provenance module's basename (re-exported from provenance-format.mjs). */
export declare const PROVENANCE_BASENAME: string;

/**
 * The single canonical provenance encoder (re-exported from provenance-format.mjs):
 * helper SHA-256 (lowercase 64-hex) → exact provenance module text. Pure; throws a
 * TypeError on a non-64-hex digest.
 */
export declare function encodeProvenance(sha256Hex: string): string;
