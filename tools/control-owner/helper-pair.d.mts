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
 * Decide whether the helper/provenance pair on disk is the canonical pair AND was
 * built from the CURRENT reviewed source — on-disk provenance bytes equal
 * `encodeProvenance(sha256(helper bytes), sourceId(current source))`, exactly.
 * Never imports/parses provenance; the runtime remains the security authority.
 */
export declare function validateHelperPair(input: HelperPairInput): HelperPairValidity;

/**
 * The same decision for the DESCRIPTOR CREATOR, against its OWN canonical encoder and
 * its OWN reviewed source. The two artifacts have separate provenance; a cross-wired
 * module is never valid.
 */
export declare function validateCreatorPair(input: HelperPairInput): HelperPairValidity;

/** The read-only owner helper's reviewed C source basename (re-exported). */
export declare const OWNER_HELPER_SOURCE_BASENAME: string;

/** The descriptor creator's reviewed C source basename (re-exported). */
export declare const DESCRIPTOR_CREATOR_SOURCE_BASENAME: string;

/** Absolute path to the reviewed owner-helper C source (module-relative). */
export declare const OWNER_HELPER_SOURCE_PATH: string;

/** Absolute path to the reviewed descriptor-creator C source (module-relative). */
export declare const DESCRIPTOR_CREATOR_SOURCE_PATH: string;

/**
 * The canonical build-source identity: SHA-256 (lowercase 64-hex) of the exact
 * reviewed C source bytes, or `null` when that source cannot be read. Whole-file
 * bytes — never a scan, an extracted version literal, or a regex.
 */
export declare function sourceIdFor(sourcePath: string): string | null;

/** The current owner-helper build-source identity, or `null` if unreadable. */
export declare function ownerHelperSourceId(): string | null;

/** The current descriptor-creator build-source identity, or `null` if unreadable. */
export declare function descriptorCreatorSourceId(): string | null;

/** The read-only owner helper's filename (re-exported from provenance-format.mjs). */
export declare const OWNER_HELPER_BASENAME: string;

/** The generated owner-helper provenance module's basename (re-exported). */
export declare const PROVENANCE_BASENAME: string;

/** The descriptor creator's filename (re-exported from provenance-format.mjs). */
export declare const DESCRIPTOR_CREATOR_BASENAME: string;

/** The generated creator provenance module's basename (re-exported). */
export declare const CREATOR_PROVENANCE_BASENAME: string;

/**
 * The single canonical provenance encoder (re-exported from provenance-format.mjs):
 * helper SHA-256 + reviewed-source SHA-256 (both lowercase 64-hex) → exact provenance
 * module text. Pure; throws a TypeError on a non-64-hex digest.
 */
export declare function encodeProvenance(sha256Hex: string, sourceId: string): string;

/**
 * The canonical provenance encoder for the descriptor creator (re-exported from
 * provenance-format.mjs): creator SHA-256 + its reviewed-source SHA-256 → exact
 * provenance module text, with its own binding name. Pure; throws a TypeError on a
 * non-64-hex digest.
 */
export declare function encodeCreatorProvenance(sha256Hex: string, sourceId: string): string;
