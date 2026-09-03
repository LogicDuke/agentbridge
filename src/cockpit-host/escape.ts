/**
 * HTML-entity escaping for the Cockpit D3 dashboard host.
 *
 * Every dynamic value the host interpolates into server-rendered HTML — all of
 * it originating from a D1-validated {@link CockpitSnapshot} — is passed through
 * {@link escapeHtml} first. The host emits no `innerHTML`, no `document.write`,
 * no inline event handlers, and no client-side script at all, so escaping here
 * is the single place untrusted prose becomes markup-safe text.
 *
 * This module is pure string transformation: no I/O, no network, no process
 * access, no imports.
 */

/** The five characters that can break out of HTML text or a double-quoted attribute. */
const HTML_ESCAPES: Readonly<Record<string, string>> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

/**
 * Escape `&`, `<`, `>`, `"`, and `'` so the returned string renders as inert
 * text in both HTML body and double-quoted attribute contexts. A value that
 * contains none of them is returned unchanged.
 */
export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => HTML_ESCAPES[character] ?? character);
}
