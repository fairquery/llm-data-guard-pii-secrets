/**
 * Local placeholder restore for restore_placeholders. Same placeholder pattern and replacement rule as
 * the Actor's mode="restore" (src/redact.ts restore()), so both return the same output_text.
 */
export const PLACEHOLDER_RE = /\[[A-Z_]+_\d+\]/g;

export function restoreText(text: string, map: Record<string, string>): { output_text: string; replacements: number; unknown_placeholders: string[] } {
    let n = 0;
    const unknown = new Set<string>();
    const output = text.replace(PLACEHOLDER_RE, (ph) => {
        if (Object.prototype.hasOwnProperty.call(map, ph)) {
            n += 1;
            return map[ph];
        }
        unknown.add(ph);
        return ph;
    });
    return { output_text: output, replacements: n, unknown_placeholders: [...unknown] };
}
