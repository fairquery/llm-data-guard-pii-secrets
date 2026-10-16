import { createHash } from 'node:crypto';

import type { Finding } from './detectors.js';

export type Style = 'placeholder' | 'mask' | 'hash';

export function maskValue(f: Pick<Finding, 'type' | 'category' | 'value'>): string {
    const v = f.value;
    if (f.category === 'secret') {
        const keep = v.startsWith('-----BEGIN') ? 0 : Math.min(4, Math.floor(v.length / 4));
        return v.slice(0, keep) + '*'.repeat(Math.max(4, Math.min(v.length - keep, 24)));
    }
    if (f.type === 'EMAIL') {
        const [local, domain = ''] = v.split('@');
        const dot = domain.lastIndexOf('.');
        return `${local[0] ?? ''}***@${domain[0] ?? ''}***${dot > 0 ? domain.slice(dot) : ''}`;
    }
    if (['CREDIT_CARD', 'IBAN', 'PHONE', 'SSN', 'UK_NINO'].includes(f.type)) {
        let seen = 0;
        const total = (v.match(/[A-Za-z0-9]/g) ?? []).length;
        return v.replace(/[A-Za-z0-9]/g, (c) => (++seen > total - 4 ? c : '*'));
    }
    return v.replace(/\S/g, '*');
}

export class Redactor {
    private counters = new Map<string, number>();
    private byValue = new Map<string, string>();
    readonly map: Record<string, string> = {};

    constructor(
        private readonly style: Style,
        private readonly salt: string,
        private readonly consistent: boolean,
    ) {}

    /** Per-document map when placeholders are not consistent across documents. */
    resetDocument(): void {
        if (this.consistent) return;
        this.counters.clear();
        this.byValue.clear();
        for (const k of Object.keys(this.map)) delete this.map[k];
    }

    replacement(f: Finding): string {
        if (this.style === 'mask') return maskValue(f);
        if (this.style === 'hash') {
            const h = createHash('sha256')
                .update(`${this.salt}\u0000${f.type}\u0000${f.value}`)
                .digest('hex')
                .slice(0, 12);
            return `[${f.type}:${h}]`;
        }
        const key = `${f.type}\u0000${f.value}`;
        const existing = this.byValue.get(key);
        if (existing) return existing;
        const n = (this.counters.get(f.type) ?? 0) + 1;
        this.counters.set(f.type, n);
        const ph = `[${f.type}_${n}]`;
        this.byValue.set(key, ph);
        this.map[ph] = f.value;
        return ph;
    }

    apply(text: string, findings: Finding[]): { text: string; replacements: string[] } {
        let out = '';
        let pos = 0;
        const replacements: string[] = [];
        for (const f of findings) {
            const r = this.replacement(f);
            replacements.push(r);
            out += text.slice(pos, f.start) + r;
            pos = f.end;
        }
        return { text: out + text.slice(pos), replacements };
    }
}

/** Restores placeholders produced with style "placeholder" (used after the LLM answers). */
export function restore(text: string, map: Record<string, string>): string {
    return text.replace(/\[[A-Z_]+_\d+\]/g, (ph) => map[ph] ?? ph);
}
