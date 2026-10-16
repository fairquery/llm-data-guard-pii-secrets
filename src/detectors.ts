import { isIP } from 'node:net';

import { findPhoneNumbersInText, type CountryCode } from 'libphonenumber-js/max';

export type Category = 'pii' | 'secret';

export interface Finding {
    type: string;
    category: Category;
    rule: string;
    start: number;
    end: number;
    value: string;
    confidence: 'high' | 'medium' | 'low';
}

export interface DetectOptions {
    detectPii: boolean;
    detectSecrets: boolean;
    detectNames: boolean;
    detectAddresses: boolean;
    entropyScan: boolean;
    minEntropy: number;
    defaultPhoneRegion: string;
    entityTypes: string[];
    allowList: string[];
}

interface Rule {
    type: string;
    category: Category;
    id: string;
    re: RegExp;
    group?: number;
    confidence?: Finding['confidence'];
    validate?: (v: string, full: string) => boolean;
}

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
    if (!s) return 0;
    const freq = new Map<string, number>();
    for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
    let h = 0;
    for (const n of freq.values()) {
        const p = n / s.length;
        h -= p * Math.log2(p);
    }
    return h;
}

export function luhn(digits: string): boolean {
    let sum = 0;
    let dbl = false;
    for (let i = digits.length - 1; i >= 0; i--) {
        let d = digits.charCodeAt(i) - 48;
        if (d < 0 || d > 9) return false;
        if (dbl) {
            d *= 2;
            if (d > 9) d -= 9;
        }
        sum += d;
        dbl = !dbl;
    }
    return sum % 10 === 0;
}

export function isCardNumber(raw: string): boolean {
    const d = raw.replace(/[ -]/g, '');
    if (d.length < 13 || d.length > 19 || /^(\d)\1+$/.test(d)) return false;
    if (!/^(4|5[1-5]|2[2-7]|3[47]|3[0689]|6(?:011|5|4[4-9]|22)|35|62|81)/.test(d)) return false;
    return luhn(d);
}

const IBAN_LEN: Record<string, number> = {
    AD: 24,
    AE: 23,
    AL: 28,
    AT: 20,
    AZ: 28,
    BA: 20,
    BE: 16,
    BG: 22,
    BH: 22,
    BR: 29,
    CH: 21,
    CR: 22,
    CY: 28,
    CZ: 24,
    DE: 22,
    DK: 18,
    DO: 28,
    EE: 20,
    EG: 29,
    ES: 24,
    FI: 18,
    FO: 18,
    FR: 27,
    GB: 22,
    GE: 22,
    GI: 23,
    GL: 18,
    GR: 27,
    GT: 28,
    HR: 21,
    HU: 28,
    IE: 22,
    IL: 23,
    IS: 26,
    IT: 27,
    JO: 30,
    KW: 30,
    KZ: 20,
    LB: 28,
    LI: 21,
    LT: 20,
    LU: 20,
    LV: 21,
    MC: 27,
    MD: 24,
    ME: 22,
    MK: 19,
    MR: 27,
    MT: 31,
    MU: 30,
    NL: 18,
    NO: 15,
    PK: 24,
    PL: 28,
    PS: 29,
    PT: 25,
    QA: 29,
    RO: 24,
    RS: 22,
    SA: 24,
    SE: 24,
    SI: 19,
    SK: 24,
    SM: 27,
    TN: 24,
    TR: 26,
    UA: 29,
    VG: 24,
    XK: 20,
};

export function isIban(raw: string): boolean {
    const s = raw.replace(/ /g, '').toUpperCase();
    const len = IBAN_LEN[s.slice(0, 2)];
    if (!len || s.length !== len) return false;
    const r = s.slice(4) + s.slice(0, 4);
    let rem = 0;
    for (const ch of r) {
        const v = ch >= 'A' ? String(ch.charCodeAt(0) - 55) : ch;
        for (const c of v) rem = (rem * 10 + (c.charCodeAt(0) - 48)) % 97;
    }
    return rem === 1;
}

const PLACEHOLDER_WORDS =
    /^(?:x+|\*+|changeme|password|secret|example|your[_-]?\w*|<[^>]*>|\$\{[^}]*\}|null|none|true|false|undefined|redacted)$/i;

const SECRET_RULES: Rule[] = [
    {
        type: 'PRIVATE_KEY',
        category: 'secret',
        id: 'private-key',
        re: /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]{20,}?-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----/g,
    },
    {
        type: 'AWS_ACCESS_KEY',
        category: 'secret',
        id: 'aws-access-key-id',
        re: /\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b/g,
    },
    {
        type: 'AWS_SECRET_KEY',
        category: 'secret',
        id: 'aws-secret-access-key',
        re: /aws_?secret_?(?:access_?)?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b/gi,
        group: 1,
    },
    {
        type: 'GITHUB_TOKEN',
        category: 'secret',
        id: 'github-token',
        re: /\b(?:gh[pousr]_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b/g,
    },
    { type: 'GITLAB_TOKEN', category: 'secret', id: 'gitlab-pat', re: /\bglpat-[0-9a-zA-Z_-]{20}\b/g },
    { type: 'SLACK_TOKEN', category: 'secret', id: 'slack-token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,250}\b/g },
    {
        type: 'SLACK_WEBHOOK',
        category: 'secret',
        id: 'slack-webhook',
        re: /https:\/\/hooks\.slack\.com\/(?:services|workflows)\/[A-Za-z0-9+/]{20,}/g,
    },
    {
        type: 'STRIPE_KEY',
        category: 'secret',
        id: 'stripe-key',
        re: /\b(?:sk|rk)_(?:test|live|prod)_[0-9a-zA-Z]{10,99}\b/g,
    },
    { type: 'GOOGLE_API_KEY', category: 'secret', id: 'gcp-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
    {
        type: 'ANTHROPIC_KEY',
        category: 'secret',
        id: 'anthropic-api-key',
        re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b/g,
    },
    {
        type: 'OPENAI_KEY',
        category: 'secret',
        id: 'openai-api-key',
        re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b/g,
        validate: (v) => !v.startsWith('sk-ant-') && entropy(v) > 3.5,
    },
    { type: 'HUGGINGFACE_TOKEN', category: 'secret', id: 'huggingface-token', re: /\bhf_[A-Za-z]{34}\b/g },
    { type: 'NPM_TOKEN', category: 'secret', id: 'npm-access-token', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
    {
        type: 'SENDGRID_KEY',
        category: 'secret',
        id: 'sendgrid-api-key',
        re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    },
    { type: 'TWILIO_KEY', category: 'secret', id: 'twilio-api-key', re: /\bSK[0-9a-fA-F]{32}\b/g },
    {
        type: 'AZURE_STORAGE_KEY',
        category: 'secret',
        id: 'azure-storage-key',
        re: /AccountKey=([A-Za-z0-9+/=]{86,88})/g,
        group: 1,
    },
    {
        type: 'JWT',
        category: 'secret',
        id: 'jwt',
        re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    },
    {
        type: 'URL_CREDENTIALS',
        category: 'secret',
        id: 'url-basic-auth',
        re: /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:@/]{1,64}:([^\s:@/]{3,128})@/gi,
        group: 1,
        validate: (v) => !PLACEHOLDER_WORDS.test(v),
    },
    {
        type: 'GENERIC_SECRET',
        category: 'secret',
        id: 'generic-assignment',
        confidence: 'medium',
        re: /(?:api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|bearer|token|passw(?:or)?d|pwd|client[_-]?secret|private[_-]?key)["']?\s*(?:[:=]|=>|\s)\s*["']?([A-Za-z0-9_\-+/=.~!@#$%^&*]{8,200})/gi,
        group: 1,
    },
];

const PII_RULES: Rule[] = [
    {
        type: 'EMAIL',
        category: 'pii',
        id: 'email',
        re: /\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}\b/g,
    },
    { type: 'SSN', category: 'pii', id: 'us-ssn', re: /\b(?!000|666|9\d\d)\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b/g },
    { type: 'CREDIT_CARD', category: 'pii', id: 'card-luhn', re: /\b(?:\d[ -]?){12,18}\d\b/g, validate: isCardNumber },
    {
        type: 'IBAN',
        category: 'pii',
        id: 'iban-mod97',
        re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b/g,
        validate: isIban,
    },
    {
        type: 'UK_NINO',
        category: 'pii',
        id: 'uk-nino',
        re: /\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b/g,
    },
    {
        type: 'IP_ADDRESS',
        category: 'pii',
        id: 'ipv4',
        re: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
        validate: (v) => isIP(v) === 4 && v !== '0.0.0.0',
    },
    {
        type: 'IP_ADDRESS',
        category: 'pii',
        id: 'ipv6',
        re: /(?<![:\w])(?:[A-Fa-f0-9]{1,4}:){2,7}(?::|[A-Fa-f0-9]{1,4})(?![:\w])/g,
        validate: (v) => isIP(v) === 6 && v.length > 6,
    },
];

const ADDRESS_RULE: Rule = {
    type: 'STREET_ADDRESS',
    category: 'pii',
    id: 'street-address',
    confidence: 'medium',
    re: /\b\d{1,6}[A-Za-z]?\s+(?:[A-Z][A-Za-z0-9.'-]*\s+){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Parkway|Pkwy|Square|Sq|Highway|Hwy)\b\.?(?:,?\s+(?:Apt|Suite|Ste|Unit)\.?\s*#?\w+)?/g,
};

/** Detector catalog (used by the MCP helper and README). */
export const DETECTORS = [
    ...SECRET_RULES.map((r) => ({ type: r.type, category: r.category, rule: r.id })),
    ...PII_RULES.map((r) => ({ type: r.type, category: r.category, rule: r.id })),
    { type: 'PHONE', category: 'pii', rule: 'libphonenumber' },
    { type: 'STREET_ADDRESS', category: 'pii', rule: 'street-address (detectAddresses)' },
    { type: 'PERSON', category: 'pii', rule: 'ner-compromise (detectNames)' },
    { type: 'LOCATION', category: 'pii', rule: 'ner-compromise (detectAddresses)' },
    { type: 'HIGH_ENTROPY_STRING', category: 'secret', rule: 'entropy (entropyScan)' },
];

// Higher wins when spans overlap.
const PRIORITY: Record<string, number> = {
    secret: 100,
    CREDIT_CARD: 90,
    IBAN: 90,
    SSN: 85,
    UK_NINO: 80,
    EMAIL: 75,
    IP_ADDRESS: 60,
    PHONE: 50,
    STREET_ADDRESS: 40,
    PERSON: 30,
    LOCATION: 20,
};
const prio = (f: Finding) =>
    f.category === 'secret' ? PRIORITY.secret + (f.confidence === 'high' ? 5 : 0) : (PRIORITY[f.type] ?? 10);

function runRule(text: string, r: Rule, out: Finding[], opt: DetectOptions): void {
    r.re.lastIndex = 0;
    for (const m of text.matchAll(r.re)) {
        const value = r.group ? m[r.group] : m[0];
        if (!value) continue;
        const start = (m.index ?? 0) + (r.group ? m[0].indexOf(value) : 0);
        if (r.validate && !r.validate(value, m[0])) continue;
        if (r.id === 'generic-assignment') {
            const v = value.replace(/["',;]+$/, '');
            if (PLACEHOLDER_WORDS.test(v) || v.length < 8) continue;
            const isPw = /passw|pwd/i.test(m[0]);
            if (!isPw && entropy(v) < opt.minEntropy) continue;
            out.push({
                type: r.type,
                category: r.category,
                rule: r.id,
                start,
                end: start + v.length,
                value: v,
                confidence: 'medium',
            });
            continue;
        }
        out.push({
            type: r.type,
            category: r.category,
            rule: r.id,
            start,
            end: start + value.length,
            value,
            confidence: r.confidence ?? 'high',
        });
    }
}

type NlpFn = (t: string) => {
    people(): { out(f: 'offset'): { text: string; offset: { start: number; length: number } }[] };
    places(): { out(f: 'offset'): { text: string; offset: { start: number; length: number } }[] };
};
let nlp: NlpFn | null = null;
async function getNlp(): Promise<NlpFn> {
    if (!nlp) nlp = ((await import('compromise')) as unknown as { default: NlpFn }).default;
    return nlp;
}

export async function detect(text: string, opt: DetectOptions): Promise<Finding[]> {
    const raw: Finding[] = [];
    if (opt.detectSecrets) {
        for (const r of SECRET_RULES) runRule(text, r, raw, opt);
        if (opt.entropyScan) {
            for (const m of text.matchAll(/(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_=-]{20,200}(?![A-Za-z0-9+/_=-])/g)) {
                const v = m[0];
                const hex = /^[0-9a-f]+$/i.test(v);
                if (!/\d/.test(v) || !/[A-Za-z]/.test(v)) continue;
                if (entropy(v) < (hex ? opt.minEntropy - 0.5 : opt.minEntropy + 0.5)) continue;
                raw.push({
                    type: 'HIGH_ENTROPY_STRING',
                    category: 'secret',
                    rule: 'entropy',
                    start: m.index ?? 0,
                    end: (m.index ?? 0) + v.length,
                    value: v,
                    confidence: 'low',
                });
            }
        }
    }
    if (opt.detectPii) {
        for (const r of PII_RULES) runRule(text, r, raw, opt);
        try {
            for (const p of findPhoneNumbersInText(text, {
                defaultCountry: (opt.defaultPhoneRegion || 'US') as CountryCode,
            })) {
                if (!p.number.isValid()) continue;
                const value = text.slice(p.startsAt, p.endsAt);
                if (value.replace(/\D/g, '').length < 7) continue;
                raw.push({
                    type: 'PHONE',
                    category: 'pii',
                    rule: 'libphonenumber',
                    start: p.startsAt,
                    end: p.endsAt,
                    value,
                    confidence: value.trim().startsWith('+') ? 'high' : 'medium',
                });
            }
        } catch {
            /* invalid region etc. */
        }
        if (opt.detectAddresses) runRule(text, ADDRESS_RULE, raw, opt);
        if (opt.detectNames || opt.detectAddresses) {
            const n = await getNlp();
            const doc = n(text);
            const push = (type: string, arr: { text: string; offset: { start: number; length: number } }[]) => {
                for (const e of arr) {
                    const t = e.text.replace(/[\s,.;:!?'"]+$/, '');
                    if (t.length < 3 || !/[A-Z]/.test(t)) continue;
                    raw.push({
                        type,
                        category: 'pii',
                        rule: 'ner-compromise',
                        start: e.offset.start,
                        end: e.offset.start + t.length,
                        value: t,
                        confidence: 'low',
                    });
                }
            };
            if (opt.detectNames) push('PERSON', doc.people().out('offset'));
            if (opt.detectAddresses) push('LOCATION', doc.places().out('offset'));
        }
    }
    const allow = new Set(opt.allowList.map((a) => a.toLowerCase()));
    const types = new Set(opt.entityTypes.map((t) => t.toUpperCase()));
    const filtered = raw.filter((f) => !allow.has(f.value.toLowerCase()) && (!types.size || types.has(f.type)));
    return resolveOverlaps(filtered);
}

/** Keep the highest-priority (then longest) finding among overlapping spans. */
export function resolveOverlaps(findings: Finding[]): Finding[] {
    const sorted = [...findings].sort(
        (a, b) => prio(b) - prio(a) || b.end - b.start - (a.end - a.start) || a.start - b.start,
    );
    const kept: Finding[] = [];
    for (const f of sorted) if (!kept.some((k) => f.start < k.end && k.start < f.end)) kept.push(f);
    return kept.sort((a, b) => a.start - b.start);
}
