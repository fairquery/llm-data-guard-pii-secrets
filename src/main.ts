import { randomBytes } from 'node:crypto';

import { Actor, log } from 'apify';

import { detect, type DetectOptions, type Finding } from './detectors.js';
import { Emitter } from './emitter.js';
import { loadUrl } from './fetch.js';
import { maskValue, Redactor, restore, type Style } from './redact.js';

const SCHEMA_VERSION = '1.0.0';
const EVENTS = { document: 'document-processed', finding: 'finding' } as const;
const HIGH_RISK = new Set(['CREDIT_CARD', 'SSN', 'IBAN', 'UK_NINO', 'PRIVATE_KEY']);

interface Input {
    texts?: string[];
    documents?: { id?: string; text?: string }[];
    documentUrls?: string[];
    mode?: 'detect' | 'redact' | 'restore';
    redactionStyle?: Style;
    returnPlaceholderMap?: boolean;
    consistentPlaceholders?: boolean;
    placeholderMap?: Record<string, string>;
    hashSalt?: string;
    detectPii?: boolean;
    detectSecrets?: boolean;
    detectNames?: boolean;
    detectAddresses?: boolean;
    entropyScan?: boolean;
    minEntropy?: number;
    defaultPhoneRegion?: string;
    entityTypes?: string[];
    allowList?: string[];
    includeFindingValues?: boolean;
    maxDocuments?: number;
    maxCharsPerDocument?: number;
    purgeInputAfterRun?: boolean;
}

await Actor.init();
const startedAt = new Date().toISOString();
const emitter = new Emitter(25);
let aborting = false;
Actor.on('aborting', async () => {
    aborting = true;
    await emitter.flush();
});

const raw = ((await Actor.getInput<Input>()) ?? {}) as Input;
const mode = raw.mode ?? 'redact';
const style: Style = raw.redactionStyle ?? 'placeholder';
const opt: DetectOptions = {
    detectPii: raw.detectPii ?? true,
    detectSecrets: raw.detectSecrets ?? true,
    detectNames: raw.detectNames ?? false,
    detectAddresses: raw.detectAddresses ?? false,
    entropyScan: raw.entropyScan ?? false,
    minEntropy: raw.minEntropy ?? 3.5,
    defaultPhoneRegion: (raw.defaultPhoneRegion ?? 'US').toUpperCase(),
    entityTypes: raw.entityTypes ?? [],
    allowList: raw.allowList ?? [],
};
const maxDocs = raw.maxDocuments ?? 1000;
const maxChars = raw.maxCharsPerDocument ?? 1_000_000;
const includeValues = raw.includeFindingValues ?? false;
const returnMap = raw.returnPlaceholderMap ?? false;
const redactor = new Redactor(
    style,
    raw.hashSalt || randomBytes(16).toString('hex'),
    raw.consistentPlaceholders ?? true,
);

const counters = { documents_processed: 0, findings: 0, errors: 0, truncated_documents: 0 };
const countsByType: Record<string, number> = {};

type Doc = { id: string; source: 'text' | 'url'; text?: string; url?: string };
const docs: Doc[] = [];
(raw.texts ?? []).forEach((t, i) => docs.push({ id: `text-${i + 1}`, source: 'text', text: String(t) }));
(raw.documents ?? []).forEach((d, i) =>
    docs.push({ id: d.id ? String(d.id) : `doc-${i + 1}`, source: 'text', text: String(d.text ?? '') }),
);
(raw.documentUrls ?? []).forEach((u, i) => docs.push({ id: `url-${i + 1}`, source: 'url', url: String(u).trim() }));

if (!docs.length)
    await pushError('INPUT_EMPTY', 'Provide at least one item in texts, documents or documentUrls.', false);
if (docs.length > maxDocs) {
    await pushError(
        'MAX_DOCUMENTS_EXCEEDED',
        `${docs.length} documents supplied; only the first ${maxDocs} were processed.`,
        false,
    );
    docs.length = maxDocs;
}
if (mode === 'restore' && !raw.placeholderMap)
    await pushError('PLACEHOLDER_MAP_MISSING', 'mode "restore" needs placeholderMap.', false);

log.info('LLM Data Guard starting', { documents: docs.length, mode, style }); // never log content

const URL_CONCURRENCY = 4;
for (let i = 0; i < docs.length && !aborting; i += URL_CONCURRENCY) {
    const slice = docs.slice(i, i + URL_CONCURRENCY);
    const loaded = await Promise.all(
        slice.map(async (d) => {
            if (d.source !== 'url') return { d, text: d.text ?? '', contentType: 'text/plain' };
            try {
                const r = await loadUrl(d.url!);
                return { d, text: r.text, contentType: r.contentType };
            } catch (e) {
                return { d, error: e instanceof Error ? e.message : String(e) };
            }
        }),
    );
    for (const l of loaded) {
        if (aborting || emitter.limitReached) break;
        if ('error' in l) {
            await pushError('DOCUMENT_FETCH_FAILED', l.error ?? 'fetch failed', true, l.d);
            continue;
        }
        await processDoc(l.d, l.text, l.contentType);
    }
}

await finish();

async function processDoc(d: Doc, fullText: string, contentType: string): Promise<void> {
    let text = fullText;
    const truncated = text.length > maxChars;
    if (truncated) {
        text = text.slice(0, maxChars);
        counters.truncated_documents += 1;
    }
    const base = {
        schema_version: SCHEMA_VERSION,
        type: 'document' as const,
        id: d.id,
        source: d.source,
        source_url: d.url ?? null,
        content_type: contentType,
        processed_at: new Date().toISOString(),
        chars: text.length,
        truncated,
        mode,
    };
    if (mode === 'restore') {
        const restored = restore(text, raw.placeholderMap ?? {});
        await emitter.emit(
            { ...base, finding_count: 0, counts_by_type: {}, risk_level: 'none', findings: [], output_text: restored },
            EVENTS.document,
        );
        counters.documents_processed += 1;
        return;
    }
    redactor.resetDocument();
    const findings = await detect(text, opt);
    let outputText: string | null = null;
    let replacements: string[] = [];
    if (mode === 'redact') ({ text: outputText, replacements } = redactor.apply(text, findings));
    const counts: Record<string, number> = {};
    for (const f of findings) {
        counts[f.type] = (counts[f.type] ?? 0) + 1;
        countsByType[f.type] = (countsByType[f.type] ?? 0) + 1;
    }
    const row: Record<string, unknown> = {
        ...base,
        finding_count: findings.length,
        counts_by_type: counts,
        risk_level: riskOf(findings),
        findings: findings.map((f, idx) => ({
            type: f.type,
            category: f.category,
            rule: f.rule,
            confidence: f.confidence,
            start: f.start,
            end: f.end,
            length: f.end - f.start,
            preview: maskValue(f),
            replacement: replacements[idx] ?? null,
            ...(includeValues ? { value: f.value } : {}),
        })),
        output_text: outputText,
    };
    if (mode === 'redact' && style === 'placeholder' && returnMap)
        row.placeholder_map = Object.fromEntries([...new Set(replacements)].map((ph) => [ph, redactor.map[ph]]));
    await emitter.emit(row, { [EVENTS.document]: 1, [EVENTS.finding]: findings.length });
    counters.documents_processed += 1;
    counters.findings += findings.length;
}

function riskOf(f: Finding[]): 'none' | 'low' | 'medium' | 'high' {
    if (!f.length) return 'none';
    if (f.some((x) => (x.category === 'secret' && x.confidence !== 'low') || HIGH_RISK.has(x.type))) return 'high';
    if (f.some((x) => x.confidence !== 'low')) return 'medium';
    return 'low';
}

async function pushError(code: string, message: string, retryable: boolean, d?: Doc): Promise<void> {
    counters.errors += 1;
    await emitter.emit(
        {
            schema_version: SCHEMA_VERSION,
            type: 'error',
            code,
            message,
            retryable,
            id: d?.id ?? null,
            source_url: d?.url ?? null,
            processed_at: new Date().toISOString(),
        },
        null,
    );
}

async function finish(): Promise<never> {
    await emitter.flush();
    // Counts only: no input text, findings or placeholder map are written here.
    await Actor.setValue('RUN_SUMMARY', {
        schema_version: SCHEMA_VERSION,
        started_at: startedAt,
        finished_at: new Date().toISOString(),
        documents_requested: docs.length,
        ...counters,
        counts_by_type: countsByType,
        charged_events: emitter.charged,
        settings: {
            mode,
            redactionStyle: style,
            ...opt,
            allowList: `<${opt.allowList.length} entries>`,
            returnPlaceholderMap: returnMap,
        },
        data_retention:
            "Results are only written to this run's default dataset. Input text is never logged; INPUT record purged at run end when purgeInputAfterRun=true.",
    });
    if (raw.purgeInputAfterRun ?? true) {
        try {
            await Actor.setValue('INPUT', null);
        } catch (e) {
            log.warning(`Could not purge INPUT record: ${e instanceof Error ? e.message : String(e)}`);
        }
    }
    await Actor.exit();
    return undefined as never;
}
