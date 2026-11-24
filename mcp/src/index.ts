#!/usr/bin/env node
/**
 * Fairquery stdio MCP server for Apify Actor fairquery/llm-data-guard-pii-secrets.
 * Four tools, one per step of a redact -> LLM -> restore round trip:
 *   list_detectors (free, local catalog) -> guard_text (paid Actor run: detect/redact) ->
 *   get_run_results (free read of a background guard_text run) -> restore_placeholders (free, local restore).
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

import { callActorTool, compact, fail, getToken, ok, READ_ONLY_LOCAL, READ_ONLY_REMOTE, readRun, RunLookupError, startActor, TOKEN_MISSING } from './common.js';
import { restoreText } from './restore.js';

const ACTOR_ID = 'fairquery~llm-data-guard-pii-secrets';

const DETECTORS = {
    pii: ['EMAIL', 'PHONE', 'SSN', 'CREDIT_CARD (Luhn)', 'IBAN (mod-97)', 'UK_NINO', 'IP_ADDRESS (v4/v6)', 'STREET_ADDRESS (opt-in)', 'PERSON (opt-in NER)', 'LOCATION (opt-in NER)'],
    secret: ['PRIVATE_KEY', 'AWS_ACCESS_KEY', 'AWS_SECRET_KEY', 'GITHUB_TOKEN', 'GITLAB_TOKEN', 'SLACK_TOKEN', 'SLACK_WEBHOOK', 'STRIPE_KEY', 'GOOGLE_API_KEY', 'OPENAI_KEY', 'ANTHROPIC_KEY', 'HUGGINGFACE_TOKEN', 'NPM_TOKEN', 'SENDGRID_KEY', 'TWILIO_KEY', 'AZURE_STORAGE_KEY', 'JWT', 'URL_CREDENTIALS', 'GENERIC_SECRET (key=value + entropy)', 'HIGH_ENTROPY_STRING (opt-in)'],
    redaction_styles: { placeholder: '[EMAIL_1], reversible with placeholder map', mask: 'j***@a***.com, **** **** **** 1111', hash: '[EMAIL:3f2a9c0d1b7e] (salted sha256 prefix)' },
    pricing_events: { 'document-processed': '$0.0015 per document', finding: '$0.0002 per finding' },
};

const INSTRUCTIONS = [
    'Fairquery LLM Data Guard: keep PII and secrets out of LLM prompts, then put the originals back into the answer.',
    'One tool per step: list_detectors (optional, free, local: which entity types and redaction styles exist) -> guard_text (paid Apify Actor run with your APIFY_TOKEN: detect or redact) -> get_run_results (free, only if guard_text was called with waitForFinish=false) -> send the redacted text to the LLM -> restore_placeholders (free, local: originals back into the answer).',
    'Only guard_text costs money ($0.0015 per document + $0.0002 per finding) and only guard_text and get_run_results use the network (your Apify account). list_detectors and restore_placeholders never leave your machine.',
    'guard_text mode="restore" exists for Actor pipelines outside MCP; through this server, restore with restore_placeholders (same output, free).',
].join(' ');

const server = new McpServer({ name: 'fairquery-llm-data-guard', version: '1.1.1' }, { instructions: INSTRUCTIONS });

server.registerTool(
    'guard_text',
    {
        title: 'Detect / redact PII and secrets before LLM use (paid run)',
        description: [
            'WHAT: The only tool in this server that inspects content. Scans text documents (or public document URLs: txt/md/json/csv/HTML/PDF) for PII (emails, phones, US SSNs, Luhn-valid cards, IBANs, UK NINOs, IPs, optional person names/addresses) and secrets (AWS/GitHub/Slack/Stripe/OpenAI/... keys, JWTs, private keys, URL credentials, high-entropy key=value). mode="detect" reports findings; mode="redact" (default) also returns sanitized text and, on request, the placeholder map that restore_placeholders needs later.',
            'WHEN TO USE: before sending prompts, tickets, logs or files to an LLM or third party; to audit text for leaked credentials. Step 2 of the round trip (list_detectors -> guard_text -> [get_run_results] -> LLM -> restore_placeholders).',
            'WHEN NOT TO USE: to put originals back into an LLM answer, use restore_placeholders (free, local; mode="restore" here gives the same output but starts a paid run and is only kept for Actor pipelines outside MCP). To see entity types, list_detectors (free). To fetch rows of a run you already started, get_run_results (free; calling guard_text again starts and bills a new run). Not for images/scanned PDFs (text layer only, no OCR) or email deliverability.',
            'COST: paid. Runs Apify Actor fairquery/llm-data-guard-pii-secrets with your APIFY_TOKEN; pay-per-event: $0.0015 per document processed + $0.0002 per finding (error rows free). Example: 10 documents with 20 findings ~ $0.02.',
            'RETURNS: findings[] hold masked previews only, never raw values; placeholder_map (ORIGINAL values) only with returnPlaceholderMap=true. With waitForFinish=false: items is empty and run.run_id is the input for get_run_results.',
            'EXAMPLE: {"texts":["Mail jane@acme.com, key AKIAIOSFODNN7EXAMPLE"],"mode":"redact","redactionStyle":"placeholder"} -> output_text with the email replaced by [EMAIL_1] and the key by a placeholder; findings lists EMAIL and AWS_ACCESS_KEY.',
            'PARAMETERS: texts and/or documentUrls: at least one is required although the schema marks both optional (neither -> a free INPUT_EMPTY error row); both may be combined, and every text or URL is one billed document (max 1000 per run; extras get a free MAX_DOCUMENTS_EXCEEDED row). mode decides which other fields apply: "detect" ignores redactionStyle / returnPlaceholderMap; "redact" uses them; "restore" ignores all detector options and only replaces placeholders found in texts with values from placeholderMap (a placeholder missing from the map stays unchanged; restore rows have 0 findings, so they cost the per-document fee only). returnPlaceholderMap only works with mode="redact" + redactionStyle="placeholder" and is what restore_placeholders consumes; placeholders are consistent across all documents of one call ([EMAIL_1] is the same address everywhere) but numbering restarts on every call, so keep each call\'s map. detectNames / detectAddresses must be true before PERSON / LOCATION / STREET_ADDRESS can be found or used in entityTypes. entityTypes filters findings after detection (unknown names match nothing, no error) and is the main lever to cut per-finding cost. waitForFinish=false returns at once with run.run_id while the run continues in your Apify account (same price, billed once); use it for big batches or many URLs/PDFs that may not finish within this call\'s 280 s wait, then poll get_run_results with that run_id.',
        ].join('\n'),
        inputSchema: {
            texts: z
                .array(z.string())
                .optional()
                .describe('Optional if documentUrls is given (at least one of the two is required). One string per document (prompt, chat message, ticket, log, file content), <= 1,000,000 chars each (longer is truncated); one billed document each. Example: ["Hi, I am Jane (jane.doe@acme.com)"]'),
            documentUrls: z
                .array(z.string().url())
                .optional()
                .describe('Optional if texts is given. Absolute public http(s) URLs of txt, md, json, csv, HTML or PDF files (max 10 MB each; PDFs text layer only, no OCR), fetched by the Actor; unreachable URLs give free DOCUMENT_FETCH_FAILED rows. Example: ["https://example.com/report.pdf"]'),
            mode: z
                .enum(['detect', 'redact', 'restore'])
                .optional()
                .describe('Optional, one of "detect" | "redact" | "restore", default "redact". "detect" = report findings only; "redact" = also return output_text with values replaced; "restore" = replace placeholders in texts with originals from placeholderMap (paid run; restore_placeholders does the same for free). Example: "detect"'),
            redactionStyle: z
                .enum(['placeholder', 'mask', 'hash'])
                .optional()
                .describe('Optional, one of "placeholder" | "mask" | "hash", default "placeholder"; used in mode="redact" only. "placeholder" = [EMAIL_1], reversible via placeholder map; "mask" = j***@a***.com / **** 1111; "hash" = [EMAIL:3f2a9c0d1b7e] salted sha256 prefix (random salt per run).'),
            returnPlaceholderMap: z
                .boolean()
                .optional()
                .describe('Optional boolean, default false. true (mode="redact" + redactionStyle="placeholder" only) adds placeholder_map {"[EMAIL_1]":"jane@acme.com"} to each row; pass it to restore_placeholders after the LLM step. Contains the ORIGINAL sensitive values.'),
            placeholderMap: z
                .record(z.string())
                .optional()
                .describe('Optional, default {}; used only with mode="restore". Object mapping placeholder -> original value, as returned in placeholder_map by a previous redact call. Example: {"[EMAIL_1]":"jane@acme.com"}'),
            detectNames: z.boolean().optional().describe('Optional boolean, default false. true detects person names (type PERSON) with English NER (lower precision, slightly slower; each finding billed).'),
            detectAddresses: z.boolean().optional().describe('Optional boolean, default false. true detects street addresses (STREET_ADDRESS, English formats) and NER place names (LOCATION).'),
            entropyScan: z
                .boolean()
                .optional()
                .describe('Optional boolean, default false. true also flags unlabeled random-looking tokens of 20+ chars as HIGH_ENTROPY_STRING (catches unknown key formats; may flag hashes/IDs).'),
            entityTypes: z
                .array(z.string())
                .optional()
                .describe('Optional, default omitted/[] = all enabled detectors. Entity type names (case-insensitive) from list_detectors, without the "(opt-in)" notes. Example: ["EMAIL","CREDIT_CARD","AWS_ACCESS_KEY"]'),
            allowList: z
                .array(z.string())
                .optional()
                .describe('Optional, default []. Exact values that are never flagged (whole value, case-insensitive; not substrings). Example: ["support@yourcompany.com"]'),
            defaultPhoneRegion: z
                .string()
                .length(2)
                .optional()
                .describe('Optional, default "US". ISO 3166-1 alpha-2 country code (exactly 2 letters, case-insensitive) used to parse phone numbers written without a +country prefix. Examples: "US", "DE", "GB"'),
            waitForFinish: z
                .boolean()
                .optional()
                .describe('Optional boolean, default true. true waits up to 280 s and returns the rows; false starts the run and returns immediately with run.run_id (poll get_run_results). Same price either way. Example: false'),
        },
        outputSchema: {
            items: z.array(z.record(z.unknown())).describe('Dataset rows: type=document (findings, risk_level, output_text) or type=error'),
            count: z.number().describe('Number of rows in items'),
            run: z.record(z.unknown()).optional().describe('Only with waitForFinish=false: run_id, status, dataset_id, console_url'),
        },
        annotations: { title: 'Guard text for LLMs', ...READ_ONLY_REMOTE },
    },
    async ({ waitForFinish, ...args }) => {
        if (waitForFinish !== false) return callActorTool(ACTOR_ID, args);
        const token = getToken();
        if (!token) return TOKEN_MISSING();
        try {
            const run = await startActor(ACTOR_ID, compact(args), token);
            return ok({ items: [], count: 0, run });
        } catch (e) {
            return fail('APIFY_ACTOR_RUN_FAILED', e instanceof Error ? e.message : String(e));
        }
    },
);

server.registerTool(
    'get_run_results',
    {
        title: 'Poll a background guard_text run (free read)',
        description: [
            'WHAT: Read-only follow-up to guard_text(waitForFinish=false): returns the run status and one page of its result rows. It scans nothing itself.',
            'WHEN TO USE: only after guard_text returned run.run_id (large batches, many documentUrls or PDFs); poll until run.finished is true and page with nextOffset. Rows already written are returned while the run is RUNNING.',
            'WHEN NOT TO USE: to scan or redact (guard_text; a synchronous guard_text call already returns its rows, so there is nothing to poll). To restore placeholders in the rows\' output_text after the LLM step, restore_placeholders (free). Cannot read runs of other Actors.',
            'BEHAVIOR: GET requests to your Apify account only (actor, run, dataset); never starts, aborts or re-bills a run. Typically <1 s; poll every 10-30 s. To stop a run early, abort it in the Apify console (run.console_url); this server has no abort tool.',
            'COST: free; needs the APIFY_TOKEN that started the run. The run was billed once, per document and finding, when it ran.',
            'RETURNS: run.status is READY | RUNNING | SUCCEEDED | FAILED | ABORTED | TIMED-OUT; finished=true for the last four, after which total no longer changes (FAILED/TIMED-OUT runs still return the rows they wrote). Rows are exactly the ones guard_text returns, including placeholder_map with ORIGINAL values if requested. Errors: APIFY_TOKEN_MISSING, RUN_NOT_FOUND, RUN_NOT_FOR_THIS_ACTOR, APIFY_TOKEN_INVALID, APIFY_RUN_LOOKUP_FAILED / APIFY_DATASET_READ_FAILED (retryable).',
            'PARAMETERS: runId comes from guard_text run.run_id. Pages are in write order; total counts rows written so far, so keep calling with nextOffset until it is null and finished is true.',
            'EXAMPLE: {"runId":"a1B2c3D4e5F6g7H8i"} -> {"run":{"status":"SUCCEEDED","finished":true},"count":1,"total":1,"items":[{"type":"document","risk_level":"high",...}]}',
        ].join('\n'),
        inputSchema: {
            runId: z.string().min(5).max(64).regex(/^[A-Za-z0-9]+$/).describe('Required. Apify run ID (letters and digits) from guard_text run.run_id. Example: "a1B2c3D4e5F6g7H8i"'),
            offset: z.number().int().min(0).optional().describe('Optional integer >= 0, default 0; use nextOffset from the previous page. Example: 100'),
            limit: z.number().int().min(1).max(1000).optional().describe('Optional page size, integer 1-1000, default 100. Example: 250'),
        },
        outputSchema: {
            run: z.record(z.unknown()).describe('run_id, status, finished, dataset_id, started_at, finished_at, console_url'),
            items: z.array(z.record(z.unknown())).describe('Dataset rows: type=document or type=error'),
            count: z.number().describe('Rows in this page'),
            total: z.number().describe('Rows written by the run so far'),
            nextOffset: z.number().nullable().describe('Offset of the next page, or null'),
        },
        annotations: { title: 'Get guard_text run results (free)', ...READ_ONLY_REMOTE },
    },
    async ({ runId, offset = 0, limit = 100 }) => {
        const token = getToken();
        if (!token) return TOKEN_MISSING();
        try {
            const { info, items, total } = await readRun(ACTOR_ID, runId, token, offset, limit);
            const next = items.length === limit || offset + items.length < total ? offset + items.length : null; // a full page may have more
            return ok({ run: info, items, count: items.length, total, nextOffset: next });
        } catch (e) {
            if (e instanceof RunLookupError) return fail(e.code, e.message + (e.retryable ? ' (retryable)' : ''));
            return fail('APIFY_RUN_LOOKUP_FAILED', `${e instanceof Error ? e.message : String(e)} (retryable)`);
        }
    },
);

server.registerTool(
    'list_detectors',
    {
        title: 'List detectable types and redaction styles (free, local)',
        description: [
            'WHAT: Reference data, not a scan: the PII and secret entity types guard_text can detect, its redaction styles and its billable events. Inspects no text.',
            'WHEN TO USE: optional step 1, before guard_text, to choose entityTypes / redactionStyle, to estimate guard_text cost, or to explain coverage to a user.',
            'WHEN NOT TO USE: to check whether a given text contains PII or secrets (guard_text; this catalog cannot tell you that). Not needed before every guard_text call: guard_text runs all default detectors when entityTypes is omitted. To undo a redaction, restore_placeholders.',
            'BEHAVIOR: the catalog ships with this server version and is not fetched from the Actor, so a newer Actor build can support types that an older server version does not list.',
            'COST: free; no APIFY_TOKEN.',
            'RETURNS: pii / secret entries are valid guard_text entityTypes once the parenthesised note is dropped ("CREDIT_CARD (Luhn)" -> "CREDIT_CARD"); "opt-in" entries need guard_text detectNames / detectAddresses / entropyScan; redaction_styles keys are the allowed redactionStyle values (only "placeholder" can be undone with restore_placeholders).',
            'PARAMETERS: none; call with {}.',
            'EXAMPLE: {} -> {"pii":["EMAIL","PHONE",...],"secret":["AWS_ACCESS_KEY",...],...}',
        ].join('\n'),
        inputSchema: {},
        outputSchema: {
            pii: z.array(z.string()).describe('PII entity types (opt-in ones marked)'),
            secret: z.array(z.string()).describe('Secret/credential entity types'),
            redaction_styles: z.record(z.string()).describe('Redaction style -> example output'),
            pricing_events: z.record(z.string()).describe('Billable Apify event -> unit'),
        },
        annotations: { title: 'List detectors', ...READ_ONLY_LOCAL },
    },
    async () => ok(DETECTORS),
);

const MAX_RESTORE_DOCS = 1000;
const MAX_RESTORE_CHARS = 5_000_000;

server.registerTool(
    'restore_placeholders',
    {
        title: 'Restore placeholders with original values (free, local)',
        description: [
            'WHAT: The last step of the round trip and the default way to restore: puts original values back into texts (typically an LLM answer) that contain placeholders such as [EMAIL_1], using the placeholder_map from a guard_text redact call. Does no detection.',
            'WHEN TO USE: after the LLM answered a prompt you redacted with guard_text (mode="redact", redactionStyle="placeholder", returnPlaceholderMap=true), before showing the answer to the user. Prefer it over guard_text mode="restore": same output_text, but free and local.',
            'WHEN NOT TO USE: to find or redact PII/secrets (guard_text) or list entity types (list_detectors). Masked and hashed values cannot be restored; only placeholder style is reversible.',
            'BEHAVIOR: no network call; the map never leaves your machine; milliseconds. Up to 1000 texts and 5,000,000 chars in total per call.',
            'COST: free; no APIFY_TOKEN.',
            'RETURNS: replacements counts substituted placeholders; unknown_placeholders lists [TYPE_N] tokens the map does not cover (left as is, e.g. invented by the LLM). Errors: INPUT_TOO_LARGE. The output holds the ORIGINAL sensitive values: show it to the user, do not send it back to the LLM.',
            'PARAMETERS: placeholderMap must be the map of the redact call that produced the placeholders (numbering restarts on every call); only [UPPERCASE_TYPE_N] keys are used (exact, case-sensitive, one pass). A placeholder the LLM rewrote (e.g. "EMAIL_1" without brackets) is not restored.',
            'EXAMPLE: {"texts":["I will email [EMAIL_1] today."],"placeholderMap":{"[EMAIL_1]":"jane@acme.com"}} -> output_text "I will email jane@acme.com today.", replacements 1.',
        ].join('\n'),
        inputSchema: {
            texts: z
                .array(z.string())
                .min(1)
                .max(MAX_RESTORE_DOCS)
                .describe('Required. 1-1000 texts containing placeholders, 5,000,000 chars in total. Example: ["I will email [EMAIL_1] today."]'),
            placeholderMap: z
                .record(z.string())
                .describe('Required. Object placeholder -> original value, exactly as returned in placeholder_map by a guard_text redact call. Example: {"[EMAIL_1]":"jane@acme.com"}'),
        },
        outputSchema: {
            items: z.array(z.record(z.unknown())).describe('type=restored_document rows (doc_index, chars, replacements, unknown_placeholders, output_text)'),
            count: z.number().describe('Number of rows in items'),
        },
        annotations: { title: 'Restore placeholders (free, local)', ...READ_ONLY_LOCAL },
    },
    async ({ texts, placeholderMap }) => {
        const total = texts.reduce((n, t) => n + t.length, 0);
        if (total > MAX_RESTORE_CHARS) return fail('INPUT_TOO_LARGE', `Total ${total} chars exceeds ${MAX_RESTORE_CHARS}; split into several calls.`);
        const items = texts.map((t, i) => ({ type: 'restored_document', doc_index: i, chars: t.length, ...restoreText(t, placeholderMap) }));
        return ok({ items, count: items.length });
    },
);

server.connect(new StdioServerTransport()).catch((err: unknown) => {
    console.error('fairquery-llm-data-guard MCP server failed to start:', err instanceof Error ? err.message : err);
    process.exit(1);
});
