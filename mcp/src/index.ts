#!/usr/bin/env node
/**
 * Fairquery stdio MCP server for Apify Actor fairquery/llm-data-guard-pii-secrets.
 * Tools: guard_text (runs the Actor, needs APIFY_TOKEN), list_detectors and restore_placeholders (free, local).
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

import { callActorTool, fail, ok, READ_ONLY_LOCAL, READ_ONLY_REMOTE } from './common.js';
import { restoreText } from './restore.js';

const ACTOR_ID = 'fairquery~llm-data-guard-pii-secrets';

const DETECTORS = {
    pii: ['EMAIL', 'PHONE', 'SSN', 'CREDIT_CARD (Luhn)', 'IBAN (mod-97)', 'UK_NINO', 'IP_ADDRESS (v4/v6)', 'STREET_ADDRESS (opt-in)', 'PERSON (opt-in NER)', 'LOCATION (opt-in NER)'],
    secret: ['PRIVATE_KEY', 'AWS_ACCESS_KEY', 'AWS_SECRET_KEY', 'GITHUB_TOKEN', 'GITLAB_TOKEN', 'SLACK_TOKEN', 'SLACK_WEBHOOK', 'STRIPE_KEY', 'GOOGLE_API_KEY', 'OPENAI_KEY', 'ANTHROPIC_KEY', 'HUGGINGFACE_TOKEN', 'NPM_TOKEN', 'SENDGRID_KEY', 'TWILIO_KEY', 'AZURE_STORAGE_KEY', 'JWT', 'URL_CREDENTIALS', 'GENERIC_SECRET (key=value + entropy)', 'HIGH_ENTROPY_STRING (opt-in)'],
    redaction_styles: { placeholder: '[EMAIL_1], reversible with placeholder map', mask: 'j***@a***.com, **** **** **** 1111', hash: '[EMAIL:3f2a9c0d1b7e] (salted sha256 prefix)' },
    pricing_events: { 'document-processed': '$0.0015 per document', finding: '$0.0002 per finding' },
};

const server = new McpServer({ name: 'fairquery-llm-data-guard', version: '1.1.0' });

server.registerTool(
    'guard_text',
    {
        title: 'Detect / redact PII and secrets before LLM use',
        description: [
            'WHAT: Scan text documents (or public document URLs: txt/md/json/csv/HTML/PDF) for PII (emails, phones, US SSNs, Luhn-valid cards, IBANs, UK NINOs, IPs, optional person names/addresses) and secrets (AWS/GitHub/Slack/Stripe/OpenAI/... keys, JWTs, private keys, URL credentials, high-entropy key=value). mode="redact" returns sanitized text; mode="restore" puts originals back into LLM output using a placeholder map.',
            'WHEN TO USE: before sending prompts, tickets, logs or files to an LLM or third party; to audit text for leaked credentials; to de-anonymize an LLM answer after a placeholder redaction.',
            'WHEN NOT TO USE: to see which entity types exist or pick entityTypes, call list_detectors (free, local); to only put originals back into an LLM answer, restore_placeholders (free, local) gives the same output as mode="restore" without a run. Not for binary files/images (PDF text layer only, no OCR) or for validating whether an email is deliverable.',
            'COST: paid. Runs Apify Actor fairquery/llm-data-guard-pii-secrets with your APIFY_TOKEN; pay-per-event: $0.0015 per document processed + $0.0002 per finding (error rows free). Example: 10 documents with 20 findings ~ $0.02. Typical run a few seconds.',
            'RETURNS: one type="document" row per input (findings[] hold masked previews only, never raw values; output_text only in redact/restore modes; placeholder_map only with returnPlaceholderMap=true) or free type="error" rows with code/message.',
            'EXAMPLE: {"texts":["Mail jane@acme.com, key AKIAIOSFODNN7EXAMPLE"],"mode":"redact","redactionStyle":"placeholder"} -> output_text with the email replaced by [EMAIL_1] and the key by a placeholder; findings lists EMAIL and AWS_ACCESS_KEY.',
            'PARAMETERS: texts and/or documentUrls: at least one is required although the schema marks both optional (neither -> a free INPUT_EMPTY error row); both may be combined, and every text or URL is one billed document (max 1000 per run; extras get a free MAX_DOCUMENTS_EXCEEDED row). Documents longer than 1,000,000 chars are cut there (truncated=true). mode decides which other fields apply: "detect" ignores redactionStyle / returnPlaceholderMap; "redact" uses them; "restore" ignores all detector options and only replaces placeholders found in texts with values from placeholderMap (a placeholder missing from the map stays unchanged; restore rows have 0 findings, so they cost the per-document fee only). returnPlaceholderMap only works with mode="redact" + redactionStyle="placeholder"; placeholders are consistent across all documents of one call ([EMAIL_1] is the same address everywhere) but numbering restarts on every call, so keep each call\'s map. detectNames / detectAddresses must be true before PERSON / LOCATION / STREET_ADDRESS can be found or used in entityTypes. entityTypes filters findings after detection (case-insensitive; unknown names match nothing, no error) and is the main lever to cut per-finding cost; allowList compares the whole matched value case-insensitively (not substrings). defaultPhoneRegion only affects numbers without a +country prefix.',
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
                .describe('Optional, one of "detect" | "redact" | "restore", default "redact". "detect" = report findings only; "redact" = also return output_text with values replaced; "restore" = replace placeholders in texts with originals from placeholderMap. Example: "detect"'),
            redactionStyle: z
                .enum(['placeholder', 'mask', 'hash'])
                .optional()
                .describe('Optional, one of "placeholder" | "mask" | "hash", default "placeholder"; used in mode="redact" only. "placeholder" = [EMAIL_1], reversible via placeholder map; "mask" = j***@a***.com / **** 1111; "hash" = [EMAIL:3f2a9c0d1b7e] salted sha256 prefix (random salt per run).'),
            returnPlaceholderMap: z
                .boolean()
                .optional()
                .describe('Optional boolean, default false. true (mode="redact" + redactionStyle="placeholder" only) adds placeholder_map {"[EMAIL_1]":"jane@acme.com"} to each row, needed for restore mode. Contains the ORIGINAL sensitive values.'),
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
        },
        outputSchema: {
            items: z.array(z.record(z.unknown())).describe('Dataset rows: type=document (findings, risk_level, output_text) or type=error'),
            count: z.number().describe('Number of rows in items'),
        },
        annotations: { title: 'Guard text for LLMs', ...READ_ONLY_REMOTE },
    },
    async (args) => callActorTool(ACTOR_ID, args),
);

server.registerTool(
    'list_detectors',
    {
        title: 'List detectors and redaction styles (free)',
        description: [
            'WHAT: Static catalog of the PII and secret entity types guard_text can detect, the available redaction styles, and the billable pricing events.',
            'WHEN TO USE: before guard_text, to choose entityTypes / redactionStyle or to explain coverage to a user.',
            'WHEN NOT TO USE: to actually scan or redact text - use guard_text.',
            'BEHAVIOR: static catalog shipped with this server version; no network call.',
            'COST: free; no APIFY_TOKEN. (guard_text is paid per document and per finding.)',
            'RETURNS: one catalog object; how each part maps to guard_text arguments is under PARAMETERS.',
            'PARAMETERS: None: call with an empty object {}; the catalog is static and cannot be filtered. Its output feeds guard_text: pii / secret entries are valid entityTypes values once the parenthesised note is dropped ("CREDIT_CARD (Luhn)" -> "CREDIT_CARD"); entries marked "opt-in" only appear when guard_text enables detectNames / detectAddresses / entropyScan; redaction_styles keys are the allowed redactionStyle values.',
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
            'WHAT: Put original values back into texts (typically an LLM answer) that contain placeholders such as [EMAIL_1], using the placeholder_map from a guard_text redact call. Same output_text as guard_text mode="restore", computed on your machine.',
            'WHEN TO USE: after the LLM answered a prompt you redacted with guard_text (mode="redact", redactionStyle="placeholder", returnPlaceholderMap=true), before showing the answer to the user.',
            'WHEN NOT TO USE: to detect or redact (guard_text) or list entity types (list_detectors). Masked and hashed values cannot be restored; only placeholder style is reversible.',
            'BEHAVIOR: no network call; the map never leaves your machine; milliseconds. Up to 1000 texts and 5,000,000 chars in total per call.',
            'COST: free; no APIFY_TOKEN. (guard_text mode="restore" bills $0.0015 per document for the same result.)',
            'RETURNS: one type="restored_document" row per text with output_text, replacements and unknown_placeholders; Errors: INPUT_TOO_LARGE.',
            'PARAMETERS: placeholderMap: pass the placeholder_map of the redact call unchanged; numbering restarts on every redact call, so use the map from the call that produced the placeholders. Tokens shaped [UPPERCASE_TYPE_N] are replaced when the map has them (exact, case-sensitive, one pass) and listed in unknown_placeholders otherwise (left as is); other map keys are ignored. A placeholder the LLM rewrote (e.g. "EMAIL_1" without brackets) is not restored. The output holds the ORIGINAL sensitive values: show it to the user, do not send it back to the LLM.',
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
