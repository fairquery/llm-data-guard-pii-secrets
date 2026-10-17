#!/usr/bin/env node
/**
 * Fairquery stdio MCP server for Apify Actor fairquery/llm-data-guard-pii-secrets.
 * Tools: guard_text (runs the Actor, needs APIFY_TOKEN) and list_detectors (free, local).
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

import { callActorTool, ok, READ_ONLY_LOCAL, READ_ONLY_REMOTE } from './common.js';

const ACTOR_ID = 'fairquery~llm-data-guard-pii-secrets';

const DETECTORS = {
    pii: ['EMAIL', 'PHONE', 'SSN', 'CREDIT_CARD (Luhn)', 'IBAN (mod-97)', 'UK_NINO', 'IP_ADDRESS (v4/v6)', 'STREET_ADDRESS (opt-in)', 'PERSON (opt-in NER)', 'LOCATION (opt-in NER)'],
    secret: ['PRIVATE_KEY', 'AWS_ACCESS_KEY', 'AWS_SECRET_KEY', 'GITHUB_TOKEN', 'GITLAB_TOKEN', 'SLACK_TOKEN', 'SLACK_WEBHOOK', 'STRIPE_KEY', 'GOOGLE_API_KEY', 'OPENAI_KEY', 'ANTHROPIC_KEY', 'HUGGINGFACE_TOKEN', 'NPM_TOKEN', 'SENDGRID_KEY', 'TWILIO_KEY', 'AZURE_STORAGE_KEY', 'JWT', 'URL_CREDENTIALS', 'GENERIC_SECRET (key=value + entropy)', 'HIGH_ENTROPY_STRING (opt-in)'],
    redaction_styles: { placeholder: '[EMAIL_1], reversible with placeholder map', mask: 'j***@a***.com, **** **** **** 1111', hash: '[EMAIL:3f2a9c0d1b7e] (salted sha256 prefix)' },
    pricing_events: { 'document-processed': '$0.003 per document', finding: '$0.0005 per finding' },
};

const server = new McpServer({ name: 'fairquery-llm-data-guard', version: '1.0.2' });

server.registerTool(
    'guard_text',
    {
        title: 'Detect / redact PII and secrets before LLM use',
        description: [
            'WHAT: Scan text documents (or public document URLs: txt/md/json/csv/HTML/PDF) for PII (emails, phones, US SSNs, Luhn-valid cards, IBANs, UK NINOs, IPs, optional person names/addresses) and secrets (AWS/GitHub/Slack/Stripe/OpenAI/... keys, JWTs, private keys, URL credentials, high-entropy key=value). mode="redact" returns sanitized text; mode="restore" puts originals back into LLM output using a placeholder map.',
            'WHEN TO USE: before sending prompts, tickets, logs or files to an LLM or third party; to audit text for leaked credentials; to de-anonymize an LLM answer after a placeholder redaction.',
            'WHEN NOT TO USE: to see which entity types exist or pick entityTypes, call list_detectors (free, local). Not for binary files/images (PDF text layer only, no OCR) or for validating whether an email is deliverable.',
            'COST: paid. Runs Apify Actor fairquery/llm-data-guard-pii-secrets with your APIFY_TOKEN; pay-per-event: $0.003 per document processed + $0.0005 per finding (error rows free). Example: 10 documents with 20 findings ~ $0.04. Typical run a few seconds.',
            'RETURNS: {count, items}. One type="document" row per input with id, source, chars, truncated, mode, finding_count, counts_by_type, risk_level, findings[] (type, offsets, masked preview; raw values are not returned), output_text (redact/restore modes), placeholder_map (only if returnPlaceholderMap=true); or type="error" rows with code/message.',
            'EXAMPLE: {"texts":["Mail jane@acme.com, key AKIAIOSFODNN7EXAMPLE"],"mode":"redact","redactionStyle":"placeholder"} -> output_text with the email replaced by [EMAIL_1] and the key by a placeholder; findings lists EMAIL and AWS_ACCESS_KEY.',
            'PARAMETERS: texts and/or documentUrls: at least one is required although the schema marks both optional (neither -> a free INPUT_EMPTY error row); both may be combined, and every text or URL is one billed document (max 1000 per run; extras get a free MAX_DOCUMENTS_EXCEEDED row). Documents longer than 1,000,000 chars are cut there (truncated=true). mode decides which other fields apply: "detect" ignores redactionStyle / returnPlaceholderMap; "redact" uses them; "restore" ignores all detector options and only replaces placeholders found in texts with values from placeholderMap (a placeholder missing from the map stays unchanged; restore rows have 0 findings, so they cost $0.003 each). returnPlaceholderMap only works with mode="redact" + redactionStyle="placeholder"; placeholders are consistent across all documents of one call ([EMAIL_1] is the same address everywhere) but numbering restarts on every call, so keep each call\'s map. detectNames / detectAddresses must be true before PERSON / LOCATION / STREET_ADDRESS can be found or used in entityTypes. entityTypes filters findings after detection (case-insensitive; unknown names match nothing, no error) and is the main lever to cut per-finding cost; allowList compares the whole matched value case-insensitively (not substrings). defaultPhoneRegion only affects numbers without a +country prefix.',
        ].join('\n'),
        inputSchema: {
            texts: z
                .array(z.string())
                .optional()
                .describe('Optional if documentUrls is given (at least one of the two is required). One string per document (prompt, chat message, ticket, log, file content), <= 1,000,000 chars each (longer is truncated); $0.003 per document. Example: ["Hi, I am Jane (jane.doe@acme.com)"]'),
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
            'COST: free; local, no network, no APIFY_TOKEN, deterministic. (guard_text costs $0.003 per document + $0.0005 per finding.)',
            'RETURNS: {pii: string[], secret: string[], redaction_styles: {style: example}, pricing_events: {event: unit}}.',
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

server.connect(new StdioServerTransport()).catch((err: unknown) => {
    console.error('fairquery-llm-data-guard MCP server failed to start:', err instanceof Error ? err.message : err);
    process.exit(1);
});
