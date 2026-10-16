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
    pricing_events: { 'document-processed': 'per document', finding: 'per finding' },
};

const server = new McpServer({ name: 'fairquery-llm-data-guard', version: '1.0.1' });

server.registerTool(
    'guard_text',
    {
        title: 'Detect / redact PII and secrets before LLM use',
        description: [
            'WHAT: Scan text documents (or public document URLs: txt/md/json/csv/HTML/PDF) for PII (emails, phones, US SSNs, Luhn-valid cards, IBANs, UK NINOs, IPs, optional person names/addresses) and secrets (AWS/GitHub/Slack/Stripe/OpenAI/... keys, JWTs, private keys, URL credentials, high-entropy key=value). mode="redact" returns sanitized text; mode="restore" puts originals back into LLM output using a placeholder map.',
            'WHEN TO USE: before sending prompts, tickets, logs or files to an LLM or third party; to audit text for leaked credentials; to de-anonymize an LLM answer after a placeholder redaction.',
            'WHEN NOT TO USE: to see which entity types exist or pick entityTypes, call list_detectors (free, local). Not for binary files/images (PDF text layer only, no OCR) or for validating whether an email is deliverable.',
            'COST: paid. Runs Apify Actor fairquery/llm-data-guard-pii-secrets with your APIFY_TOKEN; pay-per-event billed per document processed and per finding (error rows free). Typical run a few seconds.',
            'RETURNS: {count, items}. One type="document" row per input with id, source, chars, truncated, mode, finding_count, counts_by_type, risk_level, findings[] (type, offsets, masked preview; raw values are not returned), output_text (redact/restore modes), placeholder_map (only if returnPlaceholderMap=true); or type="error" rows with code/message.',
            'EXAMPLE: {"texts":["Mail jane@acme.com, key AKIAIOSFODNN7EXAMPLE"],"mode":"redact","redactionStyle":"placeholder"} -> output_text with the email replaced by [EMAIL_1] and the key by a placeholder; findings lists EMAIL and AWS_ACCESS_KEY.',
            'Provide texts and/or documentUrls (at least one).',
        ].join('\n'),
        inputSchema: {
            texts: z
                .array(z.string())
                .optional()
                .describe('Documents to scan, one string per document (prompt, chat message, ticket, log line, file content). Example: ["Hi, I am Jane (jane.doe@acme.com)"]. Optional if documentUrls is given.'),
            documentUrls: z
                .array(z.string().url())
                .optional()
                .describe('Public http(s) URLs of txt, md, json, csv, HTML or PDF files (max 10 MB each; PDFs text layer only). Example: ["https://example.com/report.pdf"]. Optional if texts is given.'),
            mode: z
                .enum(['detect', 'redact', 'restore'])
                .optional()
                .describe('"detect" = report findings only; "redact" (default) = also return output_text with values replaced; "restore" = replace placeholders in texts with originals from placeholderMap.'),
            redactionStyle: z
                .enum(['placeholder', 'mask', 'hash'])
                .optional()
                .describe('Used in redact mode. "placeholder" (default) = [EMAIL_1], reversible via placeholder map; "mask" = j***@a***.com / **** 1111; "hash" = [EMAIL:3f2a9c0d1b7e] salted sha256 prefix.'),
            returnPlaceholderMap: z
                .boolean()
                .optional()
                .describe('Default false. If true, each row includes placeholder_map {"[EMAIL_1]":"jane@acme.com"} needed for restore mode. Contains the original sensitive values.'),
            placeholderMap: z
                .record(z.string())
                .optional()
                .describe('Only for mode="restore": map of placeholder -> original value returned by a previous redact call, e.g. {"[EMAIL_1]":"jane@acme.com"}. Default {}.'),
            detectNames: z.boolean().optional().describe('Default false. Detect person names with English NER (lower precision, slightly slower).'),
            detectAddresses: z.boolean().optional().describe('Default false. Detect street addresses (English formats) and NER place names.'),
            entropyScan: z
                .boolean()
                .optional()
                .describe('Default false. Also flag unlabeled random-looking tokens of 20+ chars (catches unknown key formats; may flag hashes/IDs).'),
            entityTypes: z
                .array(z.string())
                .optional()
                .describe('Only report these entity types, e.g. ["EMAIL","CREDIT_CARD","AWS_ACCESS_KEY"]. Omit/empty = all enabled detectors. Valid names: see list_detectors.'),
            allowList: z
                .array(z.string())
                .optional()
                .describe('Exact values that are never flagged, e.g. ["support@yourcompany.com"]. Default [].'),
            defaultPhoneRegion: z
                .string()
                .length(2)
                .optional()
                .describe('ISO 3166-1 alpha-2 country code used to parse phone numbers written without +country prefix, e.g. "US" (default), "DE", "GB".'),
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
            'COST: free; local, no network, no APIFY_TOKEN, deterministic.',
            'RETURNS: {pii: string[], secret: string[], redaction_styles: {style: example}, pricing_events: {event: unit}}. Takes no arguments.',
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
