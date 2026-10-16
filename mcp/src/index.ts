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

const server = new McpServer({ name: 'fairquery-llm-data-guard', version: '1.0.0' });

server.registerTool(
    'guard_text',
    {
        title: 'Detect / redact PII and secrets before LLM use',
        description:
            'Scan texts (or document URLs: txt/HTML/PDF) for PII (emails, phones, SSNs, Luhn-valid cards, IBANs, IPs, optional names/addresses) and secrets (API keys, tokens, private keys, entropy). mode=redact returns output_text with placeholders/masks/hashes; mode=restore puts originals back using placeholderMap. One row per document with findings (offsets + masked preview, no raw values unless includeFindingValues). Runs Apify Actor fairquery/llm-data-guard-pii-secrets; requires APIFY_TOKEN, billed per document and per finding.',
        inputSchema: {
            texts: z.array(z.string()).optional().describe('Documents to scan, one string each'),
            documentUrls: z.array(z.string().url()).optional().describe('Public URLs of txt/md/json/csv/HTML/PDF files'),
            mode: z.enum(['detect', 'redact', 'restore']).optional().describe('Default redact'),
            redactionStyle: z.enum(['placeholder', 'mask', 'hash']).optional().describe('Default placeholder'),
            returnPlaceholderMap: z.boolean().optional().describe('Return the placeholder->original map (sensitive)'),
            placeholderMap: z.record(z.string()).optional().describe('Map for restore mode'),
            detectNames: z.boolean().optional().describe('NER person names (default false)'),
            detectAddresses: z.boolean().optional().describe('Street addresses + places (default false)'),
            entropyScan: z.boolean().optional().describe('Flag any high-entropy token (default false)'),
            entityTypes: z.array(z.string()).optional().describe('Only these types, e.g. ["EMAIL","AWS_ACCESS_KEY"]'),
            allowList: z.array(z.string()).optional().describe('Exact values never flagged'),
            defaultPhoneRegion: z.string().length(2).optional().describe('ISO country for local phone formats, default US'),
        },
        outputSchema: {
            items: z.array(z.record(z.unknown())).describe('Dataset rows: type=document (findings, risk_level, output_text) or type=error'),
            count: z.number(),
        },
        annotations: { title: 'Guard text for LLMs', ...READ_ONLY_REMOTE },
    },
    async (args) => callActorTool(ACTOR_ID, args),
);

server.registerTool(
    'list_detectors',
    {
        title: 'List detectors and redaction styles (free)',
        description: 'Free, local, no token: lists the PII and secret types guard_text detects, the redaction styles, and the billable events. Use it to choose entityTypes before calling guard_text.',
        inputSchema: {},
        outputSchema: {
            pii: z.array(z.string()),
            secret: z.array(z.string()),
            redaction_styles: z.record(z.string()),
            pricing_events: z.record(z.string()),
        },
        annotations: { title: 'List detectors', ...READ_ONLY_LOCAL },
    },
    async () => ok(DETECTORS),
);

server.connect(new StdioServerTransport()).catch((err: unknown) => {
    console.error('fairquery-llm-data-guard MCP server failed to start:', err instanceof Error ? err.message : err);
    process.exit(1);
});
