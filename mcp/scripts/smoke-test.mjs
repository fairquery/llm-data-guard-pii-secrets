/**
 * Smoke test: initialize + tools/list + free helper without token; main tool must return APIFY_TOKEN_MISSING.
 * Optional --call runs the main tool with APIFY_TOKEN (value never printed).
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const serverJs = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'index.js');
const MAIN_ARGS = { texts: ['Mail jane@acme.com, key AKIAIOSFODNN7EXAMPLE'] };

async function withClient(env, fn) {
    const transport = new StdioClientTransport({ command: process.execPath, args: [serverJs], env, stderr: 'pipe' });
    const client = new Client({ name: 'fairquery-smoke', version: '1.0.0' });
    await client.connect(transport);
    try {
        return await fn(client);
    } finally {
        await client.close();
    }
}

const RESTORE_TEXTS = ['Mail [EMAIL_1] or [EMAIL_2]; key [AWS_ACCESS_KEY_1] x$&y.', '[a.b] [lower_1]'];
const RESTORE_MAP = { '[EMAIL_1]': 'jane@acme.com', '[AWS_ACCESS_KEY_1]': 'AKIAIOSFODNN7EXAMPLE', '[a.b]': 'nope' };
let localRestore = [];

const env = { ...process.env };
delete env.APIFY_TOKEN;
await withClient(env, async (client) => {
    const { tools } = await client.listTools();
    console.log('OK tools/list:', tools.map((t) => `${t.name}${t.outputSchema ? ' (outputSchema)' : ''}${t.annotations ? ' (annotations)' : ''}`).join(', '));
    for (const n of ['guard_text', 'list_detectors', 'restore_placeholders']) if (!tools.some((t) => t.name === n)) throw new Error('missing tool ' + n);
    const h = await client.callTool({ name: 'list_detectors', arguments: {} });
    if (h.isError || !h.structuredContent) throw new Error('helper failed: ' + JSON.stringify(h).slice(0, 300));
    console.log('OK list_detectors (free, no token)');
    const rp = await client.callTool({ name: 'restore_placeholders', arguments: { texts: RESTORE_TEXTS, placeholderMap: RESTORE_MAP } });
    const rows = rp.structuredContent?.items ?? [];
    if (rp.isError || rows[0]?.output_text !== 'Mail jane@acme.com or [EMAIL_2]; key AKIAIOSFODNN7EXAMPLE x$&y.' || rows[0].replacements !== 2 || JSON.stringify(rows[0].unknown_placeholders) !== '["[EMAIL_2]"]' || rows[1].output_text !== '[a.b] [lower_1]')
        throw new Error('restore_placeholders wrong: ' + JSON.stringify(rows));
    localRestore = rows.map((r) => r.output_text);
    console.log('OK restore_placeholders (free, local; unknown placeholders kept, non-placeholder keys ignored)');
    const r = await client.callTool({ name: 'guard_text', arguments: MAIN_ARGS });
    if (!JSON.stringify(r).includes('APIFY_TOKEN_MISSING')) throw new Error('expected APIFY_TOKEN_MISSING');
    console.log('OK guard_text without token -> APIFY_TOKEN_MISSING');
});

if (process.argv.includes('--call')) {
    if (!process.env.APIFY_TOKEN) throw new Error('APIFY_TOKEN not set for --call');
    await withClient({ ...process.env }, async (client) => {
        const r = await client.callTool({ name: 'guard_text', arguments: MAIN_ARGS });
        if (r.isError) throw new Error('call failed: ' + JSON.stringify(r).slice(0, 500));
        console.log('OK guard_text call, items:', r.structuredContent?.count);
        const pr = await client.callTool({ name: 'guard_text', arguments: { texts: RESTORE_TEXTS, mode: 'restore', placeholderMap: RESTORE_MAP } });
        const paid = (pr.structuredContent?.items ?? []).filter((i) => i.type === 'document').map((i) => i.output_text);
        if (JSON.stringify(paid) !== JSON.stringify(localRestore)) throw new Error('restore mismatch: paid ' + JSON.stringify(paid) + ' local ' + JSON.stringify(localRestore));
        console.log('OK restore_placeholders output == guard_text mode="restore" output (Actor run)');
    });
}
