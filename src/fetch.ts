import * as cheerio from 'cheerio';

const MAX_BYTES = 10 * 1024 * 1024;
const UA = 'FairqueryBot/1.0 (+https://apify.com/fairquery)';

export async function loadUrl(url: string): Promise<{ text: string; contentType: string }> {
    if (!/^https?:\/\//i.test(url)) throw new Error(`Unsupported URL: ${url.slice(0, 200)}`);
    const res = await fetch(url, {
        headers: { 'user-agent': UA },
        redirect: 'follow',
        signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${url.slice(0, 200)}`);
    const len = Number(res.headers.get('content-length') ?? 0);
    if (len > MAX_BYTES) throw new Error(`Document larger than 10 MB (${len} bytes)`);
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > MAX_BYTES) throw new Error(`Document larger than 10 MB (${buf.length} bytes)`);
    const ct = (res.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase();
    if (ct === 'application/pdf' || buf.subarray(0, 5).toString() === '%PDF-') {
        const { extractText, getDocumentProxy } = await import('unpdf');
        const pdf = await getDocumentProxy(new Uint8Array(buf));
        const { text } = await extractText(pdf, { mergePages: true });
        return { text: text as string, contentType: 'application/pdf' };
    }
    const body = buf.toString('utf8');
    if (ct.includes('html') || /^\s*<(?:!doctype html|html)/i.test(body)) {
        const $ = cheerio.load(body);
        $('script,style,noscript,svg').remove();
        return {
            text: $('body')
                .text()
                .replace(/[ \t]+/g, ' ')
                .replace(/\n\s*\n+/g, '\n\n')
                .trim(),
            contentType: 'text/html',
        };
    }
    return { text: body, contentType: ct || 'text/plain' };
}
