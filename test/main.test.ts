import { describe, expect, it } from 'vitest';

import { detect, entropy, isCardNumber, isIban, luhn, type DetectOptions } from '../src/detectors.js';
import { maskValue, Redactor, restore } from '../src/redact.js';

const opt: DetectOptions = {
    detectPii: true, detectSecrets: true, detectNames: false, detectAddresses: false, entropyScan: false,
    minEntropy: 3.5, defaultPhoneRegion: 'US', entityTypes: [], allowList: [],
};

const SAMPLE = [
    'Contact jane.doe@acme.com or +1 415-555-0132. SSN 123-45-6789.',
    'Card 4111 1111 1111 1111, bad card 4111 1111 1111 1112. IBAN DE89 3704 0044 0532 0130 00.',
    'Server 192.168.10.24, key AKIAIOSFODNN7EXAMPLE and ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8',
    'api_key = "Zx9Qv7Lm2Rt8Wp4Ks6Hd1"',
].join('\n');

describe('validators', () => {
    it('luhn/card/iban', () => {
        expect(luhn('4111111111111111')).toBe(true);
        expect(isCardNumber('4111 1111 1111 1112')).toBe(false);
        expect(isIban('DE89 3704 0044 0532 0130 00')).toBe(true);
        expect(isIban('DE89 3704 0044 0532 0130 01')).toBe(false);
        expect(entropy('aaaa')).toBe(0);
    });
});

describe('detect', () => {
    it('finds PII and secrets', async () => {
        const f = await detect(SAMPLE, opt);
        const types = f.map((x) => x.type);
        for (const t of ['EMAIL', 'PHONE', 'SSN', 'CREDIT_CARD', 'IBAN', 'IP_ADDRESS', 'AWS_ACCESS_KEY', 'GITHUB_TOKEN', 'GENERIC_SECRET']) {
            expect(types).toContain(t);
        }
        expect(types.filter((t) => t === 'CREDIT_CARD')).toHaveLength(1);
    });
    it('honors allowList and entityTypes', async () => {
        const f = await detect(SAMPLE, { ...opt, entityTypes: ['EMAIL'], allowList: [] });
        expect(f.every((x) => x.type === 'EMAIL')).toBe(true);
        const g = await detect('mail jane.doe@acme.com', { ...opt, allowList: ['jane.doe@acme.com'] });
        expect(g).toHaveLength(0);
    });
    it('detects names with NER when enabled', async () => {
        const f = await detect('Yesterday John Smith met Mary Johnson in Chicago.', { ...opt, detectNames: true });
        expect(f.some((x) => x.type === 'PERSON')).toBe(true);
    });
});

describe('redact', () => {
    it('placeholder round trip', async () => {
        const text = 'Mail jane@acme.com twice: jane@acme.com and bob@acme.com';
        const f = await detect(text, opt);
        const r = new Redactor('placeholder', 's', true);
        const out = r.apply(text, f).text;
        expect(out).toBe('Mail [EMAIL_1] twice: [EMAIL_1] and [EMAIL_2]');
        expect(restore(out, r.map)).toBe(text);
    });
    it('mask and hash', async () => {
        expect(maskValue({ type: 'CREDIT_CARD', category: 'pii', value: '4111 1111 1111 1111' })).toBe('**** **** **** 1111');
        expect(maskValue({ type: 'EMAIL', category: 'pii', value: 'jane@acme.com' })).toBe('j***@a***.com');
        const f = await detect('jane@acme.com', opt);
        const h = new Redactor('hash', 'salt', true).apply('jane@acme.com', f).text;
        expect(h).toMatch(/^\[EMAIL:[0-9a-f]{12}\]$/);
    });
});
