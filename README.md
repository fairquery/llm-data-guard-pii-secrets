# PII Redaction & Secret Scanner for LLM Pipelines

## What does it do?

This **PII redaction** Actor finds and redacts **personal data** and **secrets** in text, HTML and PDF documents **before they are sent to an LLM**, a vector store or a third-party API. It detects emails, phones, SSNs, credit cards (Luhn-checked), IBANs, UK NINOs and IP addresses, optional names and street addresses, and 18 secret types such as AWS, GitHub, Stripe, OpenAI and Anthropic keys, private keys and JWTs.

Each document gets a risk level, a list of findings with offsets and masked previews, and in redact mode a clean `output_text`. Placeholders are **reversible**, so you can put the original values back into the model's answer. The Actor never logs document content and, by default, deletes the run's input when it finishes.

## How much does it cost?

Pay per event, no subscription. Prices per 1,000 events:

| Event | Free plan | Starter (Bronze) | Scale (Silver) | Business (Gold) |
|---|---|---|---|---|
| `document-processed` (primary) | $1.50 | $1.35 | $1.20 | $0.99 |
| `finding` | $0.20 | $0.20 | $0.20 | $0.20 |

The [Apify Free plan](https://apify.com/pricing) includes **$5 of usage every month**, no credit card needed, and this Actor's event charges come out of that $5. That covers about **3,300 clean documents a month** ($5 ÷ ($1.50/1,000)), or about 2,600 documents with 2 findings each, plus a start fee of $0.05 per 1,000 runs. Error rows are never charged.

**Example (Free-plan prices):** 1,000 support tickets with 2,000 findings in total: 1,000 × ($1.50/1,000) + 2,000 × ($0.20/1,000) = **$1.90**.

Paid Apify plans get the Store discount automatically: Starter = Bronze, Scale = Silver, Business = Gold. Set a maximum cost per run in the run options and the Actor stops cleanly at that limit.

## How to use it

1. Paste **Texts**, add **Documents** objects, or give **Document URLs** (HTML or PDF).
2. Pick a mode (`detect` or `redact`) and a **redaction style** (placeholder, mask or hash). Turn on names and addresses if you need them.
3. Click **Start**. Send `output_text` to your model, and keep the placeholder map if you want to restore values afterwards.

**Example input**

```json
{
  "texts": [
    "Contact jane.doe@example.com or call +1 415-555-0132."
  ],
  "mode": "redact",
  "redactionStyle": "placeholder"
}
```

_The Actor deletes each run's input when it finishes, so the input above is placeholder text of the same shape as the text that produced this row._

**Example output** (one row from a real run on 2026-10-18, shortened to the main fields):

```json
{
  "type": "document",
  "id": "text-1",
  "mode": "redact",
  "chars": 53,
  "finding_count": 2,
  "counts_by_type": {
    "EMAIL": 1,
    "PHONE": 1
  },
  "risk_level": "medium",
  "findings": [
    {
      "type": "EMAIL",
      "category": "pii",
      "rule": "email",
      "confidence": "high",
      "start": 8,
      "end": 28,
      "length": 20,
      "preview": "j***@e***.com",
      "replacement": "[EMAIL_1]"
    },
    {
      "type": "PHONE",
      "category": "pii",
      "rule": "libphonenumber",
      "confidence": "high",
      "start": 37,
      "end": 52,
      "length": 15,
      "preview": "+* ***-***-0132",
      "replacement": "[PHONE_1]"
    }
  ],
  "output_text": "Contact [EMAIL_1] or call [PHONE_1]."
}
```

## FAQ

### How do I remove PII from text before sending it to ChatGPT or another LLM?

Run the text through this Actor in `redact` mode and send `output_text` to the model. Emails, phones, card numbers, keys and other matches are replaced with placeholders like `[EMAIL_1]`.

### Can I restore the original values after the LLM answers?

Yes. Turn on `returnPlaceholderMap`, then run the model's answer back through the Actor in restore mode with that map.

### Does it detect API keys and secrets as well as PII?

Yes: 18 named secret types (for example AWS, GitHub, Slack, Stripe, OpenAI and Anthropic keys, private keys, JWTs) plus generic high-entropy secrets.

### Is my data stored?

The Actor is designed not to log document content, writes only result rows and a counts-only summary, and by default tries to delete the run's input record when it finishes (best effort: skipped if the run crashes, times out or is aborted). Results hold the redacted text, masked previews and any document URLs. Original values are stored if you turn on `includeFindingValues` or `returnPlaceholderMap`, restore mode outputs the original values, and anything redaction misses stays in the text.

## Limits

Pattern-based detection finds most but not all sensitive data: unusual formats, non-English names and scanned PDFs (no OCR) can slip through. Use it as one layer of data protection, not as a compliance certification.

## When to use this Actor (LLM / tool selection)

Use it when an agent or pipeline needs to:

- Strip emails, phone numbers, SSNs, card numbers, IBANs and IP addresses from prompts, chat logs, support tickets or CRM notes before LLM calls
- Catch leaked credentials (AWS, GitHub, Slack, Stripe, OpenAI, Anthropic, Google, private keys, JWTs, `password=...`) in logs, code snippets and config files
- Pseudonymise a dataset for RAG / fine-tuning with consistent placeholders (`[EMAIL_1]`, `[PERSON_2]`)
- Restore real values in the LLM's answer (`mode: "restore"`)
- Audit a batch of documents for sensitive-data risk (`mode: "detect"`)

Covers OWASP LLM Top 10 risk **LLM02 Sensitive Information Disclosure** at the input side. It is a pattern-and-validation engine, not a guarantee: always keep defense in depth.

## What it detects

| Category | Types | Validation |
| --- | --- | --- |
| PII | `EMAIL`, `PHONE`, `SSN`, `CREDIT_CARD`, `IBAN`, `UK_NINO`, `IP_ADDRESS` | Luhn + issuer prefix for cards, mod-97 + country length for IBANs, libphonenumber for phones, SSN area/group rules |
| PII (opt-in) | `PERSON`, `LOCATION`, `STREET_ADDRESS` | Open-source NER ([compromise](https://github.com/spencermountain/compromise), English) and street-address patterns |
| Secrets | `PRIVATE_KEY`, `AWS_ACCESS_KEY`, `AWS_SECRET_KEY`, `GITHUB_TOKEN`, `GITLAB_TOKEN`, `SLACK_TOKEN`, `SLACK_WEBHOOK`, `STRIPE_KEY`, `GOOGLE_API_KEY`, `OPENAI_KEY`, `ANTHROPIC_KEY`, `HUGGINGFACE_TOKEN`, `NPM_TOKEN`, `SENDGRID_KEY`, `TWILIO_KEY`, `AZURE_STORAGE_KEY`, `JWT`, `URL_CREDENTIALS` | Gitleaks-style rules |
| Secrets | `GENERIC_SECRET` (`api_key=…`, `token: …`, `password=…`) | Shannon-entropy threshold (`minEntropy`), placeholder words ignored |
| Secrets (opt-in) | `HIGH_ENTROPY_STRING` | Any 20+ char random-looking token |

Overlapping matches are resolved (secrets > cards/IBAN > SSN > email > IP > phone > address > names), so a card number is never also reported as a phone.

## Redaction styles

| `redactionStyle` | Example | Reversible |
| --- | --- | --- |
| `placeholder` (default) | `Mail [EMAIL_1] or call [PHONE_1]` | Yes, with `returnPlaceholderMap` and `mode: "restore"` |
| `mask` | `j***@a***.com`, `**** **** **** 1111`, `AKIA****************` | No |
| `hash` | `[EMAIL:3f2a9c0d1b7e]` (salted SHA-256 prefix) | No; stable across runs if you set `hashSalt` |

## Input

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `texts` | `string[]` | – (sample texts are prefilled in the Console form) | One document per entry |
| `documents` | `{id,text}[]` | `[]` | Documents with your own IDs |
| `documentUrls` | `string[]` | `[]` | Public txt/md/json/csv/HTML/PDF URLs (max 10 MB each) |
| `mode` | `detect` \| `redact` \| `restore` | `redact` | |
| `redactionStyle` | `placeholder` \| `mask` \| `hash` | `placeholder` | |
| `returnPlaceholderMap` | bool | `false` | Adds `placeholder_map` per row (contains originals!) |
| `consistentPlaceholders` | bool | `true` | Same value → same placeholder across documents |
| `placeholderMap` | object | `{}` | For `restore` mode |
| `hashSalt` | secret string | random per run | For `hash` style |
| `detectPii` / `detectSecrets` | bool | `true` | |
| `detectNames` / `detectAddresses` / `entropyScan` | bool | `false` | Opt-in detectors |
| `minEntropy` | number | `3.5` | Bits/char for generic secrets |
| `defaultPhoneRegion` | string | `US` | For numbers without `+` prefix |
| `entityTypes` | `string[]` | all | Only report these types |
| `allowList` | `string[]` | `[]` | Values never flagged |
| `includeFindingValues` | bool | `false` | Put raw values into findings |
| `maxDocuments` / `maxCharsPerDocument` | int | `1000` / `1,000,000` | Safety caps |
| `purgeInputAfterRun` | bool | `true` | Delete the `INPUT` record at the end |

```json
{
  "texts": ["Hi, I'm Jane (jane.doe@acme.com, +1 415-555-0132). Card 4111 1111 1111 1111.", "AWS key AKIAIOSFODNN7EXAMPLE"],
  "mode": "redact",
  "redactionStyle": "placeholder",
  "returnPlaceholderMap": true
}
```

## Output

One row per document (`type: "document"`) plus machine-readable `type: "error"` rows.

```json
{
  "schema_version": "1.0.0", "type": "document", "id": "text-1", "source": "text", "chars": 78, "mode": "redact",
  "finding_count": 3, "risk_level": "high",
  "counts_by_type": { "EMAIL": 1, "PHONE": 1, "CREDIT_CARD": 1 },
  "findings": [
    { "type": "EMAIL", "category": "pii", "rule": "email", "confidence": "high", "start": 14, "end": 31, "length": 17, "preview": "j***@a***.com", "replacement": "[EMAIL_1]" }
  ],
  "output_text": "Hi, I'm Jane ([EMAIL_1], [PHONE_1]). Card [CREDIT_CARD_1].",
  "placeholder_map": { "[EMAIL_1]": "jane.doe@acme.com", "[PHONE_1]": "+1 415-555-0132", "[CREDIT_CARD_1]": "4111 1111 1111 1111" }
}
```

`risk_level`: `high` = any secret or card/SSN/IBAN/NI number; `medium` = other confident PII; `low` = only low-confidence (NER/entropy) hits; `none`.

Restore after the LLM answers:

```json
{ "mode": "restore", "texts": ["Dear [EMAIL_1], your card ending [CREDIT_CARD_1]…"], "placeholderMap": { "[EMAIL_1]": "jane.doe@acme.com" } }
```

Error codes: `INPUT_EMPTY`, `MAX_DOCUMENTS_EXCEEDED`, `PLACEHOLDER_MAP_MISSING`, `DOCUMENT_FETCH_FAILED` (error rows are never charged).

**`RUN_SUMMARY`** (key-value store) holds counts per type, charged events and settings only, never text.

## Pricing

| Event | Price | When |
| --- | --- | --- |
| `document-processed` | $1.50 per 1,000 | Each document scanned (or restored) |
| `finding` | $0.20 per 1,000 | Each PII or secret finding reported |
| `apify-actor-start` | $0.05 per 1,000 runs | Once per run, per GB of memory (Apify default event) |

Error rows (`INPUT_EMPTY`, `MAX_DOCUMENTS_EXCEEDED`, `PLACEHOLDER_MAP_MISSING`, `DOCUMENT_FETCH_FAILED`) are **never charged**.

**Worked example:** 1,000 support tickets, 2,000 findings in total: 1,000 × ($1.50/1,000) + 2,000 × ($0.20/1,000) = $1.50 + $0.40 = **$1.90**, plus $0.05 per 1,000 runs. A clean document with no findings costs $1.50 per 1,000.

To cap spend, set a maximum cost per run in the run options; the Actor stops cleanly at the limit. `entityTypes` limits which types are reported (and charged as findings); `maxDocuments` caps documents per run. Prices are from the Store pricing tab (October 2026).

## Memory / runtime

Runs at a fixed **512 MB** (default and maximum; enough for NER), no browser, no proxy. Regex detectors process roughly 1–5 MB of text per second; NER (`detectNames`) is slower, so split very big batches into several runs. PDFs are parsed with `unpdf` (text layer only, no OCR).

## MCP / Apify tools

Call from agents via [Apify MCP](https://mcp.apify.com) with Actor `fairquery/llm-data-guard-pii-secrets`:

```json
{ "actor": "fairquery/llm-data-guard-pii-secrets", "input": { "texts": ["..."], "mode": "redact" } }
```

## Works well after

- [Website Content Crawler](https://apify.com/apify/website-content-crawler): scrub crawled pages before you index them in a vector store or send them to an LLM.
- Exports of support tickets, chat logs or CRM notes: run them through `mode: "redact"` first, call your model, then put the real values back with `mode: "restore"`.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| Run ends with only an `INPUT_EMPTY` row | No `texts`, `documents` or `documentUrls`. The sample texts in the Console form are prefill only and are not sent with API calls. |
| `DOCUMENT_FETCH_FAILED` | The URL was unreachable, over 10 MB or not a supported type. These rows are free. Scanned PDFs have no text layer, and there is no OCR. |
| `PLACEHOLDER_MAP_MISSING` in restore mode | Pass the `placeholderMap` returned by the redact run (`returnPlaceholderMap: true`). |
| Too many findings (false positives) | Add known-safe values to `allowList`, raise `minEntropy`, keep `entropyScan` off, or limit `entityTypes`. |
| Names or addresses not detected | `detectNames` and `detectAddresses` are opt-in and English-focused. Turn them on (they are slower; split very big batches). |

## FAQ

**Is document content stored?**

The Actor is designed not to log document content. Results go only to your run's dataset, `RUN_SUMMARY` holds counts only, and by default (`purgeInputAfterRun`) the Actor tries to delete the `INPUT` record at the end; this is best effort and is skipped if the run crashes, times out or is aborted. Delete the dataset when you no longer need it.

**Can I get the original values back after the LLM answers?**

Yes. Use `redactionStyle: "placeholder"` with `returnPlaceholderMap: true`, then run `mode: "restore"` with that map.

**Does it catch everything?**

No. It is a pattern-and-validation engine (checksums, issuer prefixes, Gitleaks-style rules). Unusual formats, non-English names and images can slip through. Use it as one layer of defence.

**How much does it cost?**

$1.50 per 1,000 documents plus $0.20 per 1,000 findings, and a start fee of $0.05 per 1,000 runs. Error rows are free.

**Can I scan text without sending it to Apify?**

Yes, through [Apify MCP](https://mcp.apify.com) with Actor `fairquery/llm-data-guard-pii-secrets`.

## Fairquery family

Other Fairquery tools on the Apify Store. Each one returns structured rows with machine-readable error codes, and error rows are never charged:

- [Email Validator for Agents (MX, Disposable, Typo)](https://apify.com/fairquery/email-validator-mx-disposable): syntax, MX, disposable, role and typo checks without sending mail; $0.79 per 1,000 emails
- [Website Contact & Company Enricher](https://apify.com/fairquery/website-contact-company-enricher): domain in, public business emails, phones, socials and company details out; $3 per 1,000 domains
- [Website Tech, SEO & llms.txt Check for Agents](https://apify.com/fairquery/website-tech-seo-ai-readiness): tech stack, SEO score, AI-crawler rules and llms.txt per site; $1.50 per 1,000 sites
- [Sanctions & Watchlist Screener (OFAC, EU, UK, UN)](https://apify.com/fairquery/sanctions-watchlist-screener): fuzzy name screening against official sanctions lists; $3 per 1,000 names + $7.00 per 1,000 runs
- [Dependency Vulnerability Check for Agents](https://apify.com/fairquery/osv-dependency-vulnerability-check): packages and lockfiles against OSV.dev; $0.50 per 1,000 packages + $1.50 per 1,000 vulnerabilities
- [EDGAR Company Facts & Filings for Agents](https://apify.com/fairquery/edgar-company-facts-filings): SEC filings and XBRL facts by ticker, CIK or name; $1.50 per 1,000 companies on the free plan; lower on paid Apify plans
- [Company Jobs Feed: Greenhouse, Lever & Ashby](https://apify.com/fairquery/company-jobs-feed): live jobs from employers' own ATS boards with age and repost signals; $0.99 per 1,000 jobs + $0.50 per 1,000 boards
- [Competitor Change Tracker: Pricing, Terms, Careers & Changelog](https://apify.com/fairquery/competitor-change-tracker): watch competitors' public pricing, terms, careers and changelog pages for real changes with plain-English summaries and webhook alerts; $0.30 per 1,000 pages + $4.90 per 1,000 changes
- [AI Exposure Scanner: Public Secrets, Files & AI-Crawler Policy](https://apify.com/fairquery/ai-exposure-scanner): passive, scored scan of your own domains and public GitHub repos for leaked secrets (masked), exposed files, AI-crawler policy, security headers and SPF/DMARC; $39.00 per 1,000 domains + $3.90 per 1,000 repos + $1.90 per 1,000 findings

All Fairquery Actors: https://apify.com/fairquery

## Data handling, security and support

- **Data retention:** Text is processed in memory, and the Actor is designed not to log it. By default the `INPUT` record is deleted when the run ends (`purgeInputAfterRun`), so only the results dataset remains in your Apify account, under your Apify plan's retention. You can delete run storages and named stores at any time in Apify Console or through the API. Fairquery's code sends nothing to Fairquery.
- **Security reports:** email info@getfairquery.com.
- **Support:** the Issues tab on this page or info@getfairquery.com. We aim to reply within 3 business days (a target, not an SLA).

## Disclaimer

Pattern-based detection finds most but not all sensitive data: unusual formats, non-English names, images and scanned PDFs (no OCR) can slip through, and some matches are false positives. Use it as one layer of a data-protection program, not as a compliance certification. Only process data you are allowed to process.

## Links

- Apify Store: https://apify.com/fairquery/llm-data-guard-pii-secrets
- Contact: info@getfairquery.com
- License: MIT
