# LLM Data Guard: PII & Secret Redactor

**Finds and redacts PII and secrets in text, HTML and PDF before they reach an LLM, for $3 per 1,000 documents plus $0.50 per 1,000 findings.** Error rows are free. Example: 1,000 support tickets with 2 findings each on average cost 1,000 × $0.003 + 2,000 × $0.0005 = **$4.00**, plus Apify's $0.00005 Actor-start fee.

**Fairquery** Apify Actor that finds and redacts **personal data (PII)** and **secrets** in text, HTML and PDF documents **before they are sent to an LLM**, a vector store or a third-party API. Each document gets a risk level, a list of findings (type, offsets, masked preview) and, in redact mode, a clean `output_text` you can pass straight to your model. Placeholders are reversible, so you can put the original values back into the model's answer.

> **No data retention.** The Actor never logs document content and writes nothing except the result rows in the run's default dataset and a counts-only `RUN_SUMMARY`. By default it also deletes the run's `INPUT` record when it finishes (`purgeInputAfterRun`). Raw values are not stored in findings unless you turn on `includeFindingValues`. You control the dataset; delete it (or the run) once you have read it.

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
| `document-processed` | $0.003 | Each document scanned (or restored) |
| `finding` | $0.0005 | Each PII or secret finding reported |
| `apify-actor-start` | $0.00005 | Once per run, per GB of memory (Apify default event) |

Error rows (`INPUT_EMPTY`, `MAX_DOCUMENTS_EXCEEDED`, `PLACEHOLDER_MAP_MISSING`, `DOCUMENT_FETCH_FAILED`) are **never charged**.

**Worked example:** 1,000 support tickets, 2,000 findings in total: 1,000 × $0.003 + 2,000 × $0.0005 = $3.00 + $1.00 = **$4.00**, plus $0.00005. A clean document with no findings costs $0.003.

To cap spend, set a maximum cost per run in the run options; the Actor stops cleanly at the limit. `entityTypes` limits which types are reported (and charged as findings); `maxDocuments` caps documents per run. Prices are from the Store pricing tab (October 2026).

## Memory / runtime

Default **256 MB**, no browser, no proxy. Regex detectors process roughly 1–5 MB of text per second; NER (`detectNames`) is slower, so give it 512 MB for big batches. PDFs are parsed with `unpdf` (text layer only, no OCR).

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
| Names or addresses not detected | `detectNames` and `detectAddresses` are opt-in and English-focused. Turn them on, and give big batches 512 MB. |

## FAQ

**Is document content stored?**

Content is never logged. Results go only to your run's dataset, `RUN_SUMMARY` holds counts only, and the `INPUT` record is deleted at the end by default (`purgeInputAfterRun`). Delete the dataset when you no longer need it.

**Can I get the original values back after the LLM answers?**

Yes. Use `redactionStyle: "placeholder"` with `returnPlaceholderMap: true`, then run `mode: "restore"` with that map.

**Does it catch everything?**

No. It is a pattern-and-validation engine (checksums, issuer prefixes, Gitleaks-style rules). Unusual formats, non-English names and images can slip through. Use it as one layer of defence.

**How much does it cost?**

$0.003 per document plus $0.0005 per finding, and a $0.00005 start fee. Error rows are free.

**Can I scan text without sending it to Apify?**

Yes. The Fairquery MCP server (`npx -y @fairquery/agent-trust-mcp`) has free `pii_scan_text` and `pii_redact_text` tools that run locally. This Actor adds names and addresses, URLs, PDFs and restore mode.

## Fairquery family

Other Fairquery tools on the Apify Store. Each one returns structured rows with machine-readable error codes, and error rows are never charged:

- [Email Validator for Agents (MX, Disposable, Typo)](https://apify.com/fairquery/email-validator-mx-disposable): syntax, MX, disposable, role and typo checks without sending mail; $2 per 1,000 emails
- [Website Contact & Company Enricher](https://apify.com/fairquery/website-contact-company-enricher): domain in, public business emails, phones, socials and company details out; $4 per 1,000 domains
- [Website Tech, SEO & llms.txt Check for Agents](https://apify.com/fairquery/website-tech-seo-ai-readiness): tech stack, SEO score, AI-crawler rules and llms.txt per site; $2 per 1,000 sites
- [Sanctions & Watchlist Screener (OFAC, EU, UK, UN)](https://apify.com/fairquery/sanctions-watchlist-screener): fuzzy name screening against official sanctions lists; $5 per 1,000 names
- [Dependency Vulnerability Check for Agents](https://apify.com/fairquery/osv-dependency-vulnerability-check): packages and lockfiles against OSV.dev; $0.90 per 1,000 packages + $2.80 per 1,000 vulnerabilities
- [EDGAR Company Facts & Filings for Agents](https://apify.com/fairquery/edgar-company-facts-filings): SEC filings and XBRL facts by ticker, CIK or name; from $2 per 1,000 companies
- **MCP server** [`@fairquery/agent-trust-mcp`](https://www.npmjs.com/package/@fairquery/agent-trust-mcp): one MCP server for Claude Desktop, Cursor and VS Code (`npx -y @fairquery/agent-trust-mcp`). It has 7 free tools that need no token, plus paid tools that call the PII, email, sanctions and OSV Actors with your own Apify token.

All Fairquery Actors: https://apify.com/fairquery

## Kits & templates

Optional guides from Fairquery for wiring this Actor into agents and automations (the Actor works fine without them):

- [AI Agent Data Toolkit Quick-Start](https://fairquery.gumroad.com/l/qayngz) (PDF): MCP setup for Claude Desktop and Cursor, API calls, recipes, cost estimates.
- [n8n + Zapier Workflow Template Pack](https://fairquery.gumroad.com/l/koffbf): 10 importable n8n workflows for the four original Fairquery Actors (SEC EDGAR, website/tech, email, OSV); it does not include workflows for this Actor yet, but the patterns adapt easily.
- [Agent Prompt Pack for Research & Lead Ops](https://fairquery.gumroad.com/l/djdilu): 69 prompts for company research, lead cleaning, SEO and security reviews.
- [Agent Starter Kit: 10 copy-paste MCP + n8n recipes](https://fairquery.gumroad.com/l/idvrck) ($5): 10 copy-paste MCP + n8n recipes, with ready-made Claude/Cursor configs and 3 starter workflows.

## Disclaimer

Pattern-based detection finds most but not all sensitive data: unusual formats, non-English names, images and scanned PDFs (no OCR) can slip through, and some matches are false positives. Use it as one layer of a data-protection program, not as a compliance certification. Only process data you are allowed to process.

## Links

- Apify Store: https://apify.com/fairquery/llm-data-guard-pii-secrets
- GitHub: https://github.com/fairquery/llm-data-guard-pii-secrets
- Contact: fairquery@proton.me
- License: MIT
