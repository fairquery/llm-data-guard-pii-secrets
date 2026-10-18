# Changelog (MCP server)

## 1.1.0 - unreleased (preview)
- New free tool `restore_placeholders`: puts original values back into texts (typically an LLM answer) from the placeholder_map of a guard_text redact call; same placeholder pattern and output_text as guard_text mode="restore" (verified against an Actor run), computed locally without a run. Rows report replacements and unknown_placeholders.
- guard_text WHEN NOT TO USE points to it. Smoke test covers it offline; `--call` compares it with the Actor's restore mode. CI runs the offline MCP smoke test.

## 1.0.3 - 2026-10-18
- Tool text only (Glama conciseness pass): guard_text RETURNS shortened to what `outputSchema` does not say; prices appear only under COST.
- guard_list_detectors: BEHAVIOR states it is a static catalog with no network call; COST/RETURNS no longer repeat PARAMETERS.
- No tool names, input or output schemas, limits, behavior or prices changed.
