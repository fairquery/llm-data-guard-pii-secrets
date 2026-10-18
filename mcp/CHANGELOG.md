# Changelog (MCP server)

## 1.1.0 - 2026-10-18
- New free tool `restore_placeholders`: puts original values back into texts (typically an LLM answer) from the placeholder_map of a guard_text redact call; same placeholder pattern and output_text as guard_text mode="restore" (verified against an Actor run), computed locally without a run. Rows report replacements and unknown_placeholders. guard_text WHEN NOT TO USE points to it.
- guard_text: new optional `waitForFinish` (default true). false starts the Actor run and returns at once with `run` (run_id, status, dataset_id, console_url); same price.
- New free tool `get_run_results`: status and paged rows of such a run (GET-only Apify API reads; rejects runs of other Actors with RUN_NOT_FOR_THIS_ACTOR; total never lower than the rows read, since dataset counters lag right after a run).
- Smoke test covers both new tools offline; `--call` compares restore_placeholders with the Actor's restore mode and runs the async start + poll path. CI runs the offline MCP smoke test.

## 1.0.3 - 2026-10-18
- Tool text only (Glama conciseness pass): guard_text RETURNS shortened to what `outputSchema` does not say; prices appear only under COST.
- guard_list_detectors: BEHAVIOR states it is a static catalog with no network call; COST/RETURNS no longer repeat PARAMETERS.
- No tool names, input or output schemas, limits, behavior or prices changed.
