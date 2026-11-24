# Changelog (MCP server)

## 1.1.1 - 2026-10-18
- Tool text only (disambiguation pass; no tool names, inputs, outputs, limits or prices changed):
  - Server `instructions` describe the one-tool-per-step round trip (list_detectors -> guard_text -> [get_run_results] -> LLM -> restore_placeholders), which tools cost money and which never leave your machine.
  - guard_text is described as the only tool that inspects content; `mode="restore"` is marked as kept for Actor pipelines outside MCP, with restore_placeholders as the default way to restore (same output, free, local).
  - get_run_results says it only follows guard_text(waitForFinish=false) and scans nothing; status/finished semantics moved to RETURNS; how to stop a run early (Apify console) is stated.
  - list_detectors says it is reference data that inspects no text and is not needed before every guard_text call; BEHAVIOR no longer restates the read-only annotation.
  - restore_placeholders RETURNS / PARAMETERS no longer restate the output and input schemas.
- Smoke test checks the server instructions and that every tool description names its siblings.
- Docs: SECURITY.md describes the free get_run_results reader (read-only Apify API calls with your own token); support and security contact is info@getfairquery.com; Dependabot config.

## 1.1.0 - 2026-10-18
- New free tool `restore_placeholders`: puts original values back into texts (typically an LLM answer) from the placeholder_map of a guard_text redact call; same placeholder pattern and output_text as guard_text mode="restore" (verified against an Actor run), computed locally without a run. Rows report replacements and unknown_placeholders. guard_text WHEN NOT TO USE points to it.
- guard_text: new optional `waitForFinish` (default true). false starts the Actor run and returns at once with `run` (run_id, status, dataset_id, console_url); same price.
- New free tool `get_run_results`: status and paged rows of such a run (GET-only Apify API reads; rejects runs of other Actors with RUN_NOT_FOR_THIS_ACTOR; total never lower than the rows read, since dataset counters lag right after a run).
- Smoke test covers both new tools offline; `--call` compares restore_placeholders with the Actor's restore mode and runs the async start + poll path. CI runs the offline MCP smoke test.

## 1.0.3 - 2026-10-18
- Tool text only (Glama conciseness pass): guard_text RETURNS shortened to what `outputSchema` does not say; prices appear only under COST.
- guard_list_detectors: BEHAVIOR states it is a static catalog with no network call; COST/RETURNS no longer repeat PARAMETERS.
- No tool names, input or output schemas, limits, behavior or prices changed.
