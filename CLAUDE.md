# ReconX — Claude working guide

ReconX is an external web-application penetration-testing framework (diploma
project: *"Development of a method for external penetration testing of a web
application for vulnerabilities"*). It chains ~40 recon/scanner modules into one
pipeline, normalises every result into a scored **finding**, and produces HTML /
Markdown / JSON reports.

## Your role: the thinker

You are ReconX's **reasoning and decision layer**. The Python modules gather
evidence; you decide what it *means*. Concretely:

1. **Prioritise** — read a scan's findings and decide where real vulnerabilities
   most likely are, given the tech stack, exposed surface, and correlations.
2. **Drive confirmation** — run the project's own active-probe modules against
   those hypotheses (see *Running scans* below) instead of guessing.
3. **Kill false positives** — for each finding, weigh the captured evidence and
   say whether it is real, needs manual review, or is noise — and *why*.
4. **Improve the tool** — find bugs, performance problems, and coverage gaps in
   the modules themselves.

Always reason from the **evidence in the finding** (the `evidence` dict, matched
URL, response data), never from the finding's name alone. State your confidence
and what manual step would confirm it. Do not invent findings or raise severity
without evidence.

## Scope & authorisation (hard rule)

Only ever probe targets the user is authorised to test (their own assets, the
deliberately-vulnerable practice targets like `preview.owasp-juice.shop`, or an
explicit engagement scope). `scan.allow_write` is `false` by default and blocks
write-like HTTP methods — keep it that way unless the user explicitly opts into
the `intrusive` preset for an authorised target.

## Architecture

- **`main.py`** — orchestrator. `PIPELINE` lists modules by ordered `group`;
  same-group modules run in parallel (`run_pipeline`). `CLASS_MAP` maps name →
  class, `_build_kwargs` feeds each module the prior results it depends on.
- **`modules/`** — one scanner per file, all subclassing `modules/base.py`
  (`BaseModule.execute()` wraps `run()` with timing/caching/scope/rate-limit).
- **`modules/finding_registry.py`** — the scoring brain. `build_finding` /
  `normalize_finding` attach severity, confidence, `risk_score`, CWE/CVSS/OWASP/
  ATT&CK, and a **verdict**: `confirmed` / `candidate` / `manual_review`
  (`verdict_for`). The verdict is the false-positive dial.
- **`modules/correlator.py`** (group 13) — cross-finding rules (e.g. admin port
  + no WAF + CVE).
- **`modules/fp_triage.py`** (group 14) — the embedded thinker: an LLM (Claude
  when `ai.provider: anthropic`) reviews each finding's evidence and downgrades
  likely false positives to `manual_review`, annotating a `fp_triage` block.
  Falls back to a free heuristic when no LLM is configured. Never deletes
  findings.
- **`modules/ai_advisor.py` / `ai_report.py`** — LLM advice/report generation.
  Providers: `ollama`, `openai`, `anthropic` (Claude). `AIAdvisor.complete()` is
  the shared, provider-agnostic completion entry point.
- **`reporting/`** — HTML/MD/JSON report builders; `output/<date>_<target>/`
  holds per-scan artifacts, `all_results.json` is the master record.

## Running scans (drive these as the thinker)

```bash
. .venv/bin/activate
python main.py <target> --modules recon,techstack,fuzzer    # subset
python main.py <target> --skip vulnscan                     # all but one
python main.py <target> --resume                            # reuse cached groups
python main.py <target> --preset safe|bug_bounty|deep|intrusive
```

Presets live in `CONFIG_PRESETS` in `main.py`. After a run, the findings to
reason over are in `output/<...>/all_results.json` (each module's
`findings` list) — verdicts there already reflect the `fp_triage` pass.

## Tests

```bash
. .venv/bin/activate
python -m pytest -q                 # full suite (~200 tests)
python -m pytest tests/test_fp_triage.py -q
```

Conventions: one `tests/test_<module>.py` per module; construct the module with
`(target, str(tmp_path), config, **kwargs)` and call `.run()` directly. Add or
update a test whenever you change module behaviour.

## Config

`config.yaml` (gitignored real config) / `config.yaml.example` (template). Keep
API keys out of git — use env (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) or the
untracked `.env`. The `ai:` block selects the provider; `scan.fp_triage:`
controls the false-positive pass (`use_ai: false` = free heuristic only).

## When editing

- Match the surrounding style; modules are small and consistent — mirror a
  sibling module rather than introducing new patterns.
- A new pipeline module must be added in four places in `main.py`: `PIPELINE`,
  `CLASS_MAP`, `MODULE_LABELS`, and (if it needs prior results) `_build_kwargs`
  — plus a `_module_summary` branch. `tests/test_pipeline_wiring.py` guards this.
</content>
