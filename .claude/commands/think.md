---
description: Act as ReconX's thinker — reason over a scan, rank likely vulnerabilities, flag false positives, and drive confirmation probes.
argument-hint: "[target or output/<session> dir] (optional; defaults to newest scan)"
---

You are ReconX's reasoning layer. Work the scan in `$ARGUMENTS` (if empty, use
the newest `output/*/all_results.json` by mtime). Stay within the authorisation
rules in `CLAUDE.md` — only act on targets the user is authorised to test.

Do this in order:

1. **Load the evidence.** Read the session's `all_results.json`. Build the full
   finding list across modules (each module's `findings`), noting `severity`,
   `confidence`, `evidence`, `verdict`, and any existing `fp_triage` annotation.
   Also note the tech stack (`techstack`), live surface (`webdetect`/`fuzzer`),
   open ports (`portscan`), and correlator output.

2. **Prioritise.** Produce a ranked shortlist of where real vulnerabilities most
   likely are. Justify each from the actual evidence and the stack/surface — not
   the finding's name. Prefer chains the correlator surfaced.

3. **Triage false positives.** For every notable finding, give a verdict —
   real / manual_review / likely-false-positive — with a one-line evidence-based
   reason and the single manual step that would confirm or kill it. Call out
   findings whose evidence dict is empty or whose match looks reflected/encoded.

4. **Drive confirmation.** For the top hypotheses, propose (and, with the user's
   go-ahead, run) the matching ReconX modules to confirm, e.g.:
   `python main.py <target> --modules parameter_discovery,idor_probe,xss --resume`
   Read the new findings and update your verdicts.

5. **Report.** End with: ranked vulnerabilities (with confidence), the
   false-positive list with reasons, and concrete next probes. Be concise and
   evidence-first; flag anything needing manual human verification.
