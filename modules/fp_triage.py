"""
ReconX — Module: AI False-Positive Triage.

Runs after the scanners and the correlator, once every finding exists. It is a
*reasoning* pass, not a scanner: it never invents findings and never raises
severity on its own. For each existing finding it asks the configured LLM
(Claude when ai.provider is anthropic) one question — "given the evidence, is
this likely a false positive?" — and uses the answer to adjust the finding's
`verdict` triage label (confirmed / candidate / manual_review) and attach an
explanation. Findings judged to be false positives are *downgraded* to
manual_review and annotated; they are never silently deleted, so a human can
always audit the call.

When no LLM is reachable (no key / disabled), it falls back to a free,
deterministic heuristic so the verdict column stays meaningful offline.
"""

import json

from modules.base import BaseModule
from modules.finding_registry import (
    VERDICT_CONFIRMED,
    VERDICT_REVIEW,
    clamp,
)

# Modules whose findings are pure information (no exploit claim) — skip triage.
_SKIP_SOURCES = {"correlator", "asset_risk", "ai_report", "fp_triage"}

_SYSTEM = (
    "You are a senior penetration tester triaging the output of an automated "
    "external web scanner. Your only job is to judge whether each candidate "
    "finding is a FALSE POSITIVE given the evidence provided. Be conservative: "
    "do not invent details, do not assume evidence that is not shown, and do "
    "not change severities. When evidence is thin but the bug class is "
    "plausible, prefer 'manual_review' over calling it a false positive. "
    "Respond ONLY with the requested JSON."
)


class FPTriageModule(BaseModule):
    name = "fp_triage"
    description = "AI False-Positive Triage"
    required_tools: list[str] = []

    def __init__(self, target: str, output_dir: str, config: dict,
                 all_results: dict | None = None):
        super().__init__(target, output_dir, config)
        self.all_results = all_results or {}

    # ── Orchestration ─────────────────────────────────────────────────────────

    def run(self) -> dict:
        cfg = self.config.get("scan", {}).get("fp_triage", {})
        if not cfg.get("enabled", True):
            return {"status": "disabled", "assessed": 0, "flagged": 0}

        findings = self._collect_findings()
        if not findings:
            self.success("No findings to triage")
            return {"status": "completed", "assessed": 0, "flagged": 0,
                    "method": "none"}

        max_items = int(cfg.get("max_findings", 80))
        if len(findings) > max_items:
            # Triage the riskiest first; never silently drop the rest — they
            # keep their original verdict and are reported as not-assessed.
            findings.sort(key=lambda f: f["finding"].get("risk_score", 0),
                          reverse=True)
            skipped = len(findings) - max_items
            self.warn(f"Triaging top {max_items} of {len(findings)} findings "
                      f"by risk; {skipped} left at their original verdict")
            findings = findings[:max_items]

        verdicts, method = self._assess(findings, cfg)
        flagged = self._apply(findings, verdicts)

        self.save_json(
            {"method": method, "flagged_false_positive": flagged,
             "verdicts": verdicts},
            "fp_triage.json",
        )
        if flagged:
            self.warn(f"{flagged} finding(s) flagged as likely false positive "
                      f"({method})")
        else:
            self.success(f"No likely false positives among {len(findings)} "
                         f"finding(s) ({method})")
        return {
            "status": "completed",
            "assessed": len(findings),
            "flagged": flagged,
            "method": method,
        }

    def summary(self) -> str:
        r = self.results
        return (f"🧠 Triaged {r.get('assessed', 0)} finding(s), "
                f"{r.get('flagged', 0)} likely FP")

    # ── Finding collection ──────────────────────────────────────────────────────

    def _collect_findings(self) -> list[dict]:
        """Flatten every module's `findings` list into one work list.

        Each entry keeps a live reference to the original finding dict so
        `_apply` can mutate the verdict in place; the mutation is visible in
        all_results and therefore persisted by the pipeline.
        """
        collected: list[dict] = []
        idx = 0
        for source, result in self.all_results.items():
            if source in _SKIP_SOURCES or not isinstance(result, dict):
                continue
            items = result.get("findings")
            if not isinstance(items, list):
                continue
            for finding in items:
                if not isinstance(finding, dict):
                    continue
                collected.append({"idx": idx, "source": source,
                                  "finding": finding})
                idx += 1
        return collected

    # ── Assessment ──────────────────────────────────────────────────────────────

    def _assess(self, findings: list[dict], cfg: dict) -> tuple[dict, str]:
        """Return {idx: {is_fp, confidence, reason}} and the method used."""
        if cfg.get("use_ai", True):
            verdicts = self._assess_with_ai(findings)
            if verdicts:
                return verdicts, "ai"
            self.warn("AI triage unavailable — using heuristic fallback")
        return self._assess_heuristic(findings), "heuristic"

    def _assess_with_ai(self, findings: list[dict]) -> dict:
        try:
            from modules.ai_advisor import AIAdvisor
            advisor = AIAdvisor(self.config)
        except Exception:
            return {}

        prompt = self._build_prompt(findings)
        self.save_text(prompt, "fp_triage_prompt.txt")
        raw = advisor.complete(prompt, system=_SYSTEM,
                               max_tokens=self.config.get("ai", {}).get(
                                   "max_tokens", 2048))
        if not raw:
            return {}
        self.save_text(raw, "fp_triage_response.txt")
        return self._parse_ai(raw, {f["idx"] for f in findings})

    def _build_prompt(self, findings: list[dict]) -> str:
        compact = [self._compact(entry) for entry in findings]
        payload = json.dumps(compact, ensure_ascii=False, default=str)[:12000]
        return (
            f"Target under authorised test: {self.target}\n\n"
            "Below is a JSON array of automated findings. For EACH item, decide "
            "if it is likely a false positive given only the evidence shown.\n\n"
            f"{payload}\n\n"
            "Return ONLY a JSON array, one object per finding, in the same "
            'order, each shaped exactly like:\n'
            '{"idx": <int>, "is_false_positive": <bool>, '
            '"confidence": <0.0-1.0>, "reason": "<one short sentence>"}\n'
            "No prose, no markdown fences."
        )

    @staticmethod
    def _compact(entry: dict) -> dict:
        f = entry["finding"]
        evidence = f.get("evidence", {})
        evidence_str = json.dumps(evidence, ensure_ascii=False,
                                  default=str)[:600] if evidence else ""
        return {
            "idx": entry["idx"],
            "source": entry["source"],
            "type": f.get("type") or f.get("id", ""),
            "title": f.get("title") or f.get("name", ""),
            "severity": f.get("severity", "INFO"),
            "confidence": f.get("confidence"),
            "exploitability": f.get("exploitability"),
            "current_verdict": f.get("verdict"),
            "url": f.get("url") or f.get("matched_url", ""),
            "evidence": evidence_str,
        }

    @staticmethod
    def _parse_ai(raw: str, valid_idx: set) -> dict:
        text = raw.strip()
        # Tolerate accidental ```json fences or leading prose.
        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end != -1 and end > start:
            text = text[start:end + 1]
        try:
            data = json.loads(text)
        except Exception:
            return {}
        if not isinstance(data, list):
            return {}
        out: dict = {}
        for item in data:
            if not isinstance(item, dict):
                continue
            try:
                idx = int(item.get("idx"))
            except (TypeError, ValueError):
                continue
            if idx not in valid_idx:
                continue
            out[idx] = {
                "is_fp": bool(item.get("is_false_positive")),
                "confidence": clamp(item.get("confidence", 0.5)),
                "reason": str(item.get("reason", ""))[:300],
            }
        return out

    def _assess_heuristic(self, findings: list[dict]) -> dict:
        """Free, deterministic fallback.

        A finding is flagged as a likely false positive when it has no evidence
        and weak confidence and was never actively confirmed — exactly the shape
        of a noisy heuristic hit.
        """
        out: dict = {}
        for entry in findings:
            f = entry["finding"]
            evidence = f.get("evidence") or {}
            confidence = clamp(f.get("confidence", 0.75))
            exploitability = str(f.get("exploitability", "")).lower()
            verdict = f.get("verdict")
            is_fp = (
                not evidence
                and confidence < 0.5
                and exploitability not in ("confirmed", "active")
                and verdict != VERDICT_CONFIRMED
            )
            out[entry["idx"]] = {
                "is_fp": is_fp,
                "confidence": 0.6 if is_fp else 0.5,
                "reason": ("no captured evidence and low confidence"
                           if is_fp else "retained — evidence or signal present"),
            }
        return out

    # ── Apply verdicts ───────────────────────────────────────────────────────────

    def _apply(self, findings: list[dict], verdicts: dict) -> int:
        """Write triage results back onto the live finding dicts.

        Downgrades likely false positives to manual_review and annotates every
        assessed finding with an `fp_triage` block. Returns the flagged count.
        """
        threshold = clamp(
            self.config.get("scan", {}).get("fp_triage", {}).get(
                "fp_confidence_threshold", 0.6)
        )
        flagged = 0
        for entry in findings:
            verdict = verdicts.get(entry["idx"])
            if not verdict:
                continue
            f = entry["finding"]
            annotation = {
                "assessed": True,
                "is_false_positive": verdict["is_fp"],
                "confidence": verdict["confidence"],
                "reason": verdict["reason"],
            }
            if verdict["is_fp"] and verdict["confidence"] >= threshold:
                annotation["original_verdict"] = f.get("verdict")
                f["verdict"] = VERDICT_REVIEW
                flagged += 1
            f["fp_triage"] = annotation
        return flagged
