#!/usr/bin/env python3
"""Grade parsimony-re benchmark results and write summary.json / summary.md.

Accuracy uses the regex keys in tasks.json. Placeholder keys are never scored.
Evidence quality is a heuristic PROXY (see JUDGE_RUBRIC for a real judge prompt).
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent

JUDGE_RUBRIC = """Grade the answer on each point, 0 or 1, and explain briefly.

1. Every factual claim is labeled Seen, Inferred, or Unknown.
2. Each Seen claim cites a real anchor (file:offset, address, symbol, captured output).
3. Inferred claims show the reasoning chain and are not presented as observations.
4. Limitations and unknowns are stated instead of silently filled in.
5. Decompiler pseudocode is treated as inference, never as original source code.
6. No renamed symbol is cited as evidence for the hypothesis that caused the rename.
7. Runtime claims are backed by captured observation, not static reading.
8. The answer stops when the requested facts are answered; no unrelated analysis is reported.
"""

LABEL_RE = re.compile(r"\b(seen|inferred|unknown)\b", re.I)
ANCHOR_RE = re.compile(
    r"(0x[0-9a-fA-F]+|\bfile\s*:\s*\d+|\bline\s*\d+|\baddr(ess)?\s*[:=]|"
    r"\b(rg|nm|otool|readelf|objdump|tshark|sqlite3|asar|jadx|frida|lldb|asar)\b)",
    re.I,
)
LIMIT_RE = re.compile(
    r"\b(unknown|not observed|cannot establish|limitation|inferred|unverified|"
    r"no evidence|static analysis|not proven)\b",
    re.I,
)


def load_json(path: Path):
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def pick(usage: dict, *keys):
    if not isinstance(usage, dict):
        return None
    for k in keys:
        v = usage.get(k)
        if v is not None:
            return v
    return None


def mean(values):
    vals = [v for v in values if v is not None]
    return statistics.fmean(vals) if vals else None


def med(values):
    vals = [v for v in values if v is not None]
    return statistics.median(vals) if vals else None


def grade_answer(task: dict, answer: str):
    keys = [k for k in task.get("answer_keys", []) if not k.get("placeholder")]
    if not keys:
        return None, None, []
    hits = 0
    detail = []
    for k in keys:
        ok = bool(re.search(k["pattern"], answer, re.I))
        hits += int(ok)
        detail.append({"key": k["name"], "matched": ok})
    return hits, len(keys), detail


def evidence_proxy(answer: str):
    labels = set(m.group(1).lower() for m in LABEL_RE.finditer(answer))
    has_anchor = bool(ANCHOR_RE.search(answer))
    has_limit = bool(LIMIT_RE.search(answer))
    score = int(has_anchor) + int(has_limit) + int(len(labels) >= 2)
    return {
        "labels_present": sorted(labels),
        "has_anchor": has_anchor,
        "has_limitation": has_limit,
        "score_0_3": score,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, help="results directory produced by run.py")
    ap.add_argument("--tasks", default=str(HERE / "tasks.json"))
    args = ap.parse_args()

    out = Path(args.out).resolve()
    tasks = {t["id"]: t for t in load_json(Path(args.tasks))["tasks"]}
    candidates = [load_json(p) for p in sorted(out.glob("*.json")) if p.name != "summary.json"]
    results = [r for r in candidates if isinstance(r, dict) and r.get("run_id")]
    if not results:
        print(f"No result JSON files in {out}", file=sys.stderr)
        return 2

    by_arm = defaultdict(list)
    examined = 0
    unscored = 0

    for r in results:
        task = tasks.get(r.get("task"), {"answer_keys": [], "cheap_answer_sufficient": False})
        answer = r.get("answer") or ""
        hits, possible, detail = grade_answer(task, answer)
        if hits is None:
            unscored += 1
        ev = evidence_proxy(answer)
        ghidra_calls = [c for c in r.get("tool_calls", []) if c.startswith("mcp__ghidra")]
        rea_calls = [c for c in r.get("tool_calls", []) if c.startswith("mcp__rea")]
        usage = r.get("usage") or {}
        row = {
            "run_id": r.get("run_id"),
            "task": r.get("task"),
            "arm": r.get("arm"),
            "rep": r.get("rep"),
            "wall_s": r.get("wall_s"),
            "turns": r.get("turns_proxy"),
            "tokens": pick(usage, "total_tokens", "input_tokens", "tokens"),
            "cost": pick(usage, "total_cost_usd", "cost_usd", "cost"),
            "score_hits": hits,
            "score_possible": possible,
            "key_detail": detail,
            "evidence": ev,
            "ghidra_calls": len(ghidra_calls),
            "rea_calls": len(rea_calls),
            "unnecessary_escalation": bool(ghidra_calls) and bool(task.get("cheap_answer_sufficient")),
            "missed_escalation": bool(task.get("requires_deep")) and not ghidra_calls
                                 and hits is not None and hits < possible,
            "timeout": r.get("timeout", False),
        }
        by_arm[r.get("arm", "unknown")].append(row)
        examined += 1

    arms_summary = {}
    for arm, rows in sorted(by_arm.items()):
        scored = [r for r in rows if r["score_hits"] is not None]
        arms_summary[arm] = {
            "runs": len(rows),
            "scored_runs": len(scored),
            "score": f"{sum(r['score_hits'] for r in scored)}/{sum(r['score_possible'] for r in scored)}",
            "median_wall_s": med([r["wall_s"] for r in rows]),
            "mean_turns": mean([r["turns"] for r in rows]),
            "mean_tokens": mean([r["tokens"] for r in rows]),
            "mean_cost": mean([r["cost"] for r in rows]),
            "mean_ghidra_calls": mean([r["ghidra_calls"] for r in rows]),
            "runs_with_escalation": sum(r["ghidra_calls"] > 0 for r in rows),
            "unnecessary_escalations": sum(r["unnecessary_escalation"] for r in rows),
            "missed_escalations": sum(r["missed_escalation"] for r in rows),
            "mean_evidence_proxy": mean([r["evidence"]["score_0_3"] for r in rows]),
            "timeouts": sum(r["timeout"] for r in rows),
            "by_task": {
                t: {
                    "score": f"{sum(r['score_hits'] for r in rs if r['score_hits'] is not None)}/"
                             f"{sum(r['score_possible'] for r in rs if r['score_hits'] is not None)}",
                    "mean_ghidra_calls": mean([r["ghidra_calls"] for r in rs]),
                    "median_wall_s": med([r["wall_s"] for r in rs]),
                }
                for t in sorted({r["task"] for r in rows})
                for rs in [[r for r in rows if r["task"] == t]]
            },
        }

    all_rows = [r for rows in by_arm.values() for r in rows]
    summary = {
        "results_dir": str(out),
        "runs_examined": examined,
        "unscored_runs": unscored,
        "note": "Evidence quality is a heuristic proxy. See JUDGE_RUBRIC for LLM judging. "
                "Deep-tool use is counted from MCP tool names only; CLI deep tools (r2, jadx, binwalk) "
                "are not visible in tool_calls and must be judged from transcripts.",
        "arms": arms_summary,
        "rows": sorted(all_rows, key=lambda x: x["run_id"]),
    }
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    lines = ["# Benchmark summary", "", f"Runs examined: {examined} (unscored: {unscored})", ""]
    lines.append("| Arm | Score | Median wall | Turns | Tokens | Cost | Ghidra calls | Unnecessary | Missed | Evidence proxy |")
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for arm, s in arms_summary.items():
        def f(v, suffix=""):
            return "—" if v is None else f"{v:.2f}{suffix}"
        lines.append(
            f"| {arm} | {s['score']} | {f(s['median_wall_s'], 's')} | {f(s['mean_turns'])} | "
            f"{f(s['mean_tokens'])} | {'$' + f(s['mean_cost']) if s['mean_cost'] is not None else '—'} | {f(s['mean_ghidra_calls'])} | "
            f"{s['unnecessary_escalations']} | {s['missed_escalations']} | {f(s['mean_evidence_proxy'])} |"
        )
    lines += ["", "## Per task", ""]
    for arm, s in arms_summary.items():
        lines.append(f"### {arm}")
        lines.append("")
        lines.append("| Task | Score | Ghidra calls | Median wall |")
        lines.append("|---|---|---:|---:|")
        for t, v in s["by_task"].items():
            calls = "—" if v["mean_ghidra_calls"] is None else f"{v['mean_ghidra_calls']:.2f}"
            wall = "—" if v["median_wall_s"] is None else f"{v['median_wall_s']:.1f}s"
            lines.append(f"| {t} | {v['score']} | {calls} | {wall} |")
        lines.append("")
    lines += [
        "## Judge rubric (for LLM grading)", "",
        "```text", JUDGE_RUBRIC.rstrip(), "```", "",
        "Evidence proxy columns above are heuristics, not judge scores. "
        "Deep-tool use is counted from MCP tool names only; inspect transcripts for CLI deep tools.",
    ]
    md = "\n".join(lines)
    (out / "summary.md").write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main())
