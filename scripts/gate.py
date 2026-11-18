#!/usr/bin/env python3
"""Machine-readable escalation gate for parsimony-re.

The five gate fields are a required artifact, not just prose. Record them before
tier 1c/2/3 work, then cite the returned GATE-xxxxxxxx id in the answer. An
escalation without a recorded gate id is a policy violation.

Stdlib only. The log is append-only JSONL, default path from PARSIMONY_GATE_LOG
or ./gate-log.jsonl.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

TIERS = {"1c", "2", "3"}
MIN_LENGTH = 12


def log_path(explicit: str | None) -> Path:
    return Path(explicit or os.environ.get("PARSIMONY_GATE_LOG", "gate-log.jsonl")).expanduser().resolve()


def read_records(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and obj.get("gate_id"):
                out.append(obj)
        except json.JSONDecodeError:
            continue
    return out


def record(args) -> int:
    fields = {
        "unanswered_question": args.question,
        "evidence_gathered": args.evidence,
        "why_cheap_tools_fail": args.why_cheap_fails,
        "backend_adds": args.backend_adds,
        "stop_condition": args.stop_condition,
    }
    problems = []
    for name, value in fields.items():
        if not value or len(value.strip()) < MIN_LENGTH:
            problems.append(f"{name}: required, at least {MIN_LENGTH} characters")
    if args.tier not in TIERS:
        problems.append(f"tier: one of {sorted(TIERS)}")
    if problems:
        print(json.dumps({"valid": False, "problems": problems}, indent=2), file=sys.stderr)
        return 2

    payload = json.dumps({"tier": args.tier, "target": args.target, **fields}, sort_keys=True)
    gate_id = "GATE-" + hashlib.sha256(
        (payload + datetime.now(timezone.utc).isoformat()).encode("utf-8")
    ).hexdigest()[:8]
    entry = {
        "gate_id": gate_id,
        "tier": args.tier,
        "target": args.target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **fields,
    }
    path = log_path(args.log)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    print(json.dumps({"valid": True, "gate_id": gate_id, "log": str(path), **entry}, indent=2, ensure_ascii=False))
    return 0


def check(args) -> int:
    entry = next((r for r in read_records(log_path(args.log)) if r["gate_id"] == args.gate_id), None)
    if entry is None:
        print(json.dumps({"valid": False, "reason": "gate id not found in log", "gate_id": args.gate_id}), file=sys.stderr)
        return 2
    print(json.dumps({"valid": True, "record": entry}, indent=2, ensure_ascii=False))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("action", nargs="?", default="record", choices=["record", "check"])
    ap.add_argument("--log")
    ap.add_argument("--gate-id", help="for check")
    ap.add_argument("--tier", choices=sorted(TIERS))
    ap.add_argument("--target")
    ap.add_argument("--question")
    ap.add_argument("--evidence")
    ap.add_argument("--why-cheap-fails")
    ap.add_argument("--backend-adds")
    ap.add_argument("--stop-condition")
    args = ap.parse_args()
    if args.action == "check":
        if not args.gate_id:
            print("check requires --gate-id", file=sys.stderr)
            return 2
        return check(args)
    return record(args)


if __name__ == "__main__":
    raise SystemExit(main())
