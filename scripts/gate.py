#!/usr/bin/env python3
"""Machine-recorded escalation gate for parsimony-re.

The five gate fields are a required artifact, not just prose. Records are
hash-chained so editing or deleting an earlier entry is detectable. `check`
verifies the chain and the gate id; `verify` checks the whole log.

Stdlib only. Log path: PARSIMONY_GATE_LOG or ./gate-log.jsonl.
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
GENESIS = "0" * 64


def log_path(explicit: str | None) -> Path:
    return Path(explicit or os.environ.get("PARSIMONY_GATE_LOG", "gate-log.jsonl")).expanduser().resolve()


def canonical(entry: dict) -> str:
    return json.dumps({k: v for k, v in entry.items() if k != "record_hash"},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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


def verify_chain(records: list[dict]) -> dict:
    expected_prev = GENESIS
    for i, entry in enumerate(records):
        claimed = entry.get("record_hash")
        if claimed != digest(canonical(entry)):
            return {"valid": False, "reason": "record_hash mismatch", "index": i}
        if entry.get("prev_hash") != expected_prev:
            return {"valid": False, "reason": "prev_hash chain broken", "index": i}
        expected_prev = claimed
    return {"valid": True, "records": len(records)}


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

    records = read_records(log_path(args.log))
    chain = verify_chain(records)
    if not chain["valid"]:
        print(json.dumps({"valid": False, "reason": "existing gate log is corrupted", "chain": chain},
                         indent=2), file=sys.stderr)
        return 2

    entry = {
        "gate_id": "GATE-" + hashlib.sha256(
            (json.dumps(fields, sort_keys=True) + datetime.now(timezone.utc).isoformat()).encode("utf-8")
        ).hexdigest()[:8],
        "tier": args.tier,
        "target": args.target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "prev_hash": records[-1]["record_hash"] if records else GENESIS,
        **fields,
    }
    entry["record_hash"] = digest(canonical(entry))
    path = log_path(args.log)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    print(json.dumps({"valid": True, **entry}, indent=2, ensure_ascii=False))
    return 0


def check_gate(gate_id: str, path: Path) -> dict:
    records = read_records(path)
    chain = verify_chain(records)
    if not chain["valid"]:
        return {"valid": False, "reason": "gate log integrity check failed", "chain": chain}
    entry = next((r for r in records if r["gate_id"] == gate_id), None)
    if entry is None:
        return {"valid": False, "reason": "gate id not found in log", "gate_id": gate_id}
    return {"valid": True, "record": entry, "chain": chain}


def check(args) -> int:
    result = check_gate(args.gate_id, log_path(args.log))
    print(json.dumps(result, indent=2, ensure_ascii=False),
          file=sys.stdout if result["valid"] else sys.stderr)
    return 0 if result["valid"] else 2


def verify(args) -> int:
    result = verify_chain(read_records(log_path(args.log)))
    print(json.dumps(result, indent=2, ensure_ascii=False),
          file=sys.stdout if result["valid"] else sys.stderr)
    return 0 if result["valid"] else 2


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("action", nargs="?", default="record", choices=["record", "check", "verify"])
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
    if args.action == "verify":
        return verify(args)
    return record(args)


if __name__ == "__main__":
    raise SystemExit(main())
