#!/usr/bin/env python3
"""Run an expensive CLI escalation only with a verified gate record.

Usage:
  python3 scripts/escalate.py --gate-id GATE-xxxxxxxx -- <command> [args...]

If the gate id is missing, the log chain is broken, or the record cannot be
verified, the command is refused and never executed. This makes the gate a
technical precondition for CLI-based tier 1c/2/3 tools. MCP tool calls cannot
be wrapped by a local script; for those, cite the gate id in the answer and
use a client-side tool group where possible.

Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import sys

from gate import check_gate, log_path
from tier0 import run_command


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--gate-id", required=True)
    ap.add_argument("--log")
    ap.add_argument("--max-output", type=int, default=8192)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("command", nargs=argparse.REMAINDER)
    args = ap.parse_args()

    cmd = [c for c in args.command if c != "--"]
    if not cmd:
        print("escalate: no command supplied after --", file=sys.stderr)
        return 2

    gate = check_gate(args.gate_id, log_path(args.log))
    if not gate["valid"]:
        print(json.dumps({"allowed": False, "reason": gate.get("reason"),
                          "command": cmd}, indent=2), file=sys.stderr)
        return 2

    print(json.dumps({"allowed": True, "gate_id": args.gate_id,
                      "tier": gate["record"]["tier"], "command": cmd},
                     indent=2, ensure_ascii=False))
    result = run_command(cmd[0], cmd[1:], max_bytes=args.max_output, timeout=args.timeout)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if not result.get("available"):
        return 127
    if result.get("timeout"):
        return 124
    return int(result.get("exit_code") or 0)


if __name__ == "__main__":
    raise SystemExit(main())
