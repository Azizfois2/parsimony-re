#!/usr/bin/env python3
"""Run the parsimony-re benchmark (five arms, including a gate-isolation control).

Executes agent CLI once per task x arm x rep, in a fresh target copy, and
writes one JSON result per run plus the raw transcript.

Stdlib only. See README.md for prerequisites and caveats.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from string import Template

HERE = Path(__file__).resolve().parent


def load_json(path: Path):
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def subst(value, env: dict):
    """Recursively substitute $PLACEHOLDER in strings."""
    if isinstance(value, str):
        return Template(value).safe_substitute(env)
    if isinstance(value, list):
        return [subst(v, env) for v in value]
    if isinstance(value, dict):
        return {k: subst(v, env) for k, v in value.items()}
    return value


def build_prompt(task: dict, arm: dict, target_str: str) -> str:
    parts = []
    if arm.get("skill_command"):
        parts.append(f"Invoke the skill {arm['skill_command']} before starting this task.")
    if arm.get("prompt_prefix"):
        parts.append(arm["prompt_prefix"])
    parts.append(f"TASK: {task['question']}")
    parts.append(f"TARGET: {target_str}")
    if task.get("output_shape"):
        parts.append(f"OUTPUT: {task['output_shape']}")
    parts.append(
        "RULES: Label each claim Seen, Inferred, or Unknown. Cite an anchor for every "
        "fact. State limitations explicitly. Never claim runtime behavior from static "
        "reading alone. Stop when every requested fact has evidence."
    )
    return "\n\n".join(parts)


def extract_tool_calls(text: str) -> list[str]:
    names = []
    for m in re.finditer(r'"type"\s*:\s*"tool_use"', text):
        chunk = text[m.start():m.start() + 500]
        n = re.search(r'"name"\s*:\s*"([^"]+)"', chunk)
        if n:
            names.append(n.group(1))
    return names


def parse_agent_output(stdout: str):
    answer = stdout
    usage = {}
    stripped = stdout.strip()
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                candidate = (
                    obj.get("result")
                    or obj.get("output")
                    or obj.get("output_text")
                    or obj.get("content")
                )
                if candidate is not None:
                    answer = candidate
                usage = obj.get("usage") or obj.get("metrics") or {}
        except json.JSONDecodeError:
            pass
    if isinstance(answer, (dict, list)):
        answer = json.dumps(answer, indent=2, ensure_ascii=False)
    turns = len(re.findall(r'"type"\s*:\s*"assistant"', stdout))
    return answer, usage, extract_tool_calls(stdout), turns


def prepare_target(task: dict, work_root: Path, targets_root: Path, copy: bool):
    rel = task.get("target")
    if not rel:
        return None
    src = Path(rel)
    if not src.is_absolute():
        src = targets_root / rel
    if not src.exists():
        return src
    if not copy:
        return src
    dst = work_root / task["id"]
    if src.is_dir():
        shutil.copytree(src, dst, dirs_exist_ok=True)
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return dst


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tasks", default=str(HERE / "tasks.json"))
    ap.add_argument("--arms", default=str(HERE / "arms.json"))
    ap.add_argument("--targets-root", default=os.environ.get("BENCH_TARGETS", "."))
    ap.add_argument("--out", default=str(HERE / "results" / "run"))
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--arm", help="run only this arm name")
    ap.add_argument("--task", help="run only this task id")
    ap.add_argument("--dry-run", action="store_true", help="print commands, execute nothing")
    ap.add_argument("--shell", action="store_true", help="join command with shell=True")
    ap.add_argument("--no-copy", action="store_true", help="use target in place instead of copying")
    args = ap.parse_args()

    tasks = load_json(Path(args.tasks))["tasks"]
    arms = load_json(Path(args.arms))["arms"]
    if args.task:
        tasks = [t for t in tasks if t["id"] == args.task]
    if args.arm:
        arms = [a for a in arms if a["name"] == args.arm]
    if not tasks or not arms:
        print("No tasks or arms selected.", file=sys.stderr)
        return 2

    targets_root = Path(args.targets_root).resolve()
    out = Path(args.out).resolve()
    (out / "transcripts").mkdir(parents=True, exist_ok=True)

    planned = args.reps * len(tasks) * len(arms)
    print(f"Planned runs: {planned} ({len(tasks)} tasks x {len(arms)} arms x {args.reps} reps)")

    completed = 0
    for rep in range(1, args.reps + 1):
        for task in tasks:
            for arm in arms:
                run_id = f"{task['id']}__{arm['name']}__rep{rep}"
                result_path = out / f"{run_id}.json"
                if result_path.exists():
                    print(f"skip  {run_id} (exists)")
                    continue

                work = out / "work" / run_id
                work.mkdir(parents=True, exist_ok=True)
                target = prepare_target(task, work, targets_root, not args.no_copy)
                target_str = str(target) if target else "none"
                prompt = build_prompt(task, arm, target_str)

                mcp_path = None
                if arm.get("mcp_config"):
                    mcp_path = (HERE / arm["mcp_config"]).resolve()
                envmap = {
                    "PROMPT": prompt,
                    "MCP_CONFIG": str(mcp_path) if mcp_path else "",
                    "WORK": str(work),
                    "TARGET": target_str,
                }
                cmd = subst(arm["command"], envmap)
                extra_env = arm.get("extra_args_env")
                if extra_env and os.environ.get(extra_env):
                    cmd += shlex.split(os.environ[extra_env])

                if args.dry_run:
                    print(f"DRY   {run_id}\n  cmd: {cmd}\n  prompt: {prompt[:160]}...")
                    continue

                if target and not target.exists():
                    print(f"WARN  {run_id}: target not found: {target}")

                if task.get("setup"):
                    setup_cmd = subst(task["setup"], envmap)
                    setup_str = setup_cmd if isinstance(setup_cmd, str) else shlex.join(setup_cmd)
                    subprocess.run(
                        setup_str, shell=True, cwd=work, capture_output=True, text=True, check=False
                    )

                env = os.environ.copy()
                env.update(arm.get("env") or {})
                started = time.monotonic()
                timeout_hit = False
                try:
                    if args.shell:
                        proc = subprocess.run(
                            shlex.join(cmd), shell=True, cwd=work, env=env,
                            capture_output=True, text=True, timeout=args.timeout,
                        )
                        stdout, stderr, code = proc.stdout, proc.stderr, proc.returncode
                    else:
                        proc = subprocess.run(
                            cmd, cwd=work, env=env, capture_output=True, text=True,
                            timeout=args.timeout,
                        )
                        stdout, stderr, code = proc.stdout, proc.stderr, proc.returncode
                except subprocess.TimeoutExpired as e:
                    timeout_hit = True
                    stdout = e.stdout or ""
                    stderr = e.stderr or ""
                    if isinstance(stdout, bytes):
                        stdout = stdout.decode("utf-8", "replace")
                    if isinstance(stderr, bytes):
                        stderr = stderr.decode("utf-8", "replace")
                    code = None
                wall = time.monotonic() - started

                answer, usage, tool_calls, turns = parse_agent_output(stdout)
                record = {
                    "run_id": run_id,
                    "task": task["id"],
                    "arm": arm["name"],
                    "rep": rep,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "command": cmd,
                    "target": target_str,
                    "exit_code": code,
                    "timeout": timeout_hit,
                    "wall_s": round(wall, 3),
                    "answer": answer,
                    "stderr": stderr[-4000:],
                    "usage": usage,
                    "turns_proxy": turns,
                    "tool_calls": tool_calls,
                }
                with result_path.open("w", encoding="utf-8") as f:
                    json.dump(record, f, indent=2, ensure_ascii=False)
                (out / "transcripts" / f"{run_id}.txt").write_text(
                    f"=== STDOUT ===\n{stdout}\n\n=== STDERR ===\n{stderr}",
                    encoding="utf-8",
                )
                completed += 1
                print(f"done  {run_id}  {wall:.1f}s  {len(tool_calls)} tool calls  exit={code}")

    print(f"Completed {completed} new runs. Results: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
