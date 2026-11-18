# parsimony-re benchmark scaffold

Four-arm experiment to test whether the escalation policy changes agent behavior, rather than merely looking good on paper.

```
bench/
├── README.md              this file
├── arms.json              arm definitions (agent command, skill, MCP config, prompt)
├── tasks.json             task set, target paths, answer keys, escalation labels
├── configs/
│   ├── ghidra.json        GhidraMCP server registration
│   └── rea.json           REA MCP registration (npx -y rea-agents@6.9.0 mcp)
├── run.py                 runs agent CLI per task × arm × rep, captures transcripts
├── score.py               grades answers, aggregates metrics, writes summary
├── results/               generated (gitignored)
└── .gitignore
```

## Arms

| # | Arm | What it isolates |
|---|---|---|
| 1 | `leanrea` | Baseline cheap-path workflow |
| 2 | `leanrea_deferred_ghidra` | Escalation available but deferred |
| 3 | `leanrea_always_ghidra` | Escalation visible in every prompt |
| 4 | `rea_native` | Integrated system with native providers actually enabled |

Arm 4 is essential. Without it the experiment only shows parsimony-re beating a weakened REA.

Arms 2 and 3 use the **same** MCP config file. Their difference is a client-level discovery setting, not a config file. Set `BENCH_ALWAYS_ARGS` to whatever your client needs to disable deferred/on-demand tool discovery; `run.py` appends it to arm 3 only. If your client has no such switch, use two separate agent profiles and encode the difference in each arm's `command`.

## Metrics

- **accuracy** — regex answer keys in `tasks.json`
- **wall time**, **tokens**, **cost**, **turns** — from the agent's JSON output where available
- **escalations** — count of `mcp__ghidra__*` tool calls in the transcript
- **unnecessary escalations** — Ghidra calls on tasks marked `cheap_answer_sufficient: true`
- **evidence quality** — heuristic proxy: presence of Seen/Inferred/Unknown labels, anchors, and stated limitations

Evidence quality is a **proxy**, not ground truth. For a real claim, grade it with a judge model using the rubric in `score.py` (`JUDGE_RUBRIC`).

## Prerequisites

- Python 3.10+
- The agent CLI used in `arms.json` (default: Claude Code `claude -p`)
- Targets installed locally and paths set in `tasks.json`
- Ghidra 12.1.4 + GhidraMCP plugin for arms 2/3
- REA plus at least one native provider (Ghidra/IDA/Hopper/Kuna) for arm 4
- `BENCH_TARGETS` environment variable pointing at the target root, or pass `--targets-root`

This scaffold was authored on Windows but assumes POSIX-style target setup commands. Use WSL2 for those, or replace `setup` strings with PowerShell equivalents. Add `--shell` to `run.py` if your agent command needs a shell invocation.

## Important: answer keys are placeholders

`tasks.json` ships with example tasks and **placeholder regexes** (`"placeholder": true`). `score.py` refuses to score those tasks and reports them as unscored. You must create hand-made keys for your own target versions — a regex against the wrong app version is worse than no score.

## Run

```sh
python run.py --dry-run                    # print all commands, execute nothing
python run.py --reps 3 --out results/run1
python score.py --out results/run1
```

Useful options:

```
--arm NAME          run one arm
--task ID           run one task
--reps N            repetitions per cell (default 3)
--timeout SECONDS   per-run timeout (default 900)
--shell             join command with shell=True (Windows-friendly)
--out DIR           results directory; existing result files are skipped (resume)
```

Each target gets a fresh working copy per run, matching the original benchmark's methodology. Raw agent output is preserved under `results/<out>/transcripts/`.

## What this does not do

- It does not install targets, Ghidra, REA, or the skills.
- It does not verify that arms 2 and 3 actually differ in tool visibility. Check this manually before trusting the comparison.
- It does not execute the targets unless a task's `setup` or a dynamic task's prompt tells the agent to. Sandbox untrusted targets.
