# parsimony-re benchmark scaffold

Five-arm experiment testing two separate questions:

1. **Does the escalation-gate wording change behavior?** Isolated by arms 2 vs 3, which have identical tools and differ only by one sentence in the prompt.
2. **Does tool availability change behavior?** Isolated by arms 2 vs 4 (deferred vs always-visible) and by arm 5 (an integrated system).

```
bench/
├── README.md              this file
├── arms.json              arm definitions (command, skill, MCP config, prompt)
├── tasks.json             targets, answer keys, cheap/deep/runtime flags
├── configs/
│   ├── ghidra.json        GhidraMCP pinned to the 2.0 commit
│   └── rea.json           REA MCP pinned to rea-agents@6.9.0
├── run.py                 runs agent CLI per task x arm x rep, captures transcripts
├── score.py               grades answers, aggregates metrics, writes summary
├── results/               generated (gitignored)
└── .gitignore
```

## Arms

| # | Arm | Gate wording | Tool visibility | What it isolates |
|---|---|---|---|---|
| 1 | `leanrea` | no | none | cheap-path baseline |
| 2 | `leanrea_deferred_ghidra` | **yes** | deferred | gate + on-demand escalation |
| 3 | `leanrea_no_gate` | **no** | deferred | **gate-isolation control vs arm 2** |
| 4 | `leanrea_always_ghidra` | yes | all tools visible | cost of always-visible tools |
| 5 | `rea_native` | no (its own policy) | REA MCP | integrated system with native providers |

Arm 5 is essential: without it the experiment only shows parsimony-re beating a weakened REA.

Arms 2, 3 and 4 use the same pinned MCP config. Their differences are prompt wording and a client-level discovery setting. Set `BENCH_ALWAYS_ARGS` to whatever your client needs to disable deferred tool discovery; `run.py` appends it to arm 4 only. If your client has no such switch, use two profiles and encode the difference in each arm's `command`.

Verify manually that arms 2 and 4 actually differ in tool visibility — the harness cannot prove it.

## Metrics

- **accuracy** — regex answer keys in `tasks.json`
- **wall time**, **tokens**, **cost**, **turns** — from agent JSON output where available
- **gate compliance** — answers containing a recorded `GATE-xxxxxxxx` id from `scripts/gate.py`
- **deep calls** — `mcp__ghidra__*` tool calls plus CLI deep tools (`r2`, `analyzeHeadless`, `jadx`, `binwalk`, `unblob`, `ilspycmd`) detected in transcripts
- **runtime actions** — `frida`, `lldb -p`, `dtrace`, `adb logcat`, remote debugging detected in transcripts
- **unnecessary escalations** — Ghidra calls on tasks flagged `cheap_answer_sufficient: true`
- **missed escalations** — tasks flagged `requires_deep: true` where no deep tool was called **and** the answer scored below full marks; this measures confident under-escalation
- **evidence quality** — heuristic proxy: labels, anchors, stated limitations

Both escalation directions are now measured. A parsimony policy can fail by stopping too early, so over-escalation alone was an asymmetric metric.

CLI deep and runtime actions are detected by regex over the preserved transcript (`cli_deep_actions` / `cli_runtime_actions` in each result). This is broader than MCP tool names but can miss aliases or indirect calls; spot-check transcripts. Evidence quality is a **proxy**, not ground truth — use `JUDGE_RUBRIC` in `score.py` with a judge model for a real claim.

## Tasks

Six tasks: easy Electron, Go metadata, native exports, hard stripped native, a runtime-only question, and a packed sample (entropy/packer detection before trusting strings or decompiling). Each has `cheap_answer_sufficient`, `requires_deep` and `requires_runtime` flags.

## Prerequisites

- Python 3.10+
- The agent CLI in `arms.json` (default: Claude Code `claude -p`)
- Targets installed locally, paths set in `tasks.json`
- Ghidra 12.1.4 + GhidraMCP 2.0 plugin for arms 2–4
- REA plus at least one native provider for arm 5
- `BENCH_TARGETS` pointing at the target root, or pass `--targets-root`

The scaffold was authored on Windows but assumes POSIX setup commands. Use WSL2, PowerShell equivalents, or `--shell`.

## Important: answer keys are placeholders

All keys in `tasks.json` are marked `"placeholder": true`. `score.py` refuses to score those tasks and reports them as unscored. Build keys for your exact target versions.

## Run

```sh
python run.py --dry-run
python run.py --reps 5 --out results/run1
python score.py --out results/run1
```

Options:

```
--arm NAME          run one arm
--task ID           run one task
--reps N            repetitions per cell (default 5)
--timeout SECONDS   per-run timeout (default 900)
--shell             join command with shell=True (Windows-friendly)
--no-copy           use targets in place instead of copying
--out DIR           results directory; existing result files are skipped (resume)
```

Fresh target copies per run match the original methodology. Raw output is under `results/<out>/transcripts/`.

## Holdout set

Results on these six tasks are hypothesis-generating only — see [`HOLDOUT.md`](HOLDOUT.md) for the protocol to build an independent task set before making claims.

## What this does not do

- Install targets, Ghidra, REA or the skills.
- Prove arms 2 and 4 differ in tool visibility.
- Execute targets unless a task's setup or prompt calls for it. Sandbox untrusted targets.
- Guarantee CLI-action detection is complete; regex matching can miss aliases. Spot-check transcripts.
