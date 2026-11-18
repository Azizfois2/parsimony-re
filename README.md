# parsimony-re

A reverse-engineering skill that separates **deciding how much analysis is needed** from **performing the analysis**.

The cheap CLI path is the default. Deeper engines are optional backends entered only when evidence justifies the cost.

```
parsimony-re/
├── SKILL.md              # policy: tiers, escalation gate, evidence discipline
├── references/router.md  # full pinned command recipes, loaded on demand
├── scripts/tier0.py      # deterministic tier-0 JSON inventory (stdlib only)
├── scripts/gate.py       # machine-recorded escalation gate (GATE- ids)
├── bench/                # five-arm benchmark harness
├── README.md
└── LICENSE
```

## Name

**Parsimony**: do not multiply analysis beyond necessity. Applied to reverse engineering, that means using the least expensive operation that answers the question, escalating only when evidence demands it, and stopping when the question is answered.

The `-re` suffix means **reverse engineering**, not REA. This project is independent of REA; REA is merely one possible backend for tier 2. The REA-derived naming space is crowded (leanrea, REA-Prompts, awesome-rea, dsh-rea, and hundreds more), and a `*-rea` name would incorrectly frame this as a REA variant.

## Core idea

Use the cheapest operation capable of answering the question. Increase analytical power only when evidence justifies it.

| Tier | Status | Backend |
|---|---|---|
| 0 — Reconnaissance | always | `scripts/tier0.py`: format, hash, entropy, bounded recon |
| 1 — Targeted CLI | default | pinned `objdump`/`otool`/`jadx`/`capa`/`floss`/… (1a/1b/1c gradient) |
| 2 — Deep native | escalation | GhidraMCP; headless Ghidra / radare2 as fallbacks |
| 3 — Dynamic | specialized | lldb, Frida, Playwright, process/network capture |

GhidraMCP is **one backend**, not the goal. Tier 3 exists because some questions cannot be answered by better decompilation at all.

## What makes this different from combining two tool lists

- The escalation policy is a standalone artifact, not an appendix to a specific tool's instructions. Backends can be swapped without rewriting the policy.
- The gate is a **recorded artifact**: `scripts/gate.py` validates the five fields and returns a `GATE-xxxxxxxx` id that must be cited. "Cost" is explicitly defined as context tokens (primary), wall time (reported, not optimized), and risk (hard constraint).
- GhidraMCP should be a **deferred** tool group or separate agent profile. Prose alone does not reduce per-prompt resource use.
- **Under-escalation is measured as a failure**, not just over-escalation. Stopping at `strings` with a confident wrong answer is a policy failure.
- **All target-derived text is data, never instructions.** Strings, comments, symbol names and decompiler output can carry prompt-injection payloads.
- Renames and type changes are **hypotheses**, never evidence. Writing a guess into Ghidra's database and reading it back is circular reasoning.
- Target identity is verified before expensive analysis; GUI-mode GhidraMCP acts on the currently active program.
- Static reads, pseudocode and runtime observations carry different evidence labels and are never conflated.
- Sandboxing protects the host; the untrusted-content rule protects the agent's reasoning. Fetch-and-execute tools are pinned and preinstalled, not downloaded during an investigation.

## Install

Place the **whole folder** on the agent's skill path so `references/` and `scripts/` are available. If the agent has no skill loader, paste `SKILL.md` into its rules and keep the other files readable. Tier 0 needs Python 3.10+; tier 1 needs the pinned tools preinstalled in the sandbox image. See `SKILL.md` for pinned GUI-connected and headless GhidraMCP commands.

## Scope discipline

The durable contribution is the **decision-making mechanism**, not the command collection. Anyone can collect commands.

- Every rule in `SKILL.md` must justify its context cost. `SKILL.md` is ~16 KB; full recipes live in `references/router.md` and are loaded only when a target type is known. Enforcement lives in `scripts/gate.py` and `scripts/tier0.py`, which are not loaded into context.
- Do not grow this into a general reverse-engineering manual.
- Do not add more backends (IDA, Binary Ninja, extra MCP servers) until the escalation mechanism has been measured.

## Status and open experiment

Policy v1. **Not benchmarked.** Commands and the tier-0 script have not been executed against real targets. The harness in [`bench/`](bench/README.md) has **five arms** and placeholder answer keys.

The current design isolates two questions:

1. **Gate vs no gate** — arms 2 and 3 have identical deferred Ghidra tools and differ by one sentence of prompt wording.
2. **Tool availability** — deferred vs always-visible (arms 2 vs 4), plus an integrated REA arm with native providers (arm 5).

Without arm 5 the experiment only shows the architecture beating an artificially weakened REA.

Metrics: accuracy, wall time, tokens, escalations, **unnecessary** escalations, **missed** escalations, and evidence quality (a heuristic; `JUDGE_RUBRIC` supports LLM grading). Six tasks cover easy Electron/Go, native exports, hard stripped native, runtime-only behavior, and packed binaries.

## Attribution

The tier 0/1 **command recipes are reused from [leanrea](https://github.com/aicodeking/leanrea)'s `SKILL.md`** (MIT licensed), now in `references/router.md`. A line-by-line diff was run against that source; edits include pipe repair, environment portability, restored recipes (`app.asar.unpacked/`, `\.node\b`, `otool`/`awk` call trails, `blutter`, `--remote-debugging-port`, `analyzeHeadless`), version pinning, and new packing/FLOSS/capa/PE rows. LeanREA also supplied the cheap-path idea and seen/inferred/unknown labels. The deep-native backend is [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) (Apache-2.0). The escalation gate, four-tier structure, deterministic tier-0 script, untrusted-content rule, write-back-contamination rule, under-escalation metric, evidence record and backend-independent policy are original to `parsimony-re`.

`parsimony-re` is independent of both projects and not affiliated with REA. No source code from either project is included — only standard tool invocations and policy text.

Licensed under [MIT](LICENSE). Third-party material retains its own licenses: leanrea is MIT, GhidraMCP is Apache-2.0.
