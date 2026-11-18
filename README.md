# parsimony-re

A reverse-engineering skill that separates **deciding how much analysis is needed** from **performing the analysis**.

The cheap CLI path is the default. Deeper engines are optional backends entered only when evidence justifies the cost.

```
parsimony-re/
├── SKILL.md   # the skill: routing, escalation policy, backend contracts
└── README.md  # this file
```

## Name

**Parsimony**: do not multiply analysis beyond necessity. The law of parsimony applied to reverse engineering is exactly the policy here — use the least expensive operation that answers the question, escalate only when evidence demands it, and stop when the question is answered.

The `-re` suffix means **reverse engineering**, not REA. This project is independent of REA; REA is merely one possible backend for tier 2. The REA-derived naming space is crowded (leanrea, REA-Prompts, awesome-rea, dsh-rea, and hundreds more), and a `*-rea` name would incorrectly frame this as a REA variant.

## Core idea

Use the cheapest operation capable of answering the question. Increase analytical power only when evidence justifies it.

| Tier | Status | Backend |
|---|---|---|
| 0 — Reconnaissance | always | `file`, `strings`, `nm`, hashes |
| 1 — Targeted CLI | default | `objdump`, `otool`, `jadx`, `apktool`, `tshark`, `binwalk`, radare2… (with its own 1a/1b/1c cost gradient) |
| 2 — Deep native | escalation | GhidraMCP, or headless Ghidra / radare2 as fallback |
| 3 — Dynamic | specialized | lldb, Frida, Playwright, process/network capture |

GhidraMCP is **one backend**, not the goal. Tier 3 exists because some questions cannot be answered by better decompilation at all.

## What makes this different from combining two tool lists

- The escalation policy is a standalone artifact, not an appendix to a specific tool's instructions. Backends can be swapped without rewriting the policy.
- GhidraMCP should be a **deferred** tool group or a separate agent profile. "Use it only when needed" as prose does not reduce per-prompt resource use; a deferred tool group does.
- Renames and type changes are treated as **hypotheses**, never as evidence. Writing a guess into Ghidra's database and then reading it back is circular reasoning, and the skill explicitly forbids it.
- Target identity (`get_program_info`, architecture, hash) is verified before any expensive analysis, because GUI-mode GhidraMCP acts on the currently active program.
- Static read, decompiled pseudocode, and runtime observation carry different evidence labels and are never silently conflated.
- Unknown binaries are handled in a sandbox. "Work on a copy" protects the input; isolation protects the host.

## Install

Place `SKILL.md` on your agent's skill path, or paste it into the agent's rules/system prompt if it has no skill loader. Tier 0/1 need no installation. See the Install section of `SKILL.md` for the distinct GUI-connected and headless GhidraMCP commands.

## Scope discipline

The durable contribution is the **decision-making mechanism**, not the command collection. Anyone can collect commands. What matters is knowing when cheap analysis is sufficient, when deeper analysis is justified, and when even deeper analysis cannot establish the answer.

Consequently:

- Every new rule must justify its context cost. The skill is ~14 KB; size is acceptable only while each line changes agent behavior.
- Do not grow this into a general reverse-engineering manual.
- Do not add more backends (IDA, Binary Ninja, extra MCP servers) until the escalation mechanism has been measured.

## Status and open experiment

Policy v1. **Not benchmarked.** GhidraMCP headless, PowerShell equivalents and the router commands have been corrected but not yet executed against sample files. A runnable four-arm harness now lives in [`bench/`](bench/README.md); its answer keys are placeholders that must be replaced for your targets.

Measure before claiming superiority. Four arms on the same task set:

1. LeanREA alone.
2. LeanREA + **deferred** GhidraMCP.
3. LeanREA + **always-available** GhidraMCP.
4. REA with native providers actually installed and enabled.

Arm 4 matters: without it, the experiment only shows the architecture beating an artificially weakened REA rather than a real one.

Metrics: accuracy, wall time, token consumption, number of escalations, **unnecessary** escalations (Ghidra invoked when strings/imports would have sufficed), and evidence quality (provenance, limitations, correct labels).

Task set should include easy Electron, Go and Mach-O cases alongside genuinely difficult stripped native binaries and at least one case that requires runtime observation to answer.

## Attribution

The tier 0/1 **command set is reused from [leanrea](https://github.com/aicodeking/leanrea)'s `SKILL.md`** (MIT licensed). A line-by-line diff was run against that source; edits consist of pipe repair after a table-to-code-block move, environment-portability notes, restored recipes that had been dropped in drafting (`app.asar.unpacked/`, the `\.node\b` matcher, the `otool`/`awk` call-trail readers, `blutter`, `--remote-debugging-port`, the full `analyzeHeadless` fallback), one deliberate expansion (`jq .main` → `jq '{name,version,main}'`), and explicit tier-1 cost labels. LeanREA also supplied the cheap-path routing idea and the seen/inferred/unknown discipline. The optional deep-native backend is [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) (Apache-2.0). The escalation gate, four-tier structure, evidence record, write-back-contamination rule, and backend-independent policy are original to `parsimony-re`.

`parsimony-re` is independent of both projects and is not affiliated with REA. This folder contains no source code from either project — only standard tool invocations and policy text.

Licensed under [MIT](LICENSE). Third-party material retains its own licenses: leanrea is MIT, GhidraMCP is Apache-2.0.
