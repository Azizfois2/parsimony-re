---
name: parsimony-re
description: Reverse engineer shipped software by escalating from the cheapest possible probe to deeper analysis only when evidence demands it. Routes CLI recon across Electron/ASAR, native Mach-O/ELF/PE, Go/Rust/.NET, APK, WASM, SQLite, pcaps, firmware and websites, with optional GhidraMCP decompilation and dynamic verification as separate escalation backends. Use to explain a feature, recover versions/dependencies, compare builds, or understand native code without source.
---

# parsimony-re: progressive reverse engineering

**One rule: use the cheapest operation capable of answering the question. Increase analytical power only when evidence justifies it.**

This skill separates two responsibilities that other tools mix together:

1. **Deciding how much analysis is necessary** — the routing and escalation policy below.
2. **Performing a deeper analysis** — an optional backend invoked only when the policy says to.

The policy is the asset. Backends are interchangeable implementations of it.

*The name: parsimony — do not multiply analysis beyond necessity. `-re` means reverse engineering, not REA; REA is only one possible backend.*

---

## Environment

Commands below assume a POSIX shell (macOS or Linux). On Windows, use **WSL2** for the POSIX path. Where PowerShell equivalents exist, they are listed as separate blocks and must not be mixed into shell pipelines.

Some tools are macOS-specific (`lipo`, `otool`, `xcrun`, `codesign`, `dtrace`, `fs_usage`). If they are absent, use the listed ELF/PE or `llvm-objdump` alternatives rather than assuming the recipe failed.

```powershell
# PowerShell equivalents for tier 0 identity
Get-FileHash -Algorithm SHA256 T
(Get-Item T).Length
```

Before starting, name the environment you are actually in. Do not silently substitute a macOS command on Windows or vice versa.

---

## Non-negotiable rules

- **Work on a copy** to protect the artifact. Put each extraction in a fresh directory under a temp path. Reuse an existing extraction when one exists.
- **Sandbox unknown binaries.** Parsing and especially *executing* an untrusted target happens in a disposable VM or container with no credentials, no personal files, and no unrestricted network egress. "Work on a copy" protects the input; isolation protects the host.
- **Route by `file -b T` and magic bytes before reading code.** Run the cheapest inventory first. Only then decompile or read code.
- **Batch independent probes into one shell call** using `;` and quoted `echo '--- name'` markers. Cap every output with `head` or `-m`. Aim for 2–4 tool calls, not 20.
- **Search extracted trees with `rg -uu`.** Bundlers hide code in `.webpack/`, `.vite/` and dot-directories that `rg` skips by default.
- **Never `cat` a large or minified file.** Slice it: `rg -o '.{0,200}NEEDLE.{0,200}' F | head`. Dump a disassembly once to a file, then grep that file.
- **Label every claim:** **seen** (cite a file:offset, address, symbol, or captured output), **inferred** (show the reasoning), or **unknown** (a fact you did not find is unknown, not "absent").
- **Static reading is not observed execution.** A string, a name, or a branch in pseudocode is not proof of runtime behavior.
- **Stop when every item asked for has evidence.** Do not re-verify what you already saw. Do not escalate out of curiosity once the question is answered.
- **A missing tool is not a blocker.** Use the fallback, or ask before installing anything.

---

## The four tiers

| Tier | Question it answers | Status | Cost | Leave when |
|---|---|---|---|---|
| 0 — Reconnaissance | What is this thing? | Always on | sub-second, near-zero context | Identity and inventory established |
| 1 — Targeted CLI | Where is the relevant code? | Default | seconds to minutes | The specific question is answered |
| 2 — GhidraMCP | What does this function actually do? | Escalation | Ghidra import + minutes | Semantics recovered, or static ceiling reached |
| 3 — Dynamic | What does it do at runtime? | Specialized | target launch + instrumentation | Behavior observed or declared unknown |

Ghidra is **not** the final escalation for everything. A function can look like it authenticates a peer in pseudocode and still require runtime observation to establish what actually happens. Tier 2 and tier 3 answer different questions.

Cost increases *within* tiers too. Tier 1 is not uniformly cheap; see its sub-tiers.

---

## Tier 0 — Reconnaissance (always)

Cheap, non-invasive, no engine needed.

```sh
file -b T
sha256sum T 2>/dev/null || shasum -a 256 T    # Linux / macOS
wc -c < T                                      # portable byte count
strings -a -n 6 T | head -400
nm -gU T | head -150                           # exports
nm -u T | head -200                            # imports = capability map
```

Goal: target identity (format, arch, hash), a rough capability map, and a decision about whether deeper analysis is warranted at all. For an archive, list members first (`unzip -l`, `npx -y @electron/asar list`, `find`).

If tier 0 already answers the user's question, **answer and stop**. Most "what version / what dependencies / does it have feature X" questions end here.

---

## Tier 1 — Targeted CLI (default)

Still no heavyweight decompiler. Follow strings, imports, exports and references until the suspected implementation is located. Read call *sequences*, not every instruction.

Tier 1 has its own cost gradient. Stay at the lowest rung that works:

| Rung | Cost | Character | Examples |
|---|---|---|---|
| 1a — Quick inventory | sub-second | read-only, no extraction | `strings`, `nm`, `readelf -h`, `jq` on package metadata |
| 1b — Targeted extraction | seconds | writes a small working copy | slice one module, `asar extract`, `unzip -p`, `2>/dev/null` filtered dumps |
| 1c — Full extraction/decompile | minutes, large output | heavy | `jadx -d`, `binwalk -e`, `unblob -e`, full `ilspycmd` project |

`jadx -d X --show-bad-code a.apk` can decompile an entire APK, and `binwalk -e F` can recursively extract a large firmware image. Neither is equivalent to `strings`. Treat 1c as a mini-escalation: before running it, record what 1a/1b failed to answer and what the full output will add.

Key patterns:

- Find who uses a string: get its address from the disassembly's literal-pool comments, then find the enclosing function label.
- A C++ symbol in a call target often reveals the protocol (`getpeereid`, `write`, `std::hash`). Read the call trail around it.
- For versions/builds, diff **inventories** (`nm`, module lists, `go version -m`) before diffing any code.
- For JS, work from the native/JS boundary inward: native call → calling class → IPC registration → renderer/preload.

### Router — detect, then run the first matching block

**Electron / ASAR** (`*.app/Contents/Resources/app.asar`):

```sh
npx -y @electron/asar extract app.asar X
ls app.asar.unpacked/node_modules 2>/dev/null    # native .node addons live here
jq '{name,version,main}' X/package.json
rg -uu -n -o '.{0,120}(ipcMain\.(handle|handleOnce|on|once)|ipcRenderer\.(invoke|send|sendSync|on)|contextBridge\.exposeIn(Main|Isolated)World|webPreferences|preload:|nodeIntegration|contextIsolation|sandbox|\.node\b).{0,160}' X --glob '!node_modules'
npx -y @electron/fuses read --app A.app
```

App-specific IPC wrappers often hide channel names. Also sweep for string-shaped channels:

```sh
rg -uu -o '"[a-z]+:[a-z0-9:-]+"' X/<main> | sort -u
```

**Minified web bundle:** find `sourceMappingURL`. If the map has `sourcesContent`, dump with `jq -r '.sources[]'`. Otherwise pretty-print and read line ranges:

```sh
npx -y prettier --parser babel F > F.pretty.js
```

**Mach-O** (macOS only; without macOS tools use `llvm-objdump -d --no-show-raw-insn -C T`):

```sh
lipo -info T                          # thin first: lipo -thin arm64 -o T1 T
otool -L T
xcrun dyld_info -exports -imports T
nm -gU T                              # exports
nm -u T                               # imports
otool -l T | rg -A3 'LC_(RPATH|BUILD_VERSION)'
codesign -d --entitlements :- T
otool -ov T                           # ObjC classes/methods
xcrun swift-demangle --compact
otool -tV T > $D/dis.txt              # dump once, then grep the file
rg -n '^_?.*Name.*:$' $D/dis.txt      # find an enclosing function
rg -n 'literal pool for: "X' $D/dis.txt   # find who uses a string
awk '/^FUNC:/{p=1} p&&/^[_a-zA-Z].*:$/&&!/FUNC/{exit} p' $D/dis.txt | rg 'bl|call|literal|cmp'
```

**ELF / PE:**

```sh
readelf -hlSW T
readelf -dW T                         # NEEDED
nm -D --defined-only T
objdump -d -M intel T
pwn checksec T
# PE: objdump -x T, pefile / wrestool for resources
```

**Go:** detect by `__go_buildinfo` / `.go.buildinfo`. `go version -m T` gives toolchain, main path, deps and build flags in one call.

```sh
go version -m T
strings -a T | rg -m1 -A200 'Go buildinf'   # without Go installed
go tool nm T | rg main\.                    # symbols survive stripping
```

**Rust:**

```sh
cargo audit bin T
strings -a T | rg -o '/rustc/[0-9a-f]{40}' | sort -u
strings -a T | rg -o '[a-z0-9_-]+-[0-9]+\.[0-9]+\.[0-9]+/src' | sort -u
```

Also inflate `.dep-v0` (ELF) or `__DATA,.dep-v0` (Mach-O) for cargo-auditable deps.

**.NET:** `ilspycmd -p -o X T.dll` then `rg` over `X`. P/Invoke: `rg DllImport X`. NativeAOT/IL2CPP are native targets — use the native rows instead.

**APK:** `jadx -d X --show-bad-code a.apk` then `rg` (rung 1c). Resources/manifest only: `apktool d --no-src -o X a.apk` (rung 1b). Quick look: `unzip -l a.apk`. `lib/*/libflutter.so` → Flutter; `libhermes.so` → Hermes.

**Hermes / bytenode:** Hermes magic is `c6 1f bc 03` (`index.android.bundle`) → `hermes-dec` / `hbc-decompiler`. `.jsc` (bytenode) cannot be decompiled — use strings and runtime hooks.

**Flutter snapshot:** in `libapp.so`, magic `f5 f5 dc dc`; the 32 hex chars at +20 are the snapshot hash. Map it to a Dart version. Decode the Dart AOT snapshot with `blutter`.

**WASM:** `wasm-objdump -x`, `wasm2wat`, `wasm-decompile` (WABT).

**SQLite:** copy the db **and its `-wal`** file, then:

```sh
sqlite3 'file:C?mode=ro' '.schema'
sqlite3 'file:C?mode=ro' 'SELECT * FROM t LIMIT 20'
```

**plist / assets:** `plutil -p F`; `assetutil --info Assets.car`.

**pcap / HAR:**

```sh
tshark -r C -q -z conv,tcp
tshark -r C -T fields -e dns.qry.name -e tls.handshake.extensions_server_name -e http.request.full_uri | sort -u
jq -r '.log.entries[].request | .method+" "+.url' C   # HAR
```

**Firmware (rung 1c):** `binwalk -e F` or `unblob -e X F`, then route each extracted binary through this router.

**Website:** `curl -sL URL` for HTML and script srcs. For runtime, a headless browser with a network log (Playwright `page.on('request')`, or Chrome `--remote-debugging-port`) belongs in tier 3, not here.

**Running app (tier 3):** `lldb -p PID`, `dtrace`, `fs_usage`, `log stream --predicate 'process=="X"'`, Electron `--inspect` (only if fuses allow), `adb logcat`, `frida -U -f pkg -l hook.js`.

---

## The escalation gate

Before invoking tier 1c, tier 2 or tier 3, fill this in:

1. **Unanswered question:** one sentence.
2. **Evidence already gathered:** which cheaper findings were tried.
3. **Why cheap tools cannot answer it:** a specific limitation, not a vague feeling.
4. **What the deeper backend adds:** decompiled semantics, xrefs/call graph, or runtime observation.
5. **Stop condition:** what answer ends the investigation.

**If you cannot fill in 1 and 3, do not escalate.**

### Escalate when

- Function semantics cannot be established from the call sequence and literals.
- Control flow is complex, nested, obfuscated, or built from packed arithmetic.
- You need cross-references or a call graph to find a producer/consumer.
- You need signatures, variable types, or structure layout.
- You need exact protocol constants that disassembly alone leaves ambiguous.
- The question is about runtime behavior that no static reading can establish.

### Do not escalate when

- The question was about exports, imports, strings, metadata or versions — tier 0/1 already answered it.
- It is "just the first native task of the session."
- A missing name is already explained by a string you found.
- The asked question is answered and you are satisfying curiosity.

---

## Tier 2 contract — GhidraMCP

**Availability.** Keep GhidraMCP as a deferred/on-demand tool group if your client supports it. If it does not, use a separate Ghidra-enabled agent profile and a default profile without it. Instructions saying "only use Ghidra when needed" are a *policy*; they are not the same thing as the tool actually being absent from every prompt. Do not confuse the two.

**Identity first.** Call `get_program_info` before any other analysis and record name, format, architecture, image base and hashes. In GUI mode the backend operates on the *currently active* Ghidra program, so the active program can change underneath you. Re-verify identity if anything suggests a switch. In headless mode a session is bound to one binary — keep **separate projects for separate binaries**.

**Prefer address-based tools.** Function names are ambiguous. Use `decompile_function_by_address`, `get_xrefs_to`, `get_function_calls`, `rename_function_by_address`. Treat any name-based call as provisional.

**Read-only first.** The default tier-2 call set is `get_program_info`, `list_functions`, `decompile_function_by_address`, `disassemble_function`, `get_xrefs_*`, `get_function_calls`, `read_memory`. Modifications are a separate, later decision.

**Renames are hypotheses, never evidence.** This is the most important rule in this section:

1. You see an unfamiliar function and guess what it does.
2. You rename it `authenticate_client`.
3. Later you read the name and treat it as an established fact.
4. You now "discover" authentication by reading a label you invented.

That is circular reasoning caused by writing your guess into the database. To prevent it:

- Allow modifications only after the conclusion is independently supported by addresses, instructions or observed data.
- Keep modifications in a working project, never a reference project.
- Label any renamed symbol as **inferred** in your answer.
- If a conclusion depends on a name you assigned, re-derive it from the underlying bytes. A rename is not a citation.

**Decompiler output is not source code.** Pseudocode is an inference. It can be wrong, omit undefined behavior, or reflect compiler transformations rather than the original program. Cite it as inferred, never as seen.

**GUI vs headless.** Use GUI mode for interactive investigations where you need the active cursor/context. Use headless mode (PyGhidra) for isolated, reproducible sessions. Use a persistent project directory only when you intentionally want to keep annotations; otherwise let the project be temporary.

**Return to the cheap path.** Once the specific question is answered, stop calling tier-2 tools. Do not keep the backend warm out of habit.

---

## Tier 3 contract — dynamic verification

Enter only when static analysis cannot establish actual behavior.

- Before launching anything, declare the target, the lifecycle and the exact action. Do not broaden the target once it is running.
- Run untrusted targets inside the sandbox described in the rules, never on a host with credentials or personal files.
- Runtime observation is **seen**, but only for that run, that environment and that input. Say so.
- Capture output to a file and cite it; do not summarize from memory.
- Clean up instrumentation and processes you started.
- If the runtime is unavailable, mark the question **unknown** rather than inferring behavior.

---

## Evidence discipline across tiers

Use this record shape for any claim that matters to the answer. It makes evidence transferable between tiers without losing provenance.

| Field | Meaning |
|---|---|
| Claim | What the agent believes, in one sentence |
| Status | Seen / Inferred / Unknown |
| Anchor | File offset, address, symbol, command output or trace ID |
| Limitation | What this evidence does not establish |
| Next step | What remains unanswered, and which tier would answer it |

Never let a higher tier silently overwrite the labels of a lower one. If a stronger analysis contradicts a cheaper observation, report both and explain why.

---

## Fallbacks — no backend? degrade, don't guess

| Situation | Action |
|---|---|
| GhidraMCP unavailable, Ghidra installed | Use headless Ghidra (command below) |
| Ghidra unavailable, radare2 installed | Use `r2 -qc 'aaa; pdc @ sym.X' T` for decompilation-level analysis |
| Neither installed | Remain in tier 1 and report the limitation explicitly |

```sh
analyzeHeadless $D p -import T -postScript DecompileAll.java -deleteProject
```

Additional fallback: `npx -y @electron/asar`, `ilspycmd`, `jadx`, `apktool`, `binwalk` and similar tools each have their own native CLI paths; a missing MCP backend never blocks tier 1.

---

## Install (only on request)

Place this folder on your agent's skill path. It is plain text; if the agent has no skill loader, paste `SKILL.md` into its rules or system prompt. Tier 0/1 need no installation.

**GUI-connected mode** — connects the MCP server to an already-running Ghidra plugin (the plugin must be installed and enabled):

```sh
uvx --from git+https://github.com/LaurieWired/GhidraMCP ghidra-mcp --ghidra-server http://127.0.0.1:8080/
```

**Headless mode** — imports and analyzes a binary itself via PyGhidra, with no GUI running:

```sh
uvx --python 3.13 --from "ghidra-mcp[headless] @ git+https://github.com/LaurieWired/GhidraMCP" ghidra-mcp --headless --binary /path/to/target
```

Headless mode requires Python 3.10–3.13, `GHIDRA_INSTALL_DIR` pointing at the Ghidra installation, and the GhidraMCP extension installed (or `--extension-jar /path/to/GhidraMCP.jar`). Use the same command and arguments in your client's MCP config. Add `--project DIR` to keep the Ghidra project between runs. On macOS, build Ghidra's decompiler once with `support/gradle/gradlew buildNatives`.

Do not conflate these two modes: the `--ghidra-server` command is **not** headless.

---

## Attribution

**Provenance.** The tier 0/1 command set is derived from [leanrea](https://github.com/aicodeking/leanrea)'s `SKILL.md` (MIT licensed), lightly edited for environment portability and to fix pipes that were broken when the commands were moved into a table during drafting. The cheap-path routing idea and the seen/inferred/unknown discipline also come from leanrea. The optional deep-native backend is [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) (Apache-2.0). The escalation gate, tier structure, evidence record, write-back-contamination rule, and backend-independent policy are original to this project.

`parsimony-re` is independent of leanrea, GhidraMCP, and REA, and is not affiliated with any of their maintainers. Individual tool names remain the property of their respective projects.
