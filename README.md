# PseudoLens

**An MCP server exposing isolated, headless Ghidra static analysis as callable tools — so an AI agent can fetch, analyze, and reason about real malware samples safely.**

> Status: core pipeline complete and verified end-to-end against a live
> malware sample from MalwareBazaar. Decompiler output, function/import/
> string extraction, and async job orchestration are all working. See
> [Verified capabilities](#verified-capabilities) for exactly what's real
> today vs. planned.

## The problem

Reverse engineering a malware sample today means: pull the sample, load it
into Ghidra or IDA, manually read the disassembly/decompilation, and
cross-reference imports and strings by hand. It's slow, and it doesn't
compose with anything — there's no way for an AI agent to participate in
that workflow, because there's no structured interface between "here's a
binary" and "here's what it does."

PseudoLens is that interface: an [MCP](https://modelcontextprotocol.io)
server that wraps a real, isolated Ghidra headless analysis pipeline as a
set of callable tools, so fetching a sample, analyzing it, and reading its
decompiled logic can all happen through an agent-driven workflow instead of
a GUI.

## What it does

1. **Fetches real malware samples** from MalwareBazaar by SHA256 hash —
   downloads the AES-encrypted distribution archive, extracts it, and stages
   it locally as an inert file (never executed).
2. **Analyzes samples in an isolated environment** — every analysis run
   happens inside a fresh Docker container launched with `--network none`,
   so a sample can never make an outbound connection, exfiltrate data, or
   reach anything else on the host, regardless of what it tries to do.
3. **Runs real Ghidra headless auto-analysis** — full disassembly, function
   identification, and the standard analyzer pipeline (30+ analyzers:
   stack analysis, reference analysis, DWARF, function ID, etc.), the same
   engine a human analyst would use interactively.
4. **Decompiles functions to C-like pseudocode** via a custom Ghidra
   post-analysis script using the `DecompInterface` API — not just a
   disassembly listing, but actual readable logic.
5. **Extracts structured IOCs** — imported libraries/APIs and embedded
   strings, the two fastest signals for identifying malware family and
   behavior.
6. **Runs async**, so a multi-second-to-minute analysis doesn't block the
   calling agent — `run_static_analysis` returns a job ID immediately;
   `get_analysis_status` polls for the result.

## Architecture

```
 MalwareBazaar API ──► fetch_sample (Auth-Key, AES zip extraction)
                              │
                              ▼
                    local sample (inert file, never executed)
                              │
                              ▼
        run_static_analysis (spawns background thread)
                              │
                              ▼
   Docker container, --network none, ephemeral (--rm)
        │
        ├─► analyzeHeadless (Ghidra 12.1.3, full auto-analysis)
        │
        └─► ExtractInfo.java (post-script: DecompInterface,
             FunctionManager, ExternalManager, string extraction)
                              │
                              ▼
                    report.json (chowned back to host user)
                              │
                              ▼
              get_analysis_status (job store lookup)
```

The isolation boundary is the whole safety property here: a sample is
staged on disk as inert data, and the only thing that ever touches it is a
container with no network access, disassembling it statically — it is
never executed, on the host or in the container.

## Quick start

```bash
git clone <this repo>
cd pseudolens

# Build the isolated analysis image (downloads and verifies Ghidra's
# SHA256 during build — see docker/Dockerfile)
docker build -t pseudolens-ghidra:latest docker/

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export MALWAREBAZAAR_AUTH_KEY="your_key_from_auth.abuse.ch"

# Test with the MCP Inspector (env vars must be passed explicitly —
# the Inspector does not forward the parent shell's environment)
npx @modelcontextprotocol/inspector -e MALWAREBAZAAR_AUTH_KEY=$MALWAREBAZAAR_AUTH_KEY venv/bin/python3 server.py
```

## Tools

| Tool | Description |
|---|---|
| `fetch_sample(sha256_hash)` | Downloads and extracts a sample from MalwareBazaar by hash |
| `run_static_analysis(sample_id)` | Launches isolated Ghidra analysis, returns a `job_id` |
| `get_analysis_status(job_id)` | Polls job status; returns structured result when done |
| `ping()` | Connectivity check |

## Verified capabilities

- [x] MCP server (stdio transport, `MCPServer`/`FastMCP`-successor API)
- [x] Async job pattern (queued → running → done/failed), verified under real timing
- [x] Docker orchestration of Ghidra headless with `--network none` isolation
- [x] Real malware sample fetch from MalwareBazaar (AES-encrypted zip, `Auth-Key` header auth)
- [x] Custom Java post-analysis script (`ExtractInfo.java`) — function list, imports, strings
- [x] Function decompilation via `DecompInterface`, bounded to the first 15 functions per run
- [x] End-to-end run against a real, live malware sample (a clipboard-hijacking "clipper" — see [Worked example](#worked-example))

## Worked example

Running `fetch_sample` + `run_static_analysis` against a sample tagged
`dropped-by-remus` on MalwareBazaar produced a 5-function Windows PE with
imports limited to `KERNEL32.DLL` and `USER32.DLL`, including
`OpenClipboard`, `GetClipboardData`, `SetClipboardData`, and
`EmptyClipboard`. The decompiled `entry` function shows a loop polling
`GetClipboardSequenceNumber()`, reading `CF_UNICODETEXT` clipboard content
on change, running it through a heavily obfuscated pattern-matcher
(stack-string XOR decoding + vectorized character comparisons — classic
anti-analysis obfuscation), and calling `SetClipboardData` to overwrite it
if the pattern matches. That's the standard behavior of a **cryptocurrency
clipboard hijacker**: wait for a copied wallet address, validate its format,
silently replace it with an attacker-controlled address before the victim
pastes it into a transaction.

## Screenshots

**MCP server connected**
![Server connected](docs/screenshots/server-connected.png)

**Tools registered**
![Tools list](docs/screenshots/tools-list.png)

**Fetching a real sample from MalwareBazaar**
![fetch_sample result](docs/screenshots/fetch-sample.png)

**Launching analysis, returns a job ID immediately (async pattern)**
![run_static_analysis result](docs/screenshots/run-static-analysis.png)

**Decompiled analysis result on a live malware sample**
![Analysis result](docs/screenshots/analysis-result.png)

## Real problems solved while building this

- **Container DNS resolution under `--network none`**: Ghidra's logging
  init calls `InetAddress.getLocalHost()`, which fails outright with no
  network stack — fixed with an explicit `hostname` + `extra_hosts` mapping
  so the lookup resolves locally.
- **Ghidra 12.x dropped Jython**: headless post-scripts written in Python
  fail with `Ghidra was not started with PyGhidra` unless the container is
  launched via PyGhidra's own entrypoint. Rather than take on that
  dependency, `ExtractInfo.java` uses Ghidra's on-the-fly Java script
  compilation instead — no special startup path required.
- **Cross-container file ownership**: files written by the (root) container
  process into a bind-mounted output directory are unreadable by the host
  user afterward; fixed by having the container `chown` its own output to
  the host's UID/GID before exiting.
- **MalwareBazaar's AES-encrypted zips**: Python's stdlib `zipfile` only
  supports the older ZipCrypto scheme; MalwareBazaar's distribution
  archives use WinZip AES, which raises `NotImplementedError` — fixed by
  switching to `pyzipper.AESZipFile`.

## Limitations (stated honestly)

- Decompilation is bounded to the first 15 functions analyzed per sample —
  a deliberate trade-off to keep analysis time bounded rather than
  decompiling every function in a large binary upfront.
- `get_function_decompilation` as an on-demand, per-function lookup tool
  is not yet implemented — currently all bounded decompilation happens
  during the single `run_static_analysis` pass.
- No IDA Pro integration yet, despite the original project framing — Ghidra
  headless alone has proven sufficient so far.
- The string extraction is a straightforward "defined data with a string
  value" walk — no entropy analysis, no distinguishing between
  attacker-meaningful strings (C2 domains, mutex names) and noise (embedded
  library boilerplate).

## Author

**Lokesh Sivaprakash**

## License

MIT
