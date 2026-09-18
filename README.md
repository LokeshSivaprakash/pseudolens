# PseudoLens

An MCP server that wraps isolated, headless Ghidra static analysis as callable tools, so an AI agent can fetch a real malware sample, analyze it safely, and reason about what it does.

I built this because reverse engineering usually means opening a sample in Ghidra or IDA, manually reading disassembly, and cross referencing imports and strings by hand. There's no structured way for an AI agent to participate in that process, since there's no interface between "here's a binary" and "here's what it does." PseudoLens is that interface: an MCP server (Model Context Protocol) that wraps a real Ghidra headless pipeline as a set of tools an agent can call directly.

The core pipeline works end to end. I've run it against a live sample pulled from MalwareBazaar and it correctly extracted decompiled logic, imports, and strings that identified the sample's actual behavior. See the worked example below.

## What it does

1. Fetches real malware samples from MalwareBazaar by SHA256 hash. Downloads the AES encrypted archive, extracts it, and stages it locally as an inert file that's never executed.
2. Runs every analysis inside a fresh Docker container launched with `--network none`, so a sample can never make an outbound connection or touch anything else on the host, no matter what it tries to do.
3. Runs Ghidra's real headless auto analysis: full disassembly, function identification, and the standard 30+ analyzer pipeline, the same engine a human analyst would use interactively.
4. Decompiles functions to C-like pseudocode using Ghidra's `DecompInterface` API through a custom post-analysis script, not just a disassembly listing.
5. Extracts imported libraries and embedded strings, the fastest signals for identifying malware family and behavior.
6. Runs analysis as an async job so a long running task doesn't block the calling agent. `run_static_analysis` returns a job ID right away, `get_analysis_status` polls for the result.

## Architecture

```
MalwareBazaar API -> fetch_sample (Auth-Key header, AES zip extraction)
                            |
                            v
                  local sample (inert file, never executed)
                            |
                            v
      run_static_analysis (spawns background thread)
                            |
                            v
 Docker container, --network none, ephemeral
      |
      +--> analyzeHeadless (Ghidra 12.1.3, full auto-analysis)
      |
      +--> ExtractInfo.java (post-script: DecompInterface,
           FunctionManager, ExternalManager, string extraction)
                            |
                            v
                  report.json (chowned back to host user)
                            |
                            v
            get_analysis_status (job store lookup)
```

The isolation is the whole point here. A sample sits on disk as inert data, and the only thing that ever touches it is a container with no network access, disassembling it statically. It is never executed, on the host or in the container.

## Quick start

```bash
git clone <this repo>
cd pseudolens

# builds the isolated analysis image, downloads and verifies Ghidra's
# SHA256 at build time, see docker/Dockerfile
docker build -t pseudolens-ghidra:latest docker/

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export MALWAREBAZAAR_AUTH_KEY="your_key_from_auth.abuse.ch"

# test with the MCP Inspector. env vars need to be passed explicitly,
# the Inspector doesn't forward the parent shell's environment
npx @modelcontextprotocol/inspector -e MALWAREBAZAAR_AUTH_KEY=$MALWAREBAZAAR_AUTH_KEY venv/bin/python3 server.py
```

## Tools

| Tool | Description |
|---|---|
| `fetch_sample(sha256_hash)` | Downloads and extracts a sample from MalwareBazaar by hash |
| `run_static_analysis(sample_id)` | Launches isolated Ghidra analysis, returns a `job_id` |
| `get_analysis_status(job_id)` | Polls job status, returns structured result when done |
| `ping()` | Connectivity check |

## Verified so far

- MCP server over stdio transport
- Async job pattern (queued, running, done or failed), tested under real timing
- Docker orchestration of Ghidra headless with `--network none` isolation
- Real malware sample fetch from MalwareBazaar, AES encrypted zip, Auth-Key header auth
- Custom Java post-analysis script (`ExtractInfo.java`) for function list, imports, strings
- Function decompilation via `DecompInterface`, bounded to the first 15 functions per run
- A full end-to-end run against a real, live malware sample, see the worked example below

## Worked example

I ran `fetch_sample` and `run_static_analysis` against a sample tagged `dropped-by-remus` on MalwareBazaar. It came back as a 5-function Windows PE with imports limited to `KERNEL32.DLL` and `USER32.DLL`, including `OpenClipboard`, `GetClipboardData`, `SetClipboardData`, and `EmptyClipboard`.

The decompiled `entry` function shows a loop polling `GetClipboardSequenceNumber()`, reading `CF_UNICODETEXT` clipboard content whenever it changes, and running that text through a heavily obfuscated pattern matcher (stack string XOR decoding plus vectorized character comparisons, which is a pretty classic anti-analysis technique). If the pattern matches, it calls `SetClipboardData` to overwrite the clipboard content.

That's the standard behavior of a cryptocurrency clipboard hijacker: wait for a copied wallet address, check the format, and silently swap in an attacker-controlled address before the victim pastes it into a transaction.

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

## Problems I ran into building this

- **Container DNS resolution under `--network none`.** Ghidra's logging setup calls `InetAddress.getLocalHost()`, which fails outright with no network stack in the container. Fixed with an explicit `hostname` plus an `extra_hosts` mapping so the lookup resolves locally instead of going out to DNS.
- **Ghidra 12.x dropped Jython.** Headless post-scripts written in Python fail with "Ghidra was not started with PyGhidra" unless you launch the container through PyGhidra's own entrypoint. Instead of taking on that dependency, I rewrote the extraction script in Java (`ExtractInfo.java`), which Ghidra compiles and runs on the fly with no special startup path needed.
- **Cross-container file ownership.** Files written by the container's root process into a bind-mounted output directory come out owned by root and unreadable by the host user. Fixed by having the container chown its own output to the host's UID/GID right before it exits.
- **MalwareBazaar's AES encrypted zips.** Python's stdlib `zipfile` only supports the older ZipCrypto scheme, and MalwareBazaar's archives use WinZip AES, which raises `NotImplementedError`. Fixed by switching to `pyzipper.AESZipFile`.

## Limitations

- Decompilation is capped at the first 15 functions per sample, a deliberate tradeoff to keep analysis time bounded instead of decompiling everything in a large binary upfront.
- There's no `get_function_decompilation` tool yet for on-demand, per-function lookups. Right now all decompilation happens in the single `run_static_analysis` pass.
- No IDA Pro integration, despite how I originally framed the project. Ghidra headless alone has been enough so far.
- String extraction is a straightforward walk over defined data with a string value. No entropy analysis, no separating out attacker-meaningful strings like C2 domains or mutex names from ordinary library boilerplate.

## Author

Lokesh Sivaprakash

## License

MIT
