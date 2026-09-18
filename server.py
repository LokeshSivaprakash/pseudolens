import json
import re
import sqlite3
import threading
import uuid
import os
import pyzipper
import requests
from datetime import datetime, timezone
from pathlib import Path

import docker
from mcp.server.mcpserver import MCPServer

mcp = MCPServer("pseudolens")

jobs: dict = {}

GHIDRA_IMAGE = "pseudolens-ghidra:latest"
GHIDRA_HEADLESS = "/opt/ghidra_12.1.3_PUBLIC/support/analyzeHeadless"
SCRIPTS_DIR = str(Path.home() / "pseudolens" / "scripts")
OUTPUT_DIR = str(Path.home() / "pseudolens" / "output")
PROJECTS_DIR = str(Path.home() / "pseudolens" / "projects")
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
SAMPLES_DIR = str(Path.home() / "pseudolens" / "samples")
DB_PATH = str(Path.home() / "pseudolens" / "findings.db")

# Only allow safe characters in a function name before it ever touches a
# shell command string. Ghidra function names are things like "entry" or
# "FUN_180001350" so this is not a real limitation, and it closes off
# command injection through a tool argument.
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.$]+$")

ALLOWED_CONFIDENCE = {"low", "medium", "high"}


def _init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                sample_path TEXT,
                function_name TEXT NOT NULL,
                behavior_summary TEXT NOT NULL,
                mitre_technique TEXT NOT NULL,
                confidence TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


_init_db()


@mcp.tool()
def ping() -> str:
    """Simple connectivity check tool."""
    return "pong"


def _run_ghidra_analysis(job_id: str, sample_path: str) -> None:
    jobs[job_id]["status"] = "running"
    try:
        client = docker.from_env()
        resolved = Path(sample_path).resolve()
        if not resolved.is_file():
            raise FileNotFoundError(f"Sample not found on host: {resolved}")

        host_sample_dir = str(resolved.parent)
        filename = resolved.name
        project_name = f"job_{job_id[:8]}"
        project_dir = "/work/project"

        host_project_dir = str(Path(PROJECTS_DIR) / job_id)
        os.makedirs(host_project_dir, exist_ok=True)

        host_uid = os.getuid()
        host_gid = os.getgid()

        output_file = Path(OUTPUT_DIR) / f"{job_id}.json"

        cmd_str = (
            f"mkdir -p {project_dir} && "
            f"{GHIDRA_HEADLESS} {project_dir} {project_name} "
            f"-import /work/samples/{filename} -overwrite "
            f"-scriptPath /work/scripts -postScript ExtractInfo.java "
            f"/work/output/{job_id}.json && "
            f"chown -R {host_uid}:{host_gid} /work/output/{job_id}.json /work/project"
        )
        container_command = ["bash", "-c", cmd_str]

        # project_dir is now bind-mounted to a host directory that survives
        # after the container is removed, so decompile_function can reopen
        # this same analyzed project later instead of starting over.
        raw_logs = client.containers.run(
            GHIDRA_IMAGE,
            command=container_command,
            volumes={
                host_sample_dir: {"bind": "/work/samples", "mode": "ro"},
                SCRIPTS_DIR: {"bind": "/work/scripts", "mode": "ro"},
                OUTPUT_DIR: {"bind": "/work/output", "mode": "rw"},
                host_project_dir: {"bind": project_dir, "mode": "rw"},
            },
            network_mode="none",
            hostname="ghidra-analysis",
            extra_hosts={"ghidra-analysis": "127.0.0.1"},
            remove=True,
            stdout=True,
            stderr=True,
        )

        if output_file.is_file():
            with open(output_file) as f:
                parsed = json.load(f)
            jobs[job_id]["status"] = "done"
            jobs[job_id]["result"] = parsed
            jobs[job_id]["project_name"] = project_name
            jobs[job_id]["program_name"] = filename
            jobs[job_id]["host_project_dir"] = host_project_dir
            jobs[job_id]["decompiled_cache"] = {}
        else:
            output = raw_logs.decode("utf-8", errors="replace")
            jobs[job_id]["status"] = "failed"
            jobs[job_id]["error"] = "No report.json produced"
            jobs[job_id]["log_tail"] = output[-1000:]
    except Exception as e:
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["error"] = str(e)


@mcp.tool()
def run_static_analysis(sample_id: str) -> str:
    """Run real Ghidra headless static analysis on a sample file (absolute path on this VM). Returns a job_id to poll for results. The analyzed Ghidra project is kept on disk afterward, so list_functions, decompile_function, get_strings, get_imports, and search_functions_by_api can all be called against this job_id once it's done."""
    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": "queued", "sample_id": sample_id, "result": None}

    thread = threading.Thread(
        target=_run_ghidra_analysis, args=(job_id, sample_id), daemon=True
    )
    thread.start()

    return job_id


@mcp.tool()
def fetch_sample(sha256_hash: str) -> dict:
    """Fetch a malware sample from MalwareBazaar by SHA256 hash, download and extract it locally. Returns metadata including the local file path usable with run_static_analysis."""
    auth_key = os.environ.get("MALWAREBAZAAR_AUTH_KEY")
    if not auth_key:
        return {"error": "MALWAREBAZAAR_AUTH_KEY environment variable not set"}

    headers = {"Auth-Key": auth_key}

    info_resp = requests.post(
        MALWAREBAZAAR_API,
        headers=headers,
        data={"query": "get_info", "hash": sha256_hash},
        timeout=30,
    )
    info_json = info_resp.json()
    if info_json.get("query_status") != "ok":
        return {"error": f"get_info failed: {info_json.get('query_status')}"}

    metadata = info_json["data"][0]
    file_name = metadata.get("file_name", sha256_hash)

    file_resp = requests.post(
        MALWAREBAZAAR_API,
        headers=headers,
        data={"query": "get_file", "sha256_hash": sha256_hash},
        timeout=60,
    )
    if file_resp.status_code != 200 or "json" in file_resp.headers.get("Content-Type", ""):
        return {"error": "get_file failed", "response": file_resp.text[:500]}

    os.makedirs(SAMPLES_DIR, exist_ok=True)
    zip_path = Path(SAMPLES_DIR) / f"{sha256_hash}.zip"
    with open(zip_path, "wb") as f:
        f.write(file_resp.content)

    extract_dir = Path(SAMPLES_DIR) / sha256_hash
    extract_dir.mkdir(exist_ok=True)
    with pyzipper.AESZipFile(zip_path) as zf:
        zf.extractall(path=extract_dir, pwd=b"infected")

    extracted_files = list(extract_dir.iterdir())
    local_path = str(extracted_files[0]) if extracted_files else None

    return {
        "sha256_hash": sha256_hash,
        "file_name": file_name,
        "file_type": metadata.get("file_type"),
        "signature": metadata.get("signature"),
        "tags": metadata.get("tags"),
        "local_path": local_path,
    }


@mcp.tool()
def get_analysis_status(job_id: str) -> dict:
    """Check the status/result of a previously started analysis job."""
    return jobs.get(job_id, {"status": "not_found"})


@mcp.tool()
def list_functions(job_id: str) -> dict:
    """List every function Ghidra found in a completed analysis job, with name and entry address. Does not include decompiled code, call decompile_function for that on a specific function."""
    job = jobs.get(job_id)
    if not job:
        return {"error": "job not found"}
    if job.get("status") != "done":
        return {"error": f"job is not done yet, status: {job.get('status')}"}

    functions = job["result"].get("functions", [])
    return {
        "functions_found": job["result"].get("functions_found"),
        "functions": [
            {"name": f["name"], "entry": f["entry"]} for f in functions
        ],
    }


@mcp.tool()
def get_strings(job_id: str) -> dict:
    """Get the extracted string constants from a completed analysis job."""
    job = jobs.get(job_id)
    if not job:
        return {"error": "job not found"}
    if job.get("status") != "done":
        return {"error": f"job is not done yet, status: {job.get('status')}"}
    return {"strings": job["result"].get("strings_sample", [])}


@mcp.tool()
def get_imports(job_id: str) -> dict:
    """Get the imported libraries from a completed analysis job."""
    job = jobs.get(job_id)
    if not job:
        return {"error": "job not found"}
    if job.get("status") != "done":
        return {"error": f"job is not done yet, status: {job.get('status')}"}
    return {"imported_libraries": job["result"].get("imported_libraries", [])}


@mcp.tool()
def decompile_function(job_id: str, function_name: str) -> dict:
    """Decompile a single function by name from a completed analysis job, on demand. Reopens the already-analyzed Ghidra project rather than re-running full analysis, so this is much faster than the initial run_static_analysis call. Results are cached, calling this again for the same function returns instantly."""
    job = jobs.get(job_id)
    if not job:
        return {"error": "job not found"}
    if job.get("status") != "done":
        return {"error": f"job is not done yet, status: {job.get('status')}"}

    if not SAFE_NAME_RE.match(function_name):
        return {"error": "function_name contains characters that aren't allowed"}

    cache = job.setdefault("decompiled_cache", {})
    if function_name in cache:
        return cache[function_name]

    try:
        client = docker.from_env()
        host_uid = os.getuid()
        host_gid = os.getgid()
        out_name = f"{job_id}_{function_name}.json"

        cmd_str = (
            f"{GHIDRA_HEADLESS} /work/project {job['project_name']} "
            f"-process {job['program_name']} -noanalysis "
            f"-scriptPath /work/scripts -postScript DecompileOne.java "
            f"{function_name} /work/output/{out_name} && "
            f"chown {host_uid}:{host_gid} /work/output/{out_name}"
        )
        container_command = ["bash", "-c", cmd_str]

        client.containers.run(
            GHIDRA_IMAGE,
            command=container_command,
            volumes={
                SCRIPTS_DIR: {"bind": "/work/scripts", "mode": "ro"},
                OUTPUT_DIR: {"bind": "/work/output", "mode": "rw"},
                job["host_project_dir"]: {"bind": "/work/project", "mode": "rw"},
            },
            network_mode="none",
            hostname="ghidra-analysis",
            extra_hosts={"ghidra-analysis": "127.0.0.1"},
            remove=True,
            stdout=True,
            stderr=True,
        )

        out_path = Path(OUTPUT_DIR) / out_name
        if not out_path.is_file():
            return {"error": "decompile_function produced no output"}

        with open(out_path) as f:
            result = json.load(f)

        cache[function_name] = result
        return result
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def search_functions_by_api(job_id: str, api_name: str) -> dict:
    """Search already-decompiled functions in a job for calls to a given API name (e.g. CreateRemoteThread, GetClipboardData). Only searches functions that have already been decompiled via decompile_function or the initial analysis, call decompile_function on more functions first to widen the search."""
    job = jobs.get(job_id)
    if not job:
        return {"error": "job not found"}
    if job.get("status") != "done":
        return {"error": f"job is not done yet, status: {job.get('status')}"}

    cache = job.get("decompiled_cache", {})
    matches = []
    for name, result in cache.items():
        code = result.get("decompiled", "")
        if api_name in code:
            matches.append(name)

    return {
        "api_name": api_name,
        "matching_functions": matches,
        "functions_searched": len(cache),
        "note": "Only functions already decompiled were searched. Call decompile_function on more functions to widen coverage.",
    }


@mcp.tool()
def tag_mitre_technique(
    job_id: str,
    function_name: str,
    mitre_technique: str,
    behavior_summary: str,
    confidence: str,
) -> dict:
    """Record a finding for a function: what it does, which MITRE ATT&CK technique it maps to (e.g. T1115 for clipboard data), and how confident the analysis is. Writes to a persistent SQLite findings database so classifications survive after this job's in-memory state is gone. confidence must be one of low, medium, high."""
    job = jobs.get(job_id)
    if not job:
        return {"error": "job not found"}

    if confidence not in ALLOWED_CONFIDENCE:
        return {"error": f"confidence must be one of {sorted(ALLOWED_CONFIDENCE)}"}

    sample_path = job.get("sample_id")
    created_at = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.execute(
            """
            INSERT INTO findings
                (job_id, sample_path, function_name, behavior_summary, mitre_technique, confidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (job_id, sample_path, function_name, behavior_summary, mitre_technique, confidence, created_at),
        )
        conn.commit()
        finding_id = cur.lastrowid
    finally:
        conn.close()

    return {
        "finding_id": finding_id,
        "job_id": job_id,
        "function_name": function_name,
        "mitre_technique": mitre_technique,
        "confidence": confidence,
        "created_at": created_at,
    }


@mcp.tool()
def get_findings(job_id: str) -> dict:
    """Get every recorded finding for a job from the persistent findings database."""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM findings WHERE job_id = ? ORDER BY created_at", (job_id,)
        ).fetchall()
    finally:
        conn.close()

    return {"job_id": job_id, "findings": [dict(row) for row in rows]}


if __name__ == "__main__":
    mcp.run()
