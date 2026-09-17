import json
import threading
import uuid
import os
import pyzipper
import requests
from pathlib import Path

import docker
from mcp.server.mcpserver import MCPServer

mcp = MCPServer("pseudolens")

jobs: dict = {}

GHIDRA_IMAGE = "pseudolens-ghidra:latest"
GHIDRA_HEADLESS = "/opt/ghidra_12.1.3_PUBLIC/support/analyzeHeadless"
SCRIPTS_DIR = str(Path.home() / "pseudolens" / "scripts")
OUTPUT_DIR = str(Path.home() / "pseudolens" / "output")
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
SAMPLES_DIR = str(Path.home() / "pseudolens" / "samples")

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

        import os
        host_uid = os.getuid()
        host_gid = os.getgid()

        output_file = Path(OUTPUT_DIR) / f"{job_id}.json"

        cmd_str = (
            f"mkdir -p {project_dir} && "
            f"{GHIDRA_HEADLESS} {project_dir} {project_name} "
            f"-import /work/samples/{filename} -overwrite "
            f"-scriptPath /work/scripts -postScript ExtractInfo.java "
            f"/work/output/{job_id}.json && "
            f"chown {host_uid}:{host_gid} /work/output/{job_id}.json"
        )
        container_command = ["bash", "-c", cmd_str]

        raw_logs = client.containers.run(
            GHIDRA_IMAGE,
            command=container_command,
            volumes={
                host_sample_dir: {"bind": "/work/samples", "mode": "ro"},
                SCRIPTS_DIR: {"bind": "/work/scripts", "mode": "ro"},
                OUTPUT_DIR: {"bind": "/work/output", "mode": "rw"},
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
    """Run real Ghidra headless static analysis on a sample file (absolute path on this VM). Returns a job_id to poll for results."""
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


if __name__ == "__main__":
    mcp.run()
