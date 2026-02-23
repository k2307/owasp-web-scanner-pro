import asyncio
import logging
import time
import uuid
from typing import Dict, Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, HttpUrl

from scanner.engine import ScannerEngine


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="OWASP Web Scanner Pro", version="1.0")


# -------------------------
# In-memory stores
# -------------------------
SCAN_JOBS: Dict[str, dict] = {}
REQUEST_TIMESTAMPS: Dict[str, float] = {}

RATE_LIMIT_SECONDS = 10
JOB_TTL_SECONDS = 60 * 30  # keep finished jobs for 30 minutes


# -------------------------
# Models
# -------------------------
class ScanRequest(BaseModel):
    target: HttpUrl
    profile: str = "normal"
    output_format: str = "json"  # json/html/pdf


# -------------------------
# Helpers
# -------------------------
def get_client_ip(request: Request) -> str:
    """
    Render may sit behind proxies. Prefer X-Forwarded-For if present.
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def check_rate_limit(client_ip: str):
    now = time.time()
    last = REQUEST_TIMESTAMPS.get(client_ip)
    if last and now - last < RATE_LIMIT_SECONDS:
        raise HTTPException(status_code=429, detail="Too many requests. Please wait.")
    REQUEST_TIMESTAMPS[client_ip] = now


def cleanup_jobs():
    now = time.time()
    to_delete = []
    for job_id, job in SCAN_JOBS.items():
        created = job.get("created_at", now)
        if job.get("status") in ("completed", "failed") and now - created > JOB_TTL_SECONDS:
            to_delete.append(job_id)
    for job_id in to_delete:
        SCAN_JOBS.pop(job_id, None)


# -------------------------
# Background worker
# -------------------------
async def run_scan_job(job_id: str, target: str, profile: str, output_format: str):
    try:
        SCAN_JOBS[job_id]["status"] = "running"

        engine = ScannerEngine(target, profile)

        result = await engine.run(output_format=output_format)

        # PDF result contains bytes -> keep separately
        if output_format == "pdf":
            pdf_bytes = result.get("pdf_bytes")
            SCAN_JOBS[job_id]["pdf_bytes"] = pdf_bytes
            SCAN_JOBS[job_id]["result"] = {
                "message": "PDF generated",
                "download_endpoint": f"/scan/{job_id}/pdf"
            }
        else:
            SCAN_JOBS[job_id]["result"] = result

        SCAN_JOBS[job_id]["status"] = "completed"

    except Exception as e:
        logger.error(f"Scan job {job_id} failed: {e}")
        SCAN_JOBS[job_id]["status"] = "failed"
        SCAN_JOBS[job_id]["error"] = str(e)


# -------------------------
# Routes
# -------------------------
@app.post("/scan")
async def start_scan(request: Request, data: ScanRequest, background_tasks: BackgroundTasks):
    cleanup_jobs()

    client_ip = get_client_ip(request)
    check_rate_limit(client_ip)

    if data.output_format not in ("json", "html", "pdf"):
        raise HTTPException(status_code=400, detail="Invalid output format. Use json/html/pdf")

    job_id = str(uuid.uuid4())

    SCAN_JOBS[job_id] = {
        "status": "queued",
        "result": None,
        "error": None,
        "created_at": time.time(),
        "target": str(data.target),
        "profile": data.profile,
        "output_format": data.output_format,
        "pdf_bytes": None
    }

    background_tasks.add_task(
        run_scan_job,
        job_id,
        str(data.target),
        data.profile,
        data.output_format
    )

    return JSONResponse({
        "message": "Scan started",
        "job_id": job_id,
        "status_endpoint": f"/scan/{job_id}"
    })


@app.get("/scan/{job_id}")
async def get_scan_status(job_id: str):
    job = SCAN_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # Do not return raw PDF bytes in JSON
    safe_job = {k: v for k, v in job.items() if k != "pdf_bytes"}
    return safe_job


@app.get("/scan/{job_id}/pdf")
async def download_pdf(job_id: str):
    job = SCAN_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.get("status") != "completed":
        raise HTTPException(status_code=409, detail="Job not completed yet")

    pdf_bytes = job.get("pdf_bytes")
    if not pdf_bytes:
        raise HTTPException(status_code=404, detail="No PDF available for this job")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="scan_{job_id}.pdf"'
        }
    )


@app.get("/")
async def root():
    return {"service": "OWASP Web Scanner Pro", "status": "running"}