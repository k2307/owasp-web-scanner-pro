import time
import uuid
import threading
import asyncio
from flask import Flask, request, jsonify, render_template, Response

from scanner.engine import ScannerEngine

app = Flask(__name__)

SCAN_JOBS = {}
RATE_LIMIT_SECONDS = 10
REQUEST_TIMESTAMPS = {}
JOB_TTL_SECONDS = 60 * 30


def get_client_ip():
    # Render uses proxy headers sometimes
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def check_rate_limit(ip):
    now = time.time()
    last = REQUEST_TIMESTAMPS.get(ip)
    if last and now - last < RATE_LIMIT_SECONDS:
        return False
    REQUEST_TIMESTAMPS[ip] = now
    return True


def cleanup_jobs():
    now = time.time()
    dead = []
    for job_id, job in SCAN_JOBS.items():
        created = job.get("created_at", now)
        if job.get("status") in ("completed", "failed") and now - created > JOB_TTL_SECONDS:
            dead.append(job_id)
    for job_id in dead:
        SCAN_JOBS.pop(job_id, None)


def _run_scan_thread(job_id, target, profile, output_format):
    try:
        SCAN_JOBS[job_id]["status"] = "running"
        engine = ScannerEngine(target, profile)

        # Run async engine inside this thread
        result = asyncio.run(engine.run(output_format=output_format))

        if output_format == "pdf":
            # result is dict with pdf bytes
            SCAN_JOBS[job_id]["pdf_bytes"] = result.get("pdf_bytes")
            SCAN_JOBS[job_id]["result"] = {"message": "PDF generated", "download": f"/scan/{job_id}/pdf"}
        else:
            SCAN_JOBS[job_id]["result"] = result

        SCAN_JOBS[job_id]["status"] = "completed"
    except Exception as e:
        SCAN_JOBS[job_id]["status"] = "failed"
        SCAN_JOBS[job_id]["error"] = str(e)


@app.get("/")
def home():
    return render_template("index.html")


@app.post("/scan")
def start_scan():
    cleanup_jobs()
    ip = get_client_ip()
    if not check_rate_limit(ip):
        return jsonify({"error": "Too many requests. Please wait."}), 429

    data = request.get_json(force=True) if request.is_json else request.form
    target = data.get("target")
    profile = data.get("profile", "normal")
    output_format = data.get("output_format", "json")

    if output_format not in ("json", "html", "pdf"):
        return jsonify({"error": "Invalid output_format. Use json/html/pdf"}), 400

    if not target:
        return jsonify({"error": "target is required"}), 400

    job_id = str(uuid.uuid4())
    SCAN_JOBS[job_id] = {
        "status": "queued",
        "created_at": time.time(),
        "target": target,
        "profile": profile,
        "output_format": output_format,
        "result": None,
        "error": None,
        "pdf_bytes": None
    }

    t = threading.Thread(target=_run_scan_thread, args=(job_id, target, profile, output_format), daemon=True)
    t.start()

    return jsonify({"message": "Scan started", "job_id": job_id, "status_endpoint": f"/scan/{job_id}"})


@app.get("/scan/<job_id>")
def scan_status(job_id):
    job = SCAN_JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    # never return raw bytes in JSON
    safe = {k: v for k, v in job.items() if k != "pdf_bytes"}
    return jsonify(safe)


@app.get("/scan/<job_id>/pdf")
def download_pdf(job_id):
    job = SCAN_JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if job.get("status") != "completed":
        return jsonify({"error": "Job not completed"}), 409

    pdf_bytes = job.get("pdf_bytes")
    if not pdf_bytes:
        return jsonify({"error": "No PDF available for this job"}), 404

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="scan_{job_id}.pdf"'}
    )


@app.get("/ui/<job_id>")
def view_results(job_id):
    job = SCAN_JOBS.get(job_id)
    if not job:
        return "Job not found", 404
    return render_template("results.html", job=job)