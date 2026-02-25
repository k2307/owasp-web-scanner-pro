import time
import uuid
import threading
import asyncio
import json
from collections import deque

from flask import Flask, request, jsonify, render_template, Response

from scanner.engine import ScannerEngine

app = Flask(__name__)

SCAN_JOBS = {}
RATE_LIMIT_SECONDS = 10
REQUEST_TIMESTAMPS = {}
JOB_TTL_SECONDS = 60 * 30

EVENTS_MAXLEN = 400  # keep last N events per job


# -------------------------
# Helpers
# -------------------------

def get_client_ip():
    # Render uses proxy headers sometimes
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def check_rate_limit(ip: str) -> bool:
    now = time.time()
    last = REQUEST_TIMESTAMPS.get(ip)
    if last and now - last < RATE_LIMIT_SECONDS:
        return False
    REQUEST_TIMESTAMPS[ip] = now
    return True


def cleanup_jobs():
    now = time.time()
    dead = []
    for job_id, job in list(SCAN_JOBS.items()):
        created = job.get("created_at", now)
        if job.get("status") in ("completed", "failed") and now - created > JOB_TTL_SECONDS:
            dead.append(job_id)
    for job_id in dead:
        SCAN_JOBS.pop(job_id, None)


def push_event(job_id: str, payload: dict):
    job = SCAN_JOBS.get(job_id)
    if not job:
        return
    try:
        job["events"].append(payload)
        job["last_event_ts"] = payload.get("ts", time.time())
    except Exception:
        # don't let event failure break scan
        pass


def _run_scan_thread(job_id: str, target: str, profile: str, output_format: str):
    """
    Run the async engine inside a dedicated event loop per thread (safer for gunicorn).
    Also streams progress into SCAN_JOBS[job_id]["events"] for SSE /events/<job_id>.
    """
    try:
        SCAN_JOBS[job_id]["status"] = "running"
        push_event(job_id, {"ts": time.time(), "event": "job_running", "message": "Job is running", "data": {}})

        engine = ScannerEngine(target, profile)

        def progress_cb(evt: dict):
            push_event(job_id, evt)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(engine.run(output_format=output_format, progress_cb=progress_cb))
        finally:
            loop.close()

        if output_format == "pdf":
            # engine returns dict that includes pdf_bytes
            SCAN_JOBS[job_id]["pdf_bytes"] = result.get("pdf_bytes")
            SCAN_JOBS[job_id]["result"] = {
                "message": "PDF generated",
                "download": f"/scan/{job_id}/pdf",
                "meta": {k: v for k, v in result.items() if k != "pdf_bytes"},
            }
        else:
            SCAN_JOBS[job_id]["result"] = result

        SCAN_JOBS[job_id]["status"] = "completed"
        push_event(job_id, {"ts": time.time(), "event": "job_completed", "message": "Job completed ✅", "data": {}})

    except Exception as e:
        SCAN_JOBS[job_id]["status"] = "failed"
        SCAN_JOBS[job_id]["error"] = str(e)
        push_event(job_id, {"ts": time.time(), "event": "job_failed", "message": "Job failed ❌", "data": {"error": str(e)}})


def _count_severity(findings: list[dict]):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings or []:
        s = (f.get("severity") or "Info").title()
        if s not in counts:
            s = "Info"
        counts[s] += 1
    return counts


# -------------------------
# Routes
# -------------------------

@app.get("/health")
def health():
    return "OK", 200


@app.get("/")
def home():
    return render_template("index.html")


@app.post("/scan")
def start_scan():
    cleanup_jobs()

    ip = get_client_ip()
    if not check_rate_limit(ip):
        return jsonify({"error": "Too many requests. Please wait."}), 429

    # Read input safely
    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form or {}

    target = (data.get("target") or "").strip()
    profile = (data.get("profile") or "normal").strip().lower()
    output_format = (data.get("output_format") or "json").strip().lower()

    if not target:
        return jsonify({"error": "target is required"}), 400

    if output_format not in ("json", "html", "pdf"):
        return jsonify({"error": "Invalid output_format. Use json/html/pdf"}), 400

    job_id = str(uuid.uuid4())
    SCAN_JOBS[job_id] = {
        "status": "queued",
        "created_at": time.time(),
        "target": target,
        "profile": profile,
        "output_format": output_format,
        "result": None,
        "error": None,
        "pdf_bytes": None,
        "events": deque(maxlen=EVENTS_MAXLEN),
        "last_event_ts": None,
    }

    push_event(job_id, {"ts": time.time(), "event": "job_queued", "message": "Job queued", "data": {}})

    t = threading.Thread(
        target=_run_scan_thread,
        args=(job_id, target, profile, output_format),
        daemon=True
    )
    t.start()

    return jsonify({
        "message": "Scan started",
        "job_id": job_id,
        "status_endpoint": f"/scan/{job_id}",
        "ui_endpoint": f"/ui/{job_id}",
        "events_endpoint": f"/events/{job_id}",
    })


@app.get("/scan/<job_id>")
def scan_status(job_id):
    job = SCAN_JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    # never return raw bytes or deque in JSON
    safe = {}
    for k, v in job.items():
        if k in ("pdf_bytes",):
            continue
        if k == "events":
            safe["events_count"] = len(v)
            continue
        safe[k] = v

    return jsonify(safe)


@app.get("/events/<job_id>")
def job_events(job_id):
    """
    Server-Sent Events feed for live module progress.
    Frontend: new EventSource(`/events/${jobId}`)
    """
    job = SCAN_JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    def stream():
        last_sent = 0

        # initial hello so the browser establishes stream immediately
        yield "event: hello\ndata: {}\n\n"

        while True:
            time.sleep(0.5)

            job = SCAN_JOBS.get(job_id)
            if not job:
                break

            events = list(job.get("events", []))

            # send new events
            if last_sent < len(events):
                for evt in events[last_sent:]:
                    yield f"data: {json.dumps(evt)}\n\n"
                last_sent = len(events)

            # end stream when job finishes
            if job.get("status") in ("completed", "failed"):
                yield f"event: done\ndata: {json.dumps({'status': job.get('status')})}\n\n"
                break

    return Response(stream(), mimetype="text/event-stream")


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

    # waiting/failed states still render
    if job.get("status") not in ("completed", "failed"):
        return render_template("results.html", job=job, issues=[], counts=_count_severity([]))

    result = job.get("result") or {}

    # if pdf output, result is wrapped {message,download,meta}
    # show meta if available
    if job.get("output_format") == "pdf" and isinstance(result, dict) and "meta" in result:
        meta = result.get("meta") or {}
        findings = meta.get("findings") or []
    else:
        findings = result.get("findings") or []

    counts = _count_severity(findings)
    return render_template("results.html", job=job, issues=findings, counts=counts)