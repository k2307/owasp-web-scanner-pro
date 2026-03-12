import os
import time
import uuid
import threading
import asyncio
import json
from collections import deque
from functools import wraps
from typing import Dict, Any

from flask import Flask, request, jsonify, render_template, Response, session, redirect, url_for
from werkzeug.security import check_password_hash

from scanner.engine import ScannerEngine

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-in-render")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,   # keep True on Render HTTPS
)

SCAN_JOBS: Dict[str, Dict[str, Any]] = {}
SCAN_LOCK = threading.Lock()

RATE_LIMIT_SECONDS = 10
REQUEST_TIMESTAMPS: Dict[str, float] = {}
JOB_TTL_SECONDS = 60 * 30
EVENTS_MAXLEN = 400

# Login protection
LOGIN_ATTEMPTS: Dict[str, Dict[str, Any]] = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60

# Extra login rate limit
LOGIN_RATE_LIMIT_SECONDS = 5
LAST_LOGIN_ATTEMPT: Dict[str, float] = {}

# Scan abuse control
MAX_RUNNING_SCANS = 10


# -------------------------
# Helpers
# -------------------------

def get_client_ip():
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_logged_in() -> bool:
    return session.get("authenticated") is True


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for("home"))
        return view_func(*args, **kwargs)
    return wrapped


def _get_login_state(ip: str):
    now = time.time()
    state = LOGIN_ATTEMPTS.get(ip)
    if not state:
        state = {"count": 0, "locked_until": 0}
        LOGIN_ATTEMPTS[ip] = state

    if state["locked_until"] and now >= state["locked_until"]:
        state["count"] = 0
        state["locked_until"] = 0

    return state


def is_locked_out(ip: str) -> bool:
    state = _get_login_state(ip)
    return time.time() < state["locked_until"]


def record_failed_login(ip: str):
    state = _get_login_state(ip)
    state["count"] += 1
    if state["count"] >= MAX_LOGIN_ATTEMPTS:
        state["locked_until"] = time.time() + LOCKOUT_SECONDS


def clear_login_failures(ip: str):
    LOGIN_ATTEMPTS[ip] = {"count": 0, "locked_until": 0}


def check_login_rate_limit(ip: str) -> bool:
    now = time.time()
    last = LAST_LOGIN_ATTEMPT.get(ip)
    if last and now - last < LOGIN_RATE_LIMIT_SECONDS:
        return False
    LAST_LOGIN_ATTEMPT[ip] = now
    return True


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

    with SCAN_LOCK:
        for job_id, job in list(SCAN_JOBS.items()):
            created = job.get("created_at", now)
            if job.get("status") in ("completed", "failed") and (now - created) > JOB_TTL_SECONDS:
                dead.append(job_id)

        for job_id in dead:
            SCAN_JOBS.pop(job_id, None)


def push_event(job_id: str, payload: dict):
    with SCAN_LOCK:
        job = SCAN_JOBS.get(job_id)
        if not job:
            return
        try:
            job["events"].append(payload)
            job["last_event_ts"] = payload.get("ts", time.time())
        except Exception:
            pass


def _run_scan_thread(job_id: str, target: str, profile: str, output_format: str):
    try:
        with SCAN_LOCK:
            if job_id in SCAN_JOBS:
                SCAN_JOBS[job_id]["status"] = "running"

        push_event(job_id, {"ts": time.time(), "event": "job_running", "message": "Job is running", "data": {}})

        engine = ScannerEngine(target, profile)

        def progress_cb(evt: dict):
            evt.setdefault("ts", time.time())
            evt.setdefault("event", "log")
            evt.setdefault("message", "")
            evt.setdefault("data", {})
            push_event(job_id, evt)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(
                engine.run(output_format=output_format, progress_cb=progress_cb)
            )
        finally:
            loop.close()

        with SCAN_LOCK:
            job = SCAN_JOBS.get(job_id)
            if not job:
                return

            if output_format == "pdf":
                job["pdf_bytes"] = result.get("pdf_bytes")
                job["result"] = {
                    "message": "PDF generated",
                    "download": f"/scan/{job_id}/pdf",
                    "meta": {k: v for k, v in (result or {}).items() if k != "pdf_bytes"},
                }
            else:
                job["result"] = result

            job["status"] = "completed"

        push_event(job_id, {"ts": time.time(), "event": "job_completed", "message": "Job completed ✅", "data": {}})

    except Exception as e:
        with SCAN_LOCK:
            job = SCAN_JOBS.get(job_id)
            if job:
                job["status"] = "failed"
                job["error"] = str(e)

        push_event(job_id, {
            "ts": time.time(),
            "event": "job_failed",
            "message": "Job failed ❌",
            "data": {"error": str(e)}
        })


def _count_severity(findings: list[dict]):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings or []:
        s = (f.get("severity") or "Info").title()
        if s not in counts:
            s = "Info"
        counts[s] += 1
    return counts


# -------------------------
# Security Headers
# -------------------------

@app.after_request
def add_security_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';"
    return resp


# -------------------------
# Routes
# -------------------------

@app.get("/")
def home():
    if is_logged_in():
        return render_template("index.html", authenticated=True, login_error=None)
    return render_template("index.html", authenticated=False, login_error=None)


@app.post("/login")
def login_submit():
    ip = get_client_ip()

    if not check_login_rate_limit(ip):
        return render_template(
            "index.html",
            authenticated=False,
            login_error="Too many login attempts. Please wait a few seconds and try again."
        ), 429

    if is_locked_out(ip):
        remaining = int(_get_login_state(ip)["locked_until"] - time.time())
        return render_template(
            "index.html",
            authenticated=False,
            login_error=f"Too many failed attempts. Try again in {remaining} seconds."
        ), 429

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    expected_user = os.environ.get("APP_USERNAME", "")
    expected_hash = os.environ.get("APP_PASSWORD_HASH", "")

    time.sleep(0.6)

    if username == expected_user and expected_hash and check_password_hash(expected_hash, password):
        session.clear()
        session["authenticated"] = True
        session["username"] = username
        clear_login_failures(ip)
        return redirect(url_for("home"))

    record_failed_login(ip)
    return render_template(
        "index.html",
        authenticated=False,
        login_error="Invalid username or password."
    ), 401


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.post("/scan")
@login_required
def start_scan():
    cleanup_jobs()

    ip = get_client_ip()
    if not check_rate_limit(ip):
        return jsonify({"error": "Too many requests. Please wait."}), 429

    with SCAN_LOCK:
        running = sum(1 for j in SCAN_JOBS.values() if j.get("status") == "running")
        if running >= MAX_RUNNING_SCANS:
            return jsonify({"error": "Server is busy. Please try again later."}), 429

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

    with SCAN_LOCK:
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
@login_required
def scan_status(job_id):
    with SCAN_LOCK:
        job = SCAN_JOBS.get(job_id)

        if not job:
            return jsonify({"error": "Job not found"}), 404

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
@login_required
def job_events(job_id):
    with SCAN_LOCK:
        job = SCAN_JOBS.get(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404

    def stream():
        last_sent = 0
        yield "event: hello\ndata: {}\n\n"

        while True:
            time.sleep(0.5)

            with SCAN_LOCK:
                job = SCAN_JOBS.get(job_id)
                if not job:
                    break
                events = list(job.get("events", []))
                status = job.get("status")

            if last_sent < len(events):
                for evt in events[last_sent:]:
                    yield f"data: {json.dumps(evt)}\n\n"
                last_sent = len(events)

            yield "event: ping\ndata: {}\n\n"

            if status in ("completed", "failed"):
                yield f"event: done\ndata: {json.dumps({'status': status})}\n\n"
                break

    resp = Response(stream(), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"
    return resp


@app.get("/scan/<job_id>/pdf")
@login_required
def download_pdf(job_id):
    with SCAN_LOCK:
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
@login_required
def view_results(job_id):
    with SCAN_LOCK:
        job = SCAN_JOBS.get(job_id)

        if not job:
            return "Job not found", 404

        status = job.get("status")
        output_format = job.get("output_format")
        result = job.get("result") or {}

    if status not in ("completed", "failed"):
        return render_template("results.html", job=job, issues=[], counts=_count_severity([]))

    if output_format == "pdf" and isinstance(result, dict) and "meta" in result:
        meta = result.get("meta") or {}
        findings = meta.get("findings") or []
    else:
        findings = result.get("findings") or []

    counts = _count_severity(findings)
    return render_template("results.html", job=job, issues=findings, counts=counts)