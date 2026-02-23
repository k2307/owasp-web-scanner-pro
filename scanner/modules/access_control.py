import aiohttp
from urllib.parse import urljoin
from hashlib import sha256

COMMON_PATHS = [
    "/admin",
    "/admin/",
    "/dashboard",
    "/backup",
    "/config",
    "/settings",
    "/manage",
    "/api",
    "/api/users",
    "/api/users/1",
    "/user/1",
]

LOGIN_KEYWORDS = [
    "login", "sign in", "signin", "authentication", "password", "username"
]

REDIRECT_CODES = {301, 302, 303, 307, 308}


def _hash_preview(text: str) -> str:
    return sha256(text[:4000].encode("utf-8", errors="ignore")).hexdigest()[:16]


def _looks_like_login_page(body_lower: str) -> bool:
    return any(k in body_lower for k in LOGIN_KEYWORDS)


async def _fetch(session: aiohttp.ClientSession, url: str):
    async with session.get(url, allow_redirects=False) as r:
        body = await r.text(errors="ignore")
        return {
            "status": r.status,
            "len": len(body),
            "hash": _hash_preview(body),
            "location": r.headers.get("Location", ""),
            "body_lower": body.lower(),
            "content_type": (r.headers.get("Content-Type") or "").lower(),
        }


async def scan(target: str):
    findings = []
    timeout = aiohttp.ClientTimeout(total=12)
    headers = {"User-Agent": "OWASP-Web-Scanner-Pro/1.0"}

    base = target.rstrip("/") + "/"

    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            # Baseline (home page)
            try:
                baseline = await _fetch(session, base)
            except Exception:
                baseline = None

            # Sensitive paths check
            for path in COMMON_PATHS:
                url = urljoin(base, path.lstrip("/"))

                try:
                    ev = await _fetch(session, url)

                    # Ignore missing
                    if ev["status"] == 404:
                        continue

                    # Forbidden but exists
                    if ev["status"] == 403:
                        findings.append({
                            "title": f"Protected Resource Exists (403): {path}",
                            "severity": "Low",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            "description": (
                                "A sensitive-looking endpoint exists but is forbidden. "
                                "This can help attackers enumerate admin surfaces."
                            ),
                            "remediation": (
                                "Keep access controls strict and consider reducing endpoint discoverability "
                                "or returning consistent responses."
                            ),
                            "metadata": {
                                "endpoint": url,
                                "status": ev["status"]
                            }
                        })
                        continue

                    # Redirects (may indicate gating)
                    if ev["status"] in REDIRECT_CODES and ev["location"]:
                        loc_lower = ev["location"].lower()
                        if "login" in loc_lower or "signin" in loc_lower:
                            continue

                        findings.append({
                            "title": f"Sensitive Path Redirects (Check Access Control): {path}",
                            "severity": "Info",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                            "description": (
                                "Endpoint redirects without a clear login destination. "
                                "Review if redirects can be abused."
                            ),
                            "remediation": "Ensure redirects do not leak sensitive content or allow open redirects.",
                            "metadata": {
                                "endpoint": url,
                                "status": ev["status"],
                                "location": ev["location"]
                            }
                        })
                        continue

                    # 200 OK HTML
                    if ev["status"] == 200 and "text/html" in ev["content_type"]:
                        is_login = _looks_like_login_page(ev["body_lower"])
                        same_as_baseline = baseline and (ev["hash"] == baseline["hash"])

                        if is_login or same_as_baseline:
                            findings.append({
                                "title": f"Access Control Gate Suspected: {path}",
                                "severity": "Info",
                                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                                "description": (
                                    "Endpoint returned 200 but content looks like a login page or matches the baseline page. "
                                    "Likely gated or routed."
                                ),
                                "remediation": "Verify authorization is enforced after login and content is not leaked.",
                                "metadata": {
                                    "endpoint": url,
                                    "status": ev["status"],
                                    "login_like": is_login,
                                    "same_as_baseline": bool(same_as_baseline)
                                }
                            })
                            continue

                        findings.append({
                            "title": f"Potential Unrestricted Access: {path}",
                            "severity": "High",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            "description": (
                                "Sensitive-looking endpoint returned 200 and does not appear to be a login page. "
                                "This may indicate missing authentication/authorization."
                            ),
                            "remediation": "Enforce authentication and role-based access control (RBAC).",
                            "metadata": {
                                "endpoint": url,
                                "status": ev["status"],
                                "content_hash": ev["hash"],
                                "content_len": ev["len"]
                            }
                        })
                        continue

                    # 200 OK JSON
                    if ev["status"] == 200 and "application/json" in ev["content_type"]:
                        findings.append({
                            "title": f"Potential Unrestricted API Access: {path}",
                            "severity": "High",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            "description": "API endpoint returned JSON with 200 OK. Verify authorization is enforced.",
                            "remediation": "Require auth tokens and enforce object-level access control.",
                            "metadata": {
                                "endpoint": url,
                                "status": ev["status"],
                                "content_type": ev["content_type"],
                                "content_len": ev["len"]
                            }
                        })

                except aiohttp.ClientError:
                    continue
                except Exception:
                    continue

            # IDOR signal test
            try:
                u1 = urljoin(base, "user/1")
                u2 = urljoin(base, "user/2")

                ev1 = await _fetch(session, u1)
                ev2 = await _fetch(session, u2)

                if ev1["status"] == 200 and ev2["status"] == 200:
                    login_like = _looks_like_login_page(ev1["body_lower"]) or _looks_like_login_page(ev2["body_lower"])
                    same_as_baseline = baseline and (ev1["hash"] == baseline["hash"] or ev2["hash"] == baseline["hash"])

                    if not login_like and not same_as_baseline and ev1["hash"] != ev2["hash"]:
                        findings.append({
                            "title": "Possible IDOR Signal (Sequential Object Access)",
                            "severity": "High",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                            "description": (
                                "Two sequential object endpoints returned 200 with different content. "
                                "If the user is not authenticated, this can indicate missing object-level authorization."
                            ),
                            "remediation": (
                                "Enforce object-level authorization checks for every request (verify ownership/role). "
                                "Do not rely on sequential IDs alone."
                            ),
                            "metadata": {
                                "endpoint_1": u1,
                                "endpoint_2": u2,
                                "status_1": ev1["status"],
                                "status_2": ev2["status"],
                                "hash_1": ev1["hash"],
                                "hash_2": ev2["hash"],
                            }
                        })
            except Exception:
                pass

    except Exception as e:
        findings.append({
            "title": "Access Control Scan Failed",
            "severity": "Info",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            "description": str(e),
            "remediation": "Ensure the target is reachable."
        })

    return findings