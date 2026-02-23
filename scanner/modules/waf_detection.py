import aiohttp
import asyncio
import time
import hashlib

SUSPICIOUS_PAYLOADS = [
    "' OR 1=1--",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
]

WAF_FINGERPRINTS = {
    "cloudflare": ["cf-ray", "_cf_bm", "cloudflare"],
    "akamai": ["akamai", "akamaighost"],
    "imperva": ["incapsula", "imperva"],
    "sucuri": ["sucuri", "x-sucuri"],
    "aws waf": ["aws", "awselb"],
    "f5": ["big-ip", "f5"],
}

BLOCK_PATTERNS = [
    "access denied",
    "request blocked",
    "forbidden",
    "malicious request",
    "not allowed",
]


async def fetch(session, url):
    try:
        start = time.time()
        async with session.get(url, timeout=10) as response:
            body = await response.text()
            elapsed = time.time() - start
            return response.status, response.headers, body, elapsed
    except:
        return None, {}, "", 0


def hash_body(body):
    return hashlib.sha256(body.encode()).hexdigest()


async def scan(target):
    findings = []
    confidence_score = 0
    detected_vendor = None

    async with aiohttp.ClientSession() as session:

        # -------------------------
        # 1 BASELINE REQUEST
        # -------------------------
        base_status, base_headers, base_body, base_time = await fetch(session, target)

        if base_status is None:
            return findings

        base_hash = hash_body(base_body)
        header_blob = str({k.lower(): v.lower() for k, v in base_headers.items()})

        # -------------------------
        # 2 FINGERPRINT ENGINE
        # -------------------------
        for vendor, indicators in WAF_FINGERPRINTS.items():
            if any(indicator in header_blob for indicator in indicators):
                detected_vendor = vendor
                confidence_score += 40
                break

        # -------------------------
        # 3 ACTIVE TESTING
        # -------------------------
        block_detected = False
        timing_variation = False
        content_variation = False

        for payload in SUSPICIOUS_PAYLOADS:
            test_url = f"{target}?elite_test={payload}"

            status, headers, body, elapsed = await fetch(session, test_url)

            if status is None:
                continue

            body_lower = body.lower()

            # Status-based blocking
            if status in [403, 406, 429]:
                block_detected = True
                confidence_score += 15

            # Body pattern blocking
            if any(pattern in body_lower for pattern in BLOCK_PATTERNS):
                block_detected = True
                confidence_score += 15

            # Content hash difference
            if hash_body(body) != base_hash:
                content_variation = True
                confidence_score += 10

            # Timing anomaly detection
            if abs(elapsed - base_time) > 1.5:
                timing_variation = True
                confidence_score += 10

        # -------------------------
        # 4️ CONFIDENCE SCORING
        # -------------------------
        confidence_score = min(confidence_score, 100)

        if confidence_score >= 60:
            severity = "Info"
            description = f"WAF detected with {confidence_score}% confidence."
        elif confidence_score >= 30:
            severity = "Low"
            description = f"Possible WAF presence ({confidence_score}% confidence)."
        else:
            return findings

        findings.append({
            "title": "Advanced WAF Detection",
            "severity": severity,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            "description": description,
            "remediation": "Review WAF configuration, rule tuning, and false-positive handling.",
            "metadata": {
                "vendor": detected_vendor,
                "confidence": confidence_score,
                "block_behavior": block_detected,
                "timing_variation": timing_variation,
                "content_variation": content_variation
            }
        })

    return findings