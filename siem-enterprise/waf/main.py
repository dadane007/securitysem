"""
WAF Intelligent — OWASP Top 10, Rate Limiting, Mode Audit/Block/Strict
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import redis.asyncio as redis
import httpx
import time
import re
import json
import asyncio
from typing import Optional
from datetime import datetime
import os

app = FastAPI(title="SIEM WAF", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
INGESTION_API_URL = os.getenv("INGESTION_API_URL", "http://ingestion:8001")
WAF_MODE = os.getenv("WAF_MODE", "audit")
RATE_LIMIT_PER_MINUTE = int(os.getenv("MAX_REQUESTS_PER_MINUTE", "100"))

redis_client: Optional[redis.Redis] = None

# ── OWASP Patterns ────────────────────────────────────────────────────────────
OWASP_PATTERNS = {
    "SQL_INJECTION": {
        "code": "A03:2021", "severity": "CRITICAL",
        "patterns": [
            r"(\bUNION\b.*\bSELECT\b)", r"(\bOR\b\s+\d+\s*=\s*\d+)",
            r"(';?\s*DROP\s+TABLE)", r"(1'\s*OR\s*'1'\s*=\s*'1)",
            r"(\bEXEC\b.*\bxp_cmdshell\b)", r"(\bINSERT\b.*\bINTO\b.*\bVALUES\b)",
            r"(--\s*$)", r"(/\*.*\*/)", r"(\bSLEEP\s*\(\d+\))",
        ]
    },
    "XSS": {
        "code": "A03:2021", "severity": "HIGH",
        "patterns": [
            r"(<script[^>]*>)", r"(javascript:)", r"(onerror\s*=)",
            r"(onload\s*=)", r"(<iframe)", r"(document\.cookie)",
            r"(eval\s*\()", r"(alert\s*\()", r"(String\.fromCharCode)",
        ]
    },
    "PATH_TRAVERSAL": {
        "code": "A01:2021", "severity": "HIGH",
        "patterns": [
            r"(\.\./|\.\.\\)", r"(%2e%2e[/%5c])", r"(\.\.%2f)",
            r"(/etc/passwd)", r"(/etc/shadow)", r"(c:\\windows)",
        ]
    },
    "COMMAND_INJECTION": {
        "code": "A03:2021", "severity": "CRITICAL",
        "patterns": [
            r"(;\s*cat\s+/etc)", r"(\|\s*ls\s+)", r"(`[^`]+`)",
            r"(\$\([^)]+\))", r"(&&\s*whoami)", r"(;\s*id\s*;)",
        ]
    },
    "XXE": {
        "code": "A05:2021", "severity": "HIGH",
        "patterns": [r"(<!ENTITY)", r"(<!DOCTYPE.*SYSTEM)", r"(SYSTEM\s+['\"]file)"]
    },
    "SSRF": {
        "code": "A10:2021", "severity": "HIGH",
        "patterns": [
            r"(file://)", r"(gopher://)", r"(dict://)",
            r"(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.)",
        ]
    },
    "SCANNER": {
        "code": "A05:2021", "severity": "MEDIUM",
        "patterns": [r"(sqlmap)", r"(nikto)", r"(nmap)", r"(masscan)", r"(acunetix)"]
    }
}

SUSPICIOUS_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "acunetix", "nessus",
    "openvas", "dirbuster", "gobuster", "hydra", "medusa"
]

# ── Startup ────────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global redis_client, WAF_MODE
    WAF_MODE = os.getenv("WAF_MODE", "audit")
    for attempt in range(10):
        try:
            redis_client = await redis.from_url(REDIS_URL, decode_responses=True)
            await redis_client.ping()
            print(f"[WAF] Redis connected — Mode: {WAF_MODE}, RateLimit: {RATE_LIMIT_PER_MINUTE}/min")
            return
        except Exception as e:
            print(f"[WAF] Redis attempt {attempt+1}/10: {e}")
            await asyncio.sleep(3)
    print("[WAF] WARNING: Redis not available, continuing without rate limiting")

@app.on_event("shutdown")
async def shutdown():
    if redis_client:
        await redis_client.close()

# ── Detection Engine ───────────────────────────────────────────────────────────
async def detect_owasp(request: Request, body: str) -> list:
    detections = []
    url = str(request.url)
    content = f"{url} {request.url.query or ''} {body}".lower()
    ua = (request.headers.get("User-Agent") or "").lower()

    for attack_type, config in OWASP_PATTERNS.items():
        for pattern in config["patterns"]:
            if re.search(pattern, content, re.IGNORECASE):
                detections.append({
                    "type": attack_type, "code": config["code"],
                    "severity": config["severity"], "confidence": 0.9
                })
                break

    # Check suspicious UA
    for sus_ua in SUSPICIOUS_USER_AGENTS:
        if sus_ua in ua:
            detections.append({
                "type": "SCANNER", "code": "A05:2021",
                "severity": "MEDIUM", "confidence": 0.95, "ua": sus_ua
            })
            break

    return detections

async def check_rate_limit(client_ip: str) -> tuple:
    if not redis_client:
        return True, 0
    try:
        key = f"ratelimit:{client_ip}"
        current = await redis_client.incr(key)
        if current == 1:
            await redis_client.expire(key, 60)
        return current <= RATE_LIMIT_PER_MINUTE, current
    except Exception:
        return True, 0

async def is_ip_blocked(client_ip: str) -> tuple:
    if not redis_client:
        return False, None
    try:
        key = f"blocked_ip:{client_ip}"
        reason = await redis_client.get(key)
        return reason is not None, reason
    except Exception:
        return False, None

async def block_ip(client_ip: str, reason: str, duration_minutes: int = 60):
    if not redis_client:
        return
    try:
        key = f"blocked_ip:{client_ip}"
        await redis_client.setex(key, duration_minutes * 60, reason)
        print(f"[WAF] Blocked {client_ip} for {duration_minutes}min — {reason}")
    except Exception as e:
        print(f"[WAF] Block error: {e}")

async def send_to_ingestion(data: dict):
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(f"{INGESTION_API_URL}/api/ingest", json=data)
    except Exception:
        pass  # Don't block on ingestion failure

# ── Main Middleware ────────────────────────────────────────────────────────────
@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    # Skip health endpoint
    if request.url.path == "/health":
        return await call_next(request)

    start_time = time.time()
    client_ip = request.headers.get("X-Forwarded-For", request.client.host).split(",")[0].strip()

    # 1. Check blocked IP
    blocked, block_reason = await is_ip_blocked(client_ip)
    if blocked:
        asyncio.create_task(send_to_ingestion({
            "timestamp": datetime.utcnow().isoformat(), "client_ip": client_ip,
            "method": request.method, "url": str(request.url),
            "is_blocked": True, "block_reason": block_reason,
            "waf_rules_triggered": ["IP_BLOCKED"], "owasp_detections": []
        }))
        return JSONResponse(status_code=403, content={"error": "Access Denied", "reason": "IP blocked"})

    # 2. Rate limit
    rate_ok, count = await check_rate_limit(client_ip)
    if not rate_ok and WAF_MODE in ("block", "strict"):
        await block_ip(client_ip, "Rate limit exceeded", 15)
        return JSONResponse(status_code=429, content={"error": "Too Many Requests"})

    # 3. Read body & detect
    body_bytes = await request.body()
    body = body_bytes.decode("utf-8", errors="ignore")
    detections = await detect_owasp(request, body)
    is_suspicious = len(detections) > 0
    waf_rules = [d["type"] for d in detections]
    is_blocked_now = False

    # 4. Block if needed
    critical = any(d["severity"] == "CRITICAL" for d in detections)
    if is_suspicious and WAF_MODE in ("block", "strict"):
        if critical or WAF_MODE == "strict":
            is_blocked_now = True
            await block_ip(client_ip, f"OWASP: {waf_rules[0]}", 120)

    if is_blocked_now:
        asyncio.create_task(send_to_ingestion({
            "timestamp": datetime.utcnow().isoformat(), "client_ip": client_ip,
            "method": request.method, "url": str(request.url),
            "user_agent": request.headers.get("User-Agent"),
            "body": body[:500], "is_blocked": True, "is_suspicious": True,
            "waf_rules_triggered": waf_rules, "owasp_detections": detections
        }))
        return JSONResponse(status_code=403, content={"error": "Request Blocked", "rules": waf_rules})

    # 5. Let through
    response = await call_next(request)
    response_time = (time.time() - start_time) * 1000

    asyncio.create_task(send_to_ingestion({
        "timestamp": datetime.utcnow().isoformat(), "client_ip": client_ip,
        "method": request.method, "url": str(request.url),
        "path": request.url.path, "query_string": request.url.query,
        "user_agent": request.headers.get("User-Agent"),
        "body": body[:500], "status_code": response.status_code,
        "response_time_ms": response_time,
        "is_blocked": False, "is_suspicious": is_suspicious,
        "waf_rules_triggered": waf_rules, "owasp_detections": detections
    }))

    return response

# ── Admin Endpoints ────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "healthy", "mode": WAF_MODE, "service": "waf"}

@app.post("/admin/block-ip")
async def admin_block_ip(ip: str, reason: str = "Manual block", duration_minutes: int = 60):
    await block_ip(ip, reason, duration_minutes)
    return {"success": True, "ip": ip, "duration_minutes": duration_minutes}

@app.post("/admin/unblock-ip")
async def admin_unblock_ip(ip: str):
    if redis_client:
        await redis_client.delete(f"blocked_ip:{ip}")
    return {"success": True, "ip": ip}

@app.get("/admin/blocked-ips")
async def admin_blocked_ips():
    if not redis_client:
        return {"blocked_ips": [], "total": 0}
    keys = await redis_client.keys("blocked_ip:*")
    blocked = []
    for key in keys:
        ip_addr = key.replace("blocked_ip:", "")
        reason = await redis_client.get(key)
        ttl = await redis_client.ttl(key)
        blocked.append({"ip": ip_addr, "reason": reason, "expires_in_seconds": ttl})
    return {"blocked_ips": blocked, "total": len(blocked)}

@app.post("/admin/change-mode")
async def change_mode(mode: str):
    global WAF_MODE
    if mode not in ("audit", "block", "strict"):
        return {"error": "Mode must be audit, block or strict"}
    WAF_MODE = mode
    return {"success": True, "mode": WAF_MODE}

@app.get("/admin/stats")
async def admin_stats():
    if not redis_client:
        return {"error": "Redis not available"}
    blocked_keys = await redis_client.keys("blocked_ip:*")
    return {
        "mode": WAF_MODE,
        "rate_limit_per_minute": RATE_LIMIT_PER_MINUTE,
        "blocked_ips_count": len(blocked_keys)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
