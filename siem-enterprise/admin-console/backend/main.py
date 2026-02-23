"""
Admin Console Backend — API complète pour dashboard SIEM
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import asyncpg
import redis.asyncio as redis
import httpx
import os
import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://siem_admin:SecurePass2024!@postgres:5432/siem_enterprise")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
WAF_API_URL = os.getenv("WAF_API_URL", "http://waf:8080")
ML_ENGINE_URL = os.getenv("ML_ENGINE_URL", "http://ml-engine:8002")
RISK_ENGINE_URL = os.getenv("RISK_ENGINE_URL", "http://risk-engine:8003")
SOAR_API_URL = os.getenv("SOAR_API_URL", "http://soar:8004")
PLANGEN_API_URL = os.getenv("PLANGEN_API_URL", "http://plan-generator:8005")
INGESTION_API_URL = os.getenv("INGESTION_API_URL", "http://ingestion:8001")

db_pool: Optional[asyncpg.Pool] = None
redis_client: Optional[redis.Redis] = None

async def ensure_tables(conn):
    """Ensure all tables exist"""
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS system_config (
            key VARCHAR(100) PRIMARY KEY,
            value TEXT NOT NULL,
            value_type VARCHAR(20) DEFAULT 'STRING',
            description TEXT,
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            updated_by VARCHAR(100)
        )
    """)
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            timestamp TIMESTAMPTZ DEFAULT NOW(),
            event_type VARCHAR(50) NOT NULL,
            event_category VARCHAR(50),
            user_id VARCHAR(100),
            user_ip VARCHAR(45),
            description TEXT,
            changes JSONB,
            severity VARCHAR(20) DEFAULT 'INFO'
        )
    """)
    # Insert defaults
    await conn.execute("""
        INSERT INTO system_config (key, value, value_type, description) VALUES
        ('waf_mode', 'audit', 'STRING', 'Mode WAF: audit, block ou strict'),
        ('automation_level', 'semi-auto', 'STRING', 'Niveau automatisation SOAR'),
        ('anomaly_threshold', '0.7', 'FLOAT', 'Seuil détection anomalies ML'),
        ('risk_threshold_block', '0.9', 'FLOAT', 'Seuil risque pour blocage auto'),
        ('risk_threshold_captcha', '0.7', 'FLOAT', 'Seuil risque pour CAPTCHA'),
        ('enable_auto_block', 'true', 'BOOLEAN', 'Activer blocage automatique SOAR'),
        ('enable_ml', 'true', 'BOOLEAN', 'Activer détection ML'),
        ('rate_limit_per_minute', '100', 'INTEGER', 'Rate limit par IP par minute'),
        ('block_duration_minutes', '60', 'INTEGER', 'Durée blocage auto en minutes'),
        ('enable_auto_plan', 'true', 'BOOLEAN', 'Génération auto plans incidents')
        ON CONFLICT (key) DO NOTHING
    """)

@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool, redis_client
    for attempt in range(15):
        try:
            db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=3, max_size=15)
            async with db_pool.acquire() as conn:
                await ensure_tables(conn)
            print("[ADMIN] PostgreSQL connected")
            break
        except Exception as e:
            print(f"[ADMIN] PG attempt {attempt+1}/15: {e}")
            await asyncio.sleep(3)

    for attempt in range(10):
        try:
            redis_client = await redis.from_url(REDIS_URL, decode_responses=True)
            await redis_client.ping()
            print("[ADMIN] Redis connected")
            break
        except Exception as e:
            print(f"[ADMIN] Redis attempt {attempt+1}/10: {e}")
            await asyncio.sleep(2)
    yield
    if db_pool:
        await db_pool.close()
    if redis_client:
        await redis_client.close()

app = FastAPI(title="SIEM Admin API", version="2.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Helpers ────────────────────────────────────────────────────────────────────
async def call_service(url: str, timeout: float = 5.0) -> dict:
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
            return r.json()
    except Exception as e:
        return {"error": str(e)}

async def post_service(url: str, json_data: dict = None, params: dict = None) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(url, json=json_data, params=params)
            return r.json()
    except Exception as e:
        return {"error": str(e)}

# ── Dashboard ──────────────────────────────────────────────────────────────────
@app.get("/api/dashboard/stats")
async def dashboard_stats():
    async with db_pool.acquire() as conn:
        now = datetime.utcnow()
        since_24h = now - timedelta(hours=24)

        total_24h = await conn.fetchval(
            "SELECT COUNT(*) FROM raw_requests WHERE timestamp > $1", since_24h) or 0
        blocked_24h = await conn.fetchval(
            "SELECT COUNT(*) FROM raw_requests WHERE is_blocked=true AND timestamp > $1", since_24h) or 0
        suspicious_24h = await conn.fetchval(
            "SELECT COUNT(*) FROM raw_requests WHERE is_suspicious=true AND timestamp > $1", since_24h) or 0
        open_incidents = await conn.fetchval(
            "SELECT COUNT(*) FROM incidents WHERE status IN ('OPEN','INVESTIGATING')") or 0
        anomalies_24h = await conn.fetchval(
            "SELECT COUNT(*) FROM ml_predictions WHERE is_anomaly=true AND predicted_at > $1", since_24h) or 0
        avg_risk = await conn.fetchval(
            "SELECT AVG(risk_score) FROM risk_assessments WHERE assessed_at > $1", since_24h) or 0.0

        top_ips = await conn.fetch("""
            SELECT client_ip, COUNT(*) as total,
                   SUM(CASE WHEN is_blocked THEN 1 ELSE 0 END) as blocked,
                   MAX(timestamp) as last_seen
            FROM raw_requests WHERE timestamp > $1
            GROUP BY client_ip ORDER BY blocked DESC, total DESC LIMIT 10
        """, since_24h)

        top_owasp = await conn.fetch("""
            SELECT owasp_category, COUNT(*) as count, AVG(confidence) as avg_confidence
            FROM owasp_detections WHERE timestamp > $1
            GROUP BY owasp_category ORDER BY count DESC LIMIT 10
        """, since_24h)

        timeline = await conn.fetch("""
            SELECT DATE_TRUNC('hour', timestamp) as hour,
                   COUNT(*) as total,
                   SUM(CASE WHEN is_blocked THEN 1 ELSE 0 END) as blocked,
                   SUM(CASE WHEN is_suspicious THEN 1 ELSE 0 END) as suspicious
            FROM raw_requests WHERE timestamp > $1
            GROUP BY hour ORDER BY hour
        """, since_24h)

        attack_distribution = await conn.fetch("""
            SELECT attack_type, COUNT(*) as count
            FROM ml_predictions WHERE predicted_at > $1 AND attack_type != 'BENIGN'
            GROUP BY attack_type ORDER BY count DESC
        """, since_24h)

    return {
        "kpis": {
            "total_requests_24h": total_24h,
            "blocked_24h": blocked_24h,
            "suspicious_24h": suspicious_24h,
            "open_incidents": open_incidents,
            "anomalies_24h": anomalies_24h,
            "avg_risk_score": round(float(avg_risk), 3),
            "block_rate": round(blocked_24h / max(total_24h, 1), 3)
        },
        "top_ips": [dict(r) for r in top_ips],
        "top_owasp": [dict(r) for r in top_owasp],
        "timeline": [dict(r) for r in timeline],
        "attack_distribution": [dict(r) for r in attack_distribution]
    }

@app.get("/api/dashboard/live")
async def live_activity(limit: int = 100):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT rr.id, rr.timestamp, rr.method, rr.url, rr.path,
                   rr.client_ip, rr.status_code, rr.response_time_ms,
                   rr.is_blocked, rr.is_suspicious, rr.waf_rules_triggered,
                   ra.risk_score, ra.risk_level, ra.recommended_action,
                   mp.is_anomaly, mp.attack_type, mp.confidence_level
            FROM raw_requests rr
            LEFT JOIN LATERAL (
                SELECT risk_score, risk_level, recommended_action FROM risk_assessments
                WHERE request_id = rr.id ORDER BY assessed_at DESC LIMIT 1
            ) ra ON true
            LEFT JOIN LATERAL (
                SELECT is_anomaly, attack_type, confidence_level FROM ml_predictions
                WHERE request_id = rr.id ORDER BY predicted_at DESC LIMIT 1
            ) mp ON true
            ORDER BY rr.timestamp DESC LIMIT $1
        """, limit)
    return {"requests": [dict(r) for r in rows]}

# ── Incidents ──────────────────────────────────────────────────────────────────
@app.get("/api/incidents")
async def get_incidents(status: Optional[str] = None, limit: int = 50):
    async with db_pool.acquire() as conn:
        if status:
            rows = await conn.fetch(
                "SELECT * FROM incidents WHERE status=$1 ORDER BY created_at DESC LIMIT $2", status, limit)
        else:
            rows = await conn.fetch("SELECT * FROM incidents ORDER BY created_at DESC LIMIT $1", limit)
    return {"incidents": [dict(r) for r in rows]}

@app.post("/api/incidents")
async def create_incident(incident_type: str, severity: str, source_ip: str = "", description: str = ""):
    result = await post_service(f"{SOAR_API_URL}/api/incidents", {
        "incident_type": incident_type, "severity": severity,
        "source_ip": source_ip, "description": description
    })
    return result

@app.put("/api/incidents/{incident_id}")
async def update_incident(incident_id: str, status: str):
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE incidents SET status=$1, updated_at=$2 WHERE id=$3",
            status, datetime.utcnow(), incident_id
        )
    return {"success": True}

@app.post("/api/incidents/{incident_id}/plan")
async def generate_incident_plan(incident_id: str):
    async with db_pool.acquire() as conn:
        inc = await conn.fetchrow("SELECT * FROM incidents WHERE id=$1", incident_id)
        if not inc:
            raise HTTPException(404, "Incident not found")
    return await post_service(f"{PLANGEN_API_URL}/api/generate", {
        "incident_id": incident_id, "attack_type": inc["incident_type"], "severity": inc["severity"]
    })

# ── IP Management ──────────────────────────────────────────────────────────────
@app.get("/api/ips/reputation")
async def ip_reputation(limit: int = 100):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT * FROM ip_reputation
            ORDER BY reputation_score ASC, blocked_requests DESC LIMIT $1
        """, limit)
    return {"ips": [dict(r) for r in rows]}

@app.get("/api/ips/blocked")
async def blocked_ips():
    return await call_service(f"{WAF_API_URL}/admin/blocked-ips")

@app.post("/api/ips/block")
async def block_ip(ip: str, reason: str = "Manual block", duration_minutes: int = 60):
    result = await post_service(f"{WAF_API_URL}/admin/block-ip", params={
        "ip": ip, "reason": reason, "duration_minutes": duration_minutes
    })
    async with db_pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO ip_reputation (ip_address, is_blacklisted, blacklist_reason, trust_level)
            VALUES ($1, true, $2, 'MALICIOUS')
            ON CONFLICT (ip_address) DO UPDATE SET is_blacklisted=true, blacklist_reason=$2, trust_level='MALICIOUS'
        """, ip, reason)
    return result

@app.post("/api/ips/unblock")
async def unblock_ip(ip: str):
    result = await post_service(f"{WAF_API_URL}/admin/unblock-ip", params={"ip": ip})
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE ip_reputation SET is_blacklisted=false WHERE ip_address=$1", ip
        )
    return result

@app.post("/api/ips/whitelist")
async def whitelist_ip(ip: str):
    async with db_pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO ip_reputation (ip_address, is_whitelisted, trust_level, reputation_score)
            VALUES ($1, true, 'TRUSTED', 1.0)
            ON CONFLICT (ip_address) DO UPDATE SET is_whitelisted=true, trust_level='TRUSTED', reputation_score=1.0
        """, ip)
    return {"success": True, "ip": ip}

# ── ML Management ──────────────────────────────────────────────────────────────
@app.get("/api/ml/stats")
async def ml_stats():
    return await call_service(f"{ML_ENGINE_URL}/api/stats")

@app.get("/api/ml/models")
async def ml_models():
    return await call_service(f"{ML_ENGINE_URL}/api/models/active")

@app.post("/api/ml/train")
async def ml_train():
    return await post_service(f"{ML_ENGINE_URL}/api/train/anomaly")

@app.post("/api/ml/predict")
async def ml_predict(url: str = "", body: str = "", user_agent: str = ""):
    return await post_service(f"{ML_ENGINE_URL}/api/predict/direct", {
        "url": url, "body": body, "user_agent": user_agent
    })

# ── SOAR ──────────────────────────────────────────────────────────────────────
@app.get("/api/soar/actions")
async def soar_actions(limit: int = 50):
    return await call_service(f"{SOAR_API_URL}/api/actions?limit={limit}")

@app.post("/api/soar/manual")
async def soar_manual(target_ip: str, action_type: str, reason: str = "SOC Manual", duration_minutes: int = 60):
    return await post_service(f"{SOAR_API_URL}/api/manual-action", {
        "target_ip": target_ip, "action_type": action_type,
        "reason": reason, "duration_minutes": duration_minutes
    })

@app.post("/api/soar/rollback/{action_id}")
async def soar_rollback(action_id: str):
    return await post_service(f"{SOAR_API_URL}/api/rollback/{action_id}")

# ── Configuration ──────────────────────────────────────────────────────────────
@app.get("/api/config")
async def get_config():
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM system_config")
    return {r["key"]: {"value": r["value"], "type": r["value_type"], "description": r["description"]} for r in rows}

@app.put("/api/config/{key}")
async def update_config(key: str, value: str):
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE system_config SET value=$1, updated_at=$2 WHERE key=$3",
            value, datetime.utcnow(), key
        )
    return {"success": True, "key": key, "value": value}

# ── Services Health ────────────────────────────────────────────────────────────
@app.get("/api/services/health")
async def services_health():
    services = {
        "waf": f"{WAF_API_URL}/health",
        "ingestion": f"{INGESTION_API_URL}/health",
        "ml-engine": f"{ML_ENGINE_URL}/health",
        "risk-engine": f"{RISK_ENGINE_URL}/health",
        "soar": f"{SOAR_API_URL}/health",
        "plan-generator": f"{PLANGEN_API_URL}/health",
    }
    results = {}
    async with httpx.AsyncClient(timeout=3.0) as client:
        for name, url in services.items():
            try:
                r = await client.get(url)
                results[name] = {"status": "healthy" if r.status_code == 200 else "degraded", "code": r.status_code}
            except Exception as e:
                results[name] = {"status": "unreachable", "error": str(e)}
    return results

# ── Export & Reports ───────────────────────────────────────────────────────────
@app.get("/api/export/summary")
async def export_summary(hours: int = 24):
    async with db_pool.acquire() as conn:
        since = datetime.utcnow() - timedelta(hours=hours)
        stats = await conn.fetchrow("""
            SELECT COUNT(*) as total, SUM(CASE WHEN is_blocked THEN 1 ELSE 0 END) as blocked,
                   COUNT(DISTINCT client_ip) as unique_ips
            FROM raw_requests WHERE timestamp > $1
        """, since)
        attacks = await conn.fetch("""
            SELECT owasp_category, COUNT(*) as count FROM owasp_detections
            WHERE timestamp > $1 GROUP BY owasp_category ORDER BY count DESC
        """, since)
        incidents = await conn.fetch(
            "SELECT severity, COUNT(*) as count FROM incidents WHERE created_at > $1 GROUP BY severity", since
        )
    return {
        "period_hours": hours,
        "generated_at": datetime.utcnow().isoformat(),
        "traffic": dict(stats),
        "top_attacks": [dict(r) for r in attacks],
        "incidents_by_severity": [dict(r) for r in incidents]
    }

@app.get("/api/export/owasp-report")
async def owasp_report():
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT od.owasp_category, od.owasp_code, od.severity,
                   COUNT(*) as total, AVG(od.confidence) as avg_confidence
            FROM owasp_detections od
            WHERE od.timestamp > NOW() - INTERVAL '7 days'
            GROUP BY od.owasp_category, od.owasp_code, od.severity
            ORDER BY total DESC
        """)
    return {"owasp_report": [dict(r) for r in rows], "generated_at": datetime.utcnow().isoformat()}

# ── WAF Admin ─────────────────────────────────────────────────────────────────
@app.post("/api/waf/mode")
async def change_waf_mode(mode: str):
    result = await post_service(f"{WAF_API_URL}/admin/change-mode", params={"mode": mode})
    async with db_pool.acquire() as conn:
        await conn.execute("UPDATE system_config SET value=$1 WHERE key='waf_mode'", mode)
    return result

@app.get("/api/waf/stats")
async def waf_stats():
    return await call_service(f"{WAF_API_URL}/admin/stats")

# ── Redis Stats ────────────────────────────────────────────────────────────────
@app.get("/api/stats/realtime")
async def realtime_stats():
    if not redis_client:
        return {"error": "Redis not available"}
    return await call_service(f"{INGESTION_API_URL}/api/stats/realtime")

@app.get("/health")
async def health():
    db_ok = db_pool is not None
    redis_ok = redis_client is not None
    return {
        "status": "healthy" if db_ok else "degraded",
        "database": "connected" if db_ok else "disconnected",
        "redis": "connected" if redis_ok else "disconnected"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
