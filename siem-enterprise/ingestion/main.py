"""
Service d'Ingestion — Normalisation OCSF, PostgreSQL, MinIO Data Lake
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime
import asyncpg
import aioboto3
import json
import hashlib
import redis.asyncio as redis
import os
import asyncio
from contextlib import asynccontextmanager

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://siem_admin:SecurePass2024!@postgres:5432/siem_enterprise")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin123")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

db_pool: Optional[asyncpg.Pool] = None
redis_client: Optional[redis.Redis] = None
s3_session = None

# ── Models ─────────────────────────────────────────────────────────────────────
class IngestRequest(BaseModel):
    timestamp: str
    method: str = "GET"
    url: str = ""
    path: Optional[str] = None
    query_string: Optional[str] = None
    client_ip: str = "0.0.0.0"
    user_agent: Optional[str] = None
    headers: Optional[Dict] = None
    body: Optional[str] = None
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    is_blocked: bool = False
    is_suspicious: bool = False
    waf_rules_triggered: Optional[List[str]] = None
    owasp_detections: Optional[List[Dict]] = None
    block_reason: Optional[str] = None

# ── Create Tables (fallback if init-db didn't run) ─────────────────────────────
async def ensure_tables(conn):
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS raw_requests (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            timestamp TIMESTAMPTZ DEFAULT NOW(),
            method VARCHAR(10) NOT NULL,
            url TEXT NOT NULL,
            path VARCHAR(500),
            query_string TEXT,
            headers JSONB,
            body TEXT,
            user_agent TEXT,
            content_type VARCHAR(100),
            client_ip VARCHAR(45) NOT NULL,
            status_code INTEGER,
            response_time_ms FLOAT,
            is_blocked BOOLEAN DEFAULT false,
            is_suspicious BOOLEAN DEFAULT false,
            waf_rules_triggered TEXT[],
            minio_object_key VARCHAR(500)
        )
    """)
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS owasp_detections (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            request_id UUID REFERENCES raw_requests(id) ON DELETE CASCADE,
            timestamp TIMESTAMPTZ DEFAULT NOW(),
            owasp_category VARCHAR(50) NOT NULL,
            owasp_code VARCHAR(20),
            severity VARCHAR(20),
            confidence FLOAT,
            payload_detected TEXT,
            detection_rule VARCHAR(100),
            false_positive BOOLEAN DEFAULT false
        )
    """)
    await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_rr_timestamp ON raw_requests(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_rr_client_ip ON raw_requests(client_ip);
        CREATE INDEX IF NOT EXISTS idx_rr_blocked ON raw_requests(is_blocked) WHERE is_blocked=true;
    """)
    print("[INGESTION] Tables ensured")

# ── Startup ────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool, redis_client, s3_session

    # PostgreSQL with retry
    for attempt in range(15):
        try:
            db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=3, max_size=10)
            async with db_pool.acquire() as conn:
                await ensure_tables(conn)
            print("[INGESTION] PostgreSQL connected")
            break
        except Exception as e:
            print(f"[INGESTION] PG attempt {attempt+1}/15: {e}")
            await asyncio.sleep(3)

    # Redis with retry
    for attempt in range(10):
        try:
            redis_client = await redis.from_url(REDIS_URL, decode_responses=True)
            await redis_client.ping()
            print("[INGESTION] Redis connected")
            break
        except Exception as e:
            print(f"[INGESTION] Redis attempt {attempt+1}/10: {e}")
            await asyncio.sleep(2)

    # MinIO
    s3_session = aioboto3.Session()
    try:
        async with s3_session.client(
            "s3", endpoint_url=f"http://{MINIO_ENDPOINT}",
            aws_access_key_id=MINIO_ACCESS_KEY, aws_secret_access_key=MINIO_SECRET_KEY
        ) as s3:
            try:
                await s3.create_bucket(Bucket="raw-logs")
                await s3.create_bucket(Bucket="ocsf-events")
            except Exception:
                pass
        print("[INGESTION] MinIO connected")
    except Exception as e:
        print(f"[INGESTION] MinIO warning: {e}")

    print("[INGESTION] Service ready")
    yield

    if db_pool:
        await db_pool.close()
    if redis_client:
        await redis_client.close()

app = FastAPI(title="SIEM Ingestion Service", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── OCSF Normalization ─────────────────────────────────────────────────────────
def normalize_to_ocsf(data: IngestRequest) -> Dict[str, Any]:
    return {
        "metadata": {"version": "1.1.0", "product": {"name": "SIEM Enterprise WAF"}},
        "class_name": "HTTP Activity", "class_uid": 4002,
        "severity": "High" if data.is_blocked else ("Medium" if data.is_suspicious else "Low"),
        "http_request": {"method": data.method, "url": data.url, "user_agent": data.user_agent},
        "http_response": {"code": data.status_code, "latency": data.response_time_ms},
        "src_endpoint": {"ip": data.client_ip},
        "disposition": "Blocked" if data.is_blocked else ("Quarantined" if data.is_suspicious else "Allowed"),
        "enrichments": [{"name": "WAF Rules", "value": data.waf_rules_triggered or []}]
    }

# ── MinIO Storage ──────────────────────────────────────────────────────────────
async def store_in_datalake(data: Dict[str, Any]) -> str:
    try:
        ts = datetime.utcnow()
        date_path = ts.strftime("%Y/%m/%d/%H")
        obj_id = hashlib.sha256(json.dumps(data, default=str).encode()).hexdigest()[:16]
        key = f"{date_path}/{obj_id}.json"
        async with s3_session.client(
            "s3", endpoint_url=f"http://{MINIO_ENDPOINT}",
            aws_access_key_id=MINIO_ACCESS_KEY, aws_secret_access_key=MINIO_SECRET_KEY
        ) as s3:
            await s3.put_object(
                Bucket="raw-logs", Key=key,
                Body=json.dumps(data, default=str).encode("utf-8"),
                ContentType="application/json"
            )
        return key
    except Exception as e:
        print(f"[INGESTION] MinIO write error: {e}")
        return "minio-unavailable"

# ── PostgreSQL Storage ─────────────────────────────────────────────────────────
async def store_in_postgres(data: IngestRequest, minio_key: str) -> str:
    try:
        ts = datetime.fromisoformat(data.timestamp.replace("Z", "+00:00").replace("+00:00+00:00", "+00:00"))
    except Exception:
        ts = datetime.utcnow()

    async with db_pool.acquire() as conn:
        request_id = await conn.fetchval("""
            INSERT INTO raw_requests (
                timestamp, method, url, path, query_string,
                headers, body, user_agent, content_type, client_ip,
                status_code, response_time_ms, is_blocked, is_suspicious,
                waf_rules_triggered, minio_object_key
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
            RETURNING id
        """,
            ts, data.method, data.url or "/", data.path, data.query_string,
            json.dumps(data.headers) if data.headers else None, data.body,
            data.user_agent,
            (data.headers or {}).get("content-type") if data.headers else None,
            data.client_ip, data.status_code, data.response_time_ms,
            data.is_blocked, data.is_suspicious,
            data.waf_rules_triggered or [], minio_key
        )

        if data.owasp_detections:
            for det in data.owasp_detections:
                await conn.execute("""
                    INSERT INTO owasp_detections (
                        request_id, owasp_category, owasp_code,
                        severity, confidence, payload_detected, detection_rule
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7)
                """,
                    request_id, det.get("type"), det.get("code"),
                    det.get("severity"), det.get("confidence"),
                    str(det.get("matches", [])), det.get("pattern", "")
                )

    return str(request_id)

# ── Redis Stats Update ─────────────────────────────────────────────────────────
async def update_redis_stats(data: IngestRequest):
    if not redis_client:
        return
    try:
        pipe = redis_client.pipeline()
        pipe.incr("stats:total_requests")
        if data.is_blocked:
            pipe.incr("stats:blocked_requests")
        if data.is_suspicious:
            pipe.incr("stats:suspicious_requests")
        pipe.zincrby("stats:top_ips", 1, data.client_ip)
        pipe.hincrby("stats:methods", data.method, 1)
        if data.owasp_detections:
            for det in data.owasp_detections:
                pipe.zincrby("stats:owasp_types", 1, det.get("type", "UNKNOWN"))
        await pipe.execute()
    except Exception as e:
        print(f"[INGESTION] Redis stats error: {e}")

# ── API Endpoints ──────────────────────────────────────────────────────────────
@app.post("/api/ingest")
async def ingest_request(data: IngestRequest):
    try:
        ocsf = normalize_to_ocsf(data)
        minio_key = await store_in_datalake({"original": data.dict(), "ocsf": ocsf})
        request_id = await store_in_postgres(data, minio_key)
        await update_redis_stats(data)
        return {"success": True, "request_id": request_id, "minio_key": minio_key}
    except Exception as e:
        print(f"[INGESTION] Error: {e}")
        raise HTTPException(500, f"Ingestion failed: {str(e)}")

@app.get("/api/stats/realtime")
async def realtime_stats():
    if not redis_client:
        return {"error": "Redis not available"}
    return {
        "total_requests": int(await redis_client.get("stats:total_requests") or 0),
        "blocked_requests": int(await redis_client.get("stats:blocked_requests") or 0),
        "suspicious_requests": int(await redis_client.get("stats:suspicious_requests") or 0),
        "top_ips": await redis_client.zrevrange("stats:top_ips", 0, 9, withscores=True),
        "methods": await redis_client.hgetall("stats:methods"),
        "owasp_types": await redis_client.zrevrange("stats:owasp_types", 0, 9, withscores=True)
    }

@app.get("/api/requests")
async def get_requests(limit: int = 50, offset: int = 0):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM raw_requests ORDER BY timestamp DESC LIMIT $1 OFFSET $2",
            limit, offset
        )
        return {"requests": [dict(r) for r in rows], "total": len(rows)}

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "ingestion"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
