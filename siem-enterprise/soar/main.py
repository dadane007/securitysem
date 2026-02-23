"""
SOAR Engine — Orchestration & Réponse Automatique aux Incidents
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict
import asyncpg
import httpx
import redis.asyncio as redis
import os
import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://siem_admin:SecurePass2024!@postgres:5432/siem_enterprise")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
WAF_API_URL = os.getenv("WAF_API_URL", "http://waf:8080")
INGESTION_API_URL = os.getenv("INGESTION_API_URL", "http://ingestion:8001")
ENABLE_AUTO_BLOCK = os.getenv("ENABLE_AUTO_BLOCK", "true").lower() == "true"
ENABLE_CAPTCHA = os.getenv("ENABLE_CAPTCHA", "true").lower() == "true"
BLOCK_DURATION = int(os.getenv("BLOCK_DURATION_MINUTES", "60"))

db_pool: Optional[asyncpg.Pool] = None
redis_client: Optional[redis.Redis] = None

async def ensure_tables(conn):
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS soar_actions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            risk_assessment_id UUID,
            executed_at TIMESTAMPTZ DEFAULT NOW(),
            action_type VARCHAR(50) NOT NULL,
            action_status VARCHAR(20),
            target_ip VARCHAR(45),
            duration_minutes INTEGER,
            execution_result TEXT,
            error_message TEXT,
            requires_validation BOOLEAN DEFAULT false,
            validated_by VARCHAR(100),
            validated_at TIMESTAMPTZ,
            rollback_at TIMESTAMPTZ,
            rollback_reason TEXT
        )
    """)
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW(),
            incident_type VARCHAR(100) NOT NULL, severity VARCHAR(20),
            status VARCHAR(20) DEFAULT 'OPEN',
            source_ip VARCHAR(45), affected_endpoints TEXT[], attack_vectors TEXT[],
            total_requests_involved INTEGER DEFAULT 1, blocked_requests_count INTEGER DEFAULT 0,
            mitre_tactic VARCHAR(100), mitre_technique VARCHAR(100),
            resolved_at TIMESTAMPTZ, resolution_time_minutes INTEGER, false_positive BOOLEAN DEFAULT false
        )
    """)

@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool, redis_client
    for attempt in range(15):
        try:
            db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=8)
            async with db_pool.acquire() as conn:
                await ensure_tables(conn)
            print(f"[SOAR] PostgreSQL connected — AutoBlock: {ENABLE_AUTO_BLOCK}")
            break
        except Exception as e:
            print(f"[SOAR] PG attempt {attempt+1}/15: {e}")
            await asyncio.sleep(3)

    for attempt in range(10):
        try:
            redis_client = await redis.from_url(REDIS_URL, decode_responses=True)
            await redis_client.ping()
            print("[SOAR] Redis connected")
            break
        except Exception as e:
            print(f"[SOAR] Redis attempt {attempt+1}/10: {e}")
            await asyncio.sleep(2)
    yield
    if db_pool:
        await db_pool.close()
    if redis_client:
        await redis_client.close()

app = FastAPI(title="SIEM SOAR Engine", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class ExecuteRequest(BaseModel):
    risk_assessment_id: str
    action_type: Optional[str] = None

class ManualActionRequest(BaseModel):
    target_ip: str
    action_type: str
    reason: str = "Manual SOC action"
    duration_minutes: int = 60

class IncidentRequest(BaseModel):
    incident_type: str
    severity: str
    source_ip: str
    description: str = ""

# ── Action Executor ────────────────────────────────────────────────────────────
async def execute_action(action_type: str, target_ip: str, duration_minutes: int) -> Dict:
    if action_type == "BLOCK_IP" and ENABLE_AUTO_BLOCK:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(
                    f"{WAF_API_URL}/admin/block-ip",
                    params={"ip": target_ip, "reason": "Auto-blocked by SOAR", "duration_minutes": duration_minutes}
                )
                if resp.status_code == 200:
                    if redis_client:
                        await redis_client.setex(f"blocked_ip:{target_ip}", duration_minutes * 60, "SOAR_AUTO_BLOCK")
                    return {"executed": True, "message": f"IP {target_ip} blocked for {duration_minutes}min"}
                return {"executed": False, "message": f"WAF returned {resp.status_code}"}
        except Exception as e:
            return {"executed": False, "message": f"WAF unreachable: {str(e)}"}

    elif action_type == "CAPTCHA" and ENABLE_CAPTCHA:
        if redis_client:
            await redis_client.setex(f"require_captcha:{target_ip}", duration_minutes * 60, "1")
        return {"executed": True, "message": f"CAPTCHA required for {target_ip}"}

    elif action_type == "RATE_LIMIT":
        if redis_client:
            await redis_client.setex(f"rate_limit_strict:{target_ip}", duration_minutes * 60, "10")
        return {"executed": True, "message": f"Strict rate limit (10/min) applied to {target_ip}"}

    elif action_type == "ALERT_ONLY":
        return {"executed": True, "message": "Alert logged — no blocking action"}

    return {"executed": False, "message": f"Unknown action: {action_type}"}

# ── Endpoints ──────────────────────────────────────────────────────────────────
@app.post("/api/execute")
async def execute_soar(req: ExecuteRequest):
    try:
        async with db_pool.acquire() as conn:
            assessment = await conn.fetchrow("""
                SELECT ra.*, rr.client_ip FROM risk_assessments ra
                JOIN raw_requests rr ON ra.request_id = rr.id
                WHERE ra.id = $1
            """, req.risk_assessment_id)

            if not assessment:
                raise HTTPException(404, "Risk assessment not found")

            action_type = req.action_type or assessment["recommended_action"]
            target_ip = assessment["client_ip"]
            risk_score = assessment["risk_score"]

            duration = BLOCK_DURATION if risk_score >= 0.9 else (30 if risk_score >= 0.7 else 15)
            result = await execute_action(action_type, target_ip, duration)

            # Create incident if critical
            incident_id = None
            if risk_score >= 0.8:
                incident_id = await conn.fetchval("""
                    INSERT INTO incidents (incident_type, severity, status, source_ip, blocked_requests_count)
                    VALUES ($1, $2, $3, $4, 1) RETURNING id
                """, assessment.get("recommended_action", "THREAT"), "CRITICAL" if risk_score >= 0.9 else "HIGH",
                    "OPEN" if not result["executed"] else "INVESTIGATING", target_ip)

            action_id = await conn.fetchval("""
                INSERT INTO soar_actions (
                    risk_assessment_id, executed_at, action_type, action_status,
                    target_ip, duration_minutes, execution_result
                ) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id
            """,
                req.risk_assessment_id, datetime.utcnow(), action_type,
                "EXECUTED" if result["executed"] else "FAILED",
                target_ip, duration, result["message"]
            )

        return {
            "success": True, "action_id": str(action_id),
            "action_type": action_type, "target_ip": target_ip,
            "executed": result["executed"], "message": result["message"],
            "incident_id": str(incident_id) if incident_id else None
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"SOAR error: {str(e)}")

@app.post("/api/manual-action")
async def manual_action(req: ManualActionRequest):
    result = await execute_action(req.action_type, req.target_ip, req.duration_minutes)
    async with db_pool.acquire() as conn:
        action_id = await conn.fetchval("""
            INSERT INTO soar_actions (action_type, action_status, target_ip, duration_minutes, execution_result)
            VALUES ($1,$2,$3,$4,$5) RETURNING id
        """, req.action_type, "EXECUTED" if result["executed"] else "FAILED",
            req.target_ip, req.duration_minutes, result["message"])
    return {"success": result["executed"], "action_id": str(action_id), **result}

@app.post("/api/incidents")
async def create_incident(req: IncidentRequest):
    async with db_pool.acquire() as conn:
        inc_id = await conn.fetchval("""
            INSERT INTO incidents (incident_type, severity, status, source_ip)
            VALUES ($1,$2,'OPEN',$3) RETURNING id
        """, req.incident_type, req.severity, req.source_ip)
    return {"success": True, "incident_id": str(inc_id)}

@app.put("/api/incidents/{incident_id}")
async def update_incident(incident_id: str, status: str):
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE incidents SET status=$1, updated_at=$2 WHERE id=$3",
            status, datetime.utcnow(), incident_id
        )
    return {"success": True}

@app.post("/api/rollback/{action_id}")
async def rollback(action_id: str):
    async with db_pool.acquire() as conn:
        action = await conn.fetchrow("SELECT * FROM soar_actions WHERE id=$1", action_id)
        if not action:
            raise HTTPException(404, "Action not found")

        if action["action_type"] == "BLOCK_IP":
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(f"{WAF_API_URL}/admin/unblock-ip", params={"ip": action["target_ip"]})
            except Exception:
                pass
        elif action["action_type"] in ("RATE_LIMIT", "CAPTCHA") and redis_client:
            key = f"{'rate_limit_strict' if action['action_type']=='RATE_LIMIT' else 'require_captcha'}:{action['target_ip']}"
            await redis_client.delete(key)

        await conn.execute(
            "UPDATE soar_actions SET rollback_at=$1, rollback_reason=$2 WHERE id=$3",
            datetime.utcnow(), "Manual rollback", action_id
        )

    return {"success": True, "message": f"Action {action_id} rolled back"}

@app.get("/api/actions")
async def get_actions(limit: int = 50):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM soar_actions ORDER BY executed_at DESC LIMIT $1", limit)
    return {"actions": [dict(r) for r in rows]}

@app.get("/api/incidents")
async def get_incidents(status: Optional[str] = None, limit: int = 50):
    async with db_pool.acquire() as conn:
        if status:
            rows = await conn.fetch(
                "SELECT * FROM incidents WHERE status=$1 ORDER BY created_at DESC LIMIT $2", status, limit
            )
        else:
            rows = await conn.fetch("SELECT * FROM incidents ORDER BY created_at DESC LIMIT $1", limit)
    return {"incidents": [dict(r) for r in rows]}

@app.get("/health")
async def health():
    return {"status": "healthy", "auto_block": ENABLE_AUTO_BLOCK}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)
