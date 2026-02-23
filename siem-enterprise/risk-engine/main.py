"""
Risk Engine — Score de risque pondéré + Décision automatique
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, List
import asyncpg
import os
import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://siem_admin:SecurePass2024!@postgres:5432/siem_enterprise")
ML_ENGINE_URL = os.getenv("ML_ENGINE_URL", "http://ml-engine:8002")
AUTOMATION_LEVEL = os.getenv("AUTOMATION_LEVEL", "semi-auto")
RISK_THRESHOLD_BLOCK = float(os.getenv("RISK_THRESHOLD_BLOCK", "0.9"))
RISK_THRESHOLD_CAPTCHA = float(os.getenv("RISK_THRESHOLD_CAPTCHA", "0.7"))

db_pool: Optional[asyncpg.Pool] = None

WEIGHTS = {"ml": 0.40, "owasp": 0.30, "behavioral": 0.20, "contextual": 0.10}

async def ensure_tables(conn):
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS risk_assessments (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            request_id UUID,
            assessed_at TIMESTAMPTZ DEFAULT NOW(),
            risk_score FLOAT NOT NULL,
            risk_level VARCHAR(20),
            ml_score_weight FLOAT, owasp_score_weight FLOAT, behavioral_score_weight FLOAT,
            recommended_action VARCHAR(50), automation_level VARCHAR(20),
            contributing_factors JSONB, explanation TEXT
        )
    """)
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_reputation (
            ip_address VARCHAR(45) PRIMARY KEY,
            first_seen TIMESTAMPTZ DEFAULT NOW(), last_seen TIMESTAMPTZ DEFAULT NOW(),
            total_requests INTEGER DEFAULT 0, blocked_requests INTEGER DEFAULT 0,
            suspicious_requests INTEGER DEFAULT 0, reputation_score FLOAT DEFAULT 0.5,
            trust_level VARCHAR(20) DEFAULT 'NEUTRAL',
            is_whitelisted BOOLEAN DEFAULT false, is_blacklisted BOOLEAN DEFAULT false,
            blacklist_reason TEXT, blacklist_expires_at TIMESTAMPTZ
        )
    """)
    await conn.execute("""
        CREATE OR REPLACE FUNCTION update_ip_rep() RETURNS TRIGGER AS $$
        BEGIN
            INSERT INTO ip_reputation (ip_address, last_seen, total_requests, blocked_requests, suspicious_requests)
            VALUES (NEW.client_ip, NEW.timestamp, 1,
                CASE WHEN NEW.is_blocked THEN 1 ELSE 0 END,
                CASE WHEN NEW.is_suspicious THEN 1 ELSE 0 END)
            ON CONFLICT (ip_address) DO UPDATE SET
                last_seen = EXCLUDED.last_seen,
                total_requests = ip_reputation.total_requests + 1,
                blocked_requests = ip_reputation.blocked_requests + EXCLUDED.blocked_requests,
                suspicious_requests = ip_reputation.suspicious_requests + EXCLUDED.suspicious_requests,
                reputation_score = CASE
                    WHEN (ip_reputation.blocked_requests + EXCLUDED.blocked_requests)::float /
                         NULLIF(ip_reputation.total_requests + 1, 0) > 0.5 THEN 0.1
                    WHEN (ip_reputation.blocked_requests + EXCLUDED.blocked_requests)::float /
                         NULLIF(ip_reputation.total_requests + 1, 0) > 0.2 THEN 0.3
                    ELSE 0.7
                END;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    # Only create trigger if not exists
    await conn.execute("""
        DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_ip_rep') THEN
                CREATE TRIGGER trg_ip_rep AFTER INSERT ON raw_requests
                FOR EACH ROW EXECUTE FUNCTION update_ip_rep();
            END IF;
        END $$;
    """)

@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool
    for attempt in range(15):
        try:
            db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=8)
            async with db_pool.acquire() as conn:
                await ensure_tables(conn)
            print(f"[RISK] PostgreSQL connected — Automation: {AUTOMATION_LEVEL}")
            break
        except Exception as e:
            print(f"[RISK] PG attempt {attempt+1}/15: {e}")
            await asyncio.sleep(3)
    yield
    if db_pool:
        await db_pool.close()

app = FastAPI(title="SIEM Risk Engine", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class AssessRequest(BaseModel):
    request_id: str

def calculate_risk(ml_data: Dict, owasp_data: List, behavioral: Dict) -> float:
    # ML score
    ml_score = 0.0
    if ml_data:
        ml_score = ml_data.get("anomaly_score", 0.0) * 0.6 + ml_data.get("attack_probability", 0.0) * 0.4

    # OWASP score
    severity_map = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.3}
    owasp_score = max([severity_map.get(d.get("severity", "LOW"), 0.3) for d in owasp_data], default=0.0)

    # Behavioral score
    blocked_ratio = behavioral.get("blocked_ratio", 0.0)
    behavioral_score = min(blocked_ratio * 2.0, 1.0)

    return min(
        ml_score * WEIGHTS["ml"] +
        owasp_score * WEIGHTS["owasp"] +
        behavioral_score * WEIGHTS["behavioral"],
        1.0
    )

def decide_action(risk_score: float) -> Dict:
    global AUTOMATION_LEVEL
    AUTOMATION_LEVEL = os.getenv("AUTOMATION_LEVEL", "semi-auto")

    if risk_score >= RISK_THRESHOLD_BLOCK:
        action, level = "BLOCK_IP", "CRITICAL"
    elif risk_score >= RISK_THRESHOLD_CAPTCHA:
        action, level = "CAPTCHA", "HIGH"
    elif risk_score >= 0.5:
        action, level = "RATE_LIMIT", "MEDIUM"
    else:
        action, level = "ALERT_ONLY", "LOW"

    requires_validation = {
        "manual": True,
        "semi-auto": risk_score >= 0.8,
        "auto": risk_score >= 0.95,
        "strict": False
    }.get(AUTOMATION_LEVEL, True)

    return {"action": action, "level": level, "requires_validation": requires_validation}

@app.post("/api/assess")
async def assess_risk(req: AssessRequest):
    try:
        async with db_pool.acquire() as conn:
            ml = await conn.fetchrow(
                "SELECT anomaly_score, attack_type, attack_probability FROM ml_predictions WHERE request_id=$1 ORDER BY predicted_at DESC LIMIT 1",
                req.request_id
            )
            owasp = await conn.fetch(
                "SELECT owasp_category, severity FROM owasp_detections WHERE request_id=$1",
                req.request_id
            )
            rr = await conn.fetchrow("SELECT client_ip FROM raw_requests WHERE id=$1", req.request_id)
            if not rr:
                raise HTTPException(404, "Request not found")

            ip_rep = await conn.fetchrow(
                "SELECT total_requests, blocked_requests, reputation_score FROM ip_reputation WHERE ip_address=$1",
                rr["client_ip"]
            )

            ml_data = dict(ml) if ml else {}
            owasp_data = [dict(d) for d in owasp]
            behavioral = {}
            if ip_rep:
                behavioral = {
                    "blocked_ratio": ip_rep["blocked_requests"] / max(ip_rep["total_requests"], 1),
                    "reputation_score": ip_rep["reputation_score"]
                }

            risk_score = calculate_risk(ml_data, owasp_data, behavioral)
            decision = decide_action(risk_score)

            assessment_id = await conn.fetchval("""
                INSERT INTO risk_assessments (
                    request_id, assessed_at, risk_score, risk_level,
                    ml_score_weight, owasp_score_weight, behavioral_score_weight,
                    recommended_action, automation_level, contributing_factors, explanation
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id
            """,
                req.request_id, datetime.utcnow(), risk_score, decision["level"],
                WEIGHTS["ml"], WEIGHTS["owasp"], WEIGHTS["behavioral"],
                decision["action"], AUTOMATION_LEVEL,
                json.dumps({"ml": ml_data, "owasp_count": len(owasp_data), "behavioral": behavioral}),
                f"Risk {risk_score:.2f} → {decision['action']}"
            )

        return {
            "success": True, "assessment_id": str(assessment_id),
            "risk_score": risk_score, "risk_level": decision["level"],
            "recommended_action": decision["action"],
            "requires_validation": decision["requires_validation"],
            "client_ip": rr["client_ip"]
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Risk error: {str(e)}")

@app.get("/api/assessments/recent")
async def recent_assessments(limit: int = 20):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM risk_assessments ORDER BY assessed_at DESC LIMIT $1", limit
        )
    return {"assessments": [dict(r) for r in rows]}

@app.get("/health")
async def health():
    return {"status": "healthy", "automation_level": AUTOMATION_LEVEL}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
