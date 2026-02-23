"""
ML Engine — Heuristique + scikit-learn (Isolation Forest, Random Forest)
Fallback heuristique si scikit-learn non disponible
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict
import asyncpg
import os
import asyncio
import re
import math
from contextlib import asynccontextmanager
from datetime import datetime
from collections import Counter

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://siem_admin:SecurePass2024!@postgres:5432/siem_enterprise")
ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "0.7"))
ML_MODE = os.getenv("ML_MODE", "auto")

db_pool: Optional[asyncpg.Pool] = None

# Try to import ML libs
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    import joblib
    ML_AVAILABLE = True
    print("[ML] scikit-learn available")
except ImportError:
    ML_AVAILABLE = False
    print("[ML] scikit-learn not available — using heuristic engine")

# ── Heuristic Detection Engine ─────────────────────────────────────────────────
SQL_PATTERNS = [
    r"union\s+select", r"'\s+or\s+", r"drop\s+table", r"1\s*=\s*1",
    r"exec\s*\(", r"xp_cmdshell", r"insert\s+into", r"sleep\s*\(\d",
    r"benchmark\s*\(", r"information_schema", r"--\s*$"
]
XSS_PATTERNS = [
    r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
    r"<iframe", r"document\.cookie", r"eval\s*\(", r"alert\s*\("
]
PATH_PATTERNS = [
    r"\.\./", r"\.\.\\", r"%2e%2e", r"/etc/passwd", r"/etc/shadow", r"c:\\windows"
]
CMD_PATTERNS = [
    r";\s*cat\s+", r"\|\s*ls\s+", r"`[^`]+`", r"\$\([^)]+\)", r"&&\s*whoami"
]
SCANNER_UAS = ["sqlmap", "nikto", "nmap", "masscan", "acunetix", "nessus", "dirbuster"]

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())

def heuristic_analyze(url: str = "", body: str = "", user_agent: str = "") -> Dict:
    content = f"{url} {body}".lower()
    ua = user_agent.lower()
    score = 0.0
    attack_type = "BENIGN"
    detections = []

    checks = [
        (SQL_PATTERNS, "SQL_INJECTION", 0.4),
        (XSS_PATTERNS, "XSS", 0.35),
        (PATH_PATTERNS, "PATH_TRAVERSAL", 0.3),
        (CMD_PATTERNS, "COMMAND_INJECTION", 0.45),
    ]
    for patterns, atype, weight in checks:
        hits = sum(1 for p in patterns if re.search(p, content, re.IGNORECASE))
        if hits > 0:
            contribution = min(hits * weight / len(patterns), weight)
            score += contribution
            detections.append(atype)
            if attack_type == "BENIGN":
                attack_type = atype

    # Scanner UA
    if any(s in ua for s in SCANNER_UAS):
        score += 0.3
        if attack_type == "BENIGN":
            attack_type = "SCANNER"

    # URL entropy
    entropy = calculate_entropy(url)
    if entropy > 4.5:
        score += 0.1

    # Special chars ratio
    special = len(re.findall(r"[<>'\";(){}|`$]", content))
    if special > 5:
        score += min(special * 0.02, 0.2)

    score = min(score, 1.0)
    is_anomaly = score >= ANOMALY_THRESHOLD

    return {
        "anomaly_score": round(score, 3),
        "is_anomaly": is_anomaly,
        "attack_type": attack_type,
        "attack_probability": round(score, 3),
        "confidence": "HIGH" if score > 0.8 else ("MEDIUM" if score > 0.5 else "LOW"),
        "method": "HEURISTIC_ENGINE",
        "detections": detections
    }

# ── Ensure Tables ──────────────────────────────────────────────────────────────
async def ensure_tables(conn):
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS features (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            request_id UUID,
            computed_at TIMESTAMPTZ DEFAULT NOW(),
            requests_per_minute FLOAT, requests_last_hour INTEGER, requests_last_day INTEGER,
            url_length INTEGER, url_entropy FLOAT, unique_endpoints_count INTEGER,
            url_suspicious_chars_count INTEGER, payload_length INTEGER, payload_entropy FLOAT,
            special_chars_ratio FLOAT, failed_login_attempts INTEGER, session_duration_seconds INTEGER,
            error_rate FLOAT, distinct_user_agents_count INTEGER, country_changes_count INTEGER,
            is_known_vpn BOOLEAN, is_tor_exit_node BOOLEAN, hour_of_day INTEGER,
            day_of_week INTEGER, is_business_hours BOOLEAN, feature_vector FLOAT[]
        )
    """)
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS ml_predictions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            request_id UUID,
            predicted_at TIMESTAMPTZ DEFAULT NOW(),
            anomaly_score FLOAT, is_anomaly BOOLEAN, anomaly_method VARCHAR(50),
            attack_type VARCHAR(100), attack_probability FLOAT, classification_method VARCHAR(50),
            confidence_level VARCHAR(20), model_version VARCHAR(50), top_features JSONB
        )
    """)
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS ml_models (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            created_at TIMESTAMPTZ DEFAULT NOW(),
            model_name VARCHAR(100) NOT NULL, model_type VARCHAR(50),
            algorithm VARCHAR(50), version VARCHAR(20) NOT NULL,
            accuracy FLOAT, precision_score FLOAT, recall FLOAT, f1_score FLOAT,
            training_samples_count INTEGER, is_active BOOLEAN DEFAULT false
        )
    """)

@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool
    for attempt in range(15):
        try:
            db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=8)
            async with db_pool.acquire() as conn:
                await ensure_tables(conn)
            print(f"[ML] PostgreSQL connected — Mode: {ML_MODE}, Threshold: {ANOMALY_THRESHOLD}")
            break
        except Exception as e:
            print(f"[ML] PG attempt {attempt+1}/15: {e}")
            await asyncio.sleep(3)
    yield
    if db_pool:
        await db_pool.close()

app = FastAPI(title="SIEM ML Engine", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Models ─────────────────────────────────────────────────────────────────────
class PredictRequest(BaseModel):
    request_id: str

class DirectPredictRequest(BaseModel):
    url: str = ""
    body: str = ""
    user_agent: str = ""
    client_ip: str = ""

# ── Endpoints ──────────────────────────────────────────────────────────────────
@app.post("/api/predict")
async def predict(req: PredictRequest):
    try:
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT url, body, user_agent, client_ip FROM raw_requests WHERE id = $1",
                req.request_id
            )
            if not row:
                raise HTTPException(404, "Request not found")

            result = heuristic_analyze(
                url=row["url"] or "",
                body=row["body"] or "",
                user_agent=row["user_agent"] or ""
            )

            await conn.execute("""
                INSERT INTO ml_predictions (
                    request_id, predicted_at, anomaly_score, is_anomaly, anomaly_method,
                    attack_type, attack_probability, classification_method, confidence_level, model_version
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            """,
                req.request_id, datetime.utcnow(),
                result["anomaly_score"], result["is_anomaly"], result["method"],
                result["attack_type"], result["attack_probability"],
                result["method"], result["confidence"], "heuristic-2.0"
            )

        return {"success": True, "request_id": req.request_id, **result}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Prediction error: {str(e)}")

@app.post("/api/predict/direct")
async def predict_direct(req: DirectPredictRequest):
    result = heuristic_analyze(url=req.url, body=req.body, user_agent=req.user_agent)
    return result

@app.post("/api/train/anomaly")
async def train_anomaly(background_tasks: BackgroundTasks):
    """Lance l'entraînement ML en arrière-plan"""
    if not ML_AVAILABLE:
        return {"message": "scikit-learn not available, using heuristic engine", "status": "heuristic"}

    async def train_task():
        try:
            async with db_pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT feature_vector FROM features WHERE feature_vector IS NOT NULL LIMIT 5000"
                )
            if len(rows) < 100:
                print("[ML] Not enough training data")
                return
            import numpy as np
            X = np.array([r["feature_vector"] for r in rows])
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            iso = IsolationForest(contamination=0.1, n_estimators=100, random_state=42, n_jobs=-1)
            iso.fit(X_scaled)
            version = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            try:
                joblib.dump({"model": iso, "scaler": scaler, "version": version}, f"/app/models/anomaly_{version}.pkl")
            except Exception:
                pass
            async with db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO ml_models (model_name, model_type, algorithm, version, training_samples_count, is_active)
                    VALUES ('anomaly_detector', 'ANOMALY_DETECTION', 'IsolationForest', $1, $2, true)
                """, version, len(rows))
            print(f"[ML] Training complete: {len(rows)} samples, version {version}")
        except Exception as e:
            print(f"[ML] Training error: {e}")

    background_tasks.add_task(train_task)
    return {"message": "Training started", "samples_needed": 100}

@app.get("/api/models/active")
async def get_models():
    async with db_pool.acquire() as conn:
        models = await conn.fetch(
            "SELECT * FROM ml_models WHERE is_active=true ORDER BY created_at DESC LIMIT 5"
        )
    return {
        "engine": "heuristic+sklearn" if ML_AVAILABLE else "heuristic",
        "models": [dict(m) for m in models],
        "threshold": ANOMALY_THRESHOLD
    }

@app.get("/api/stats")
async def get_stats():
    async with db_pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM ml_predictions") or 0
        anomalies = await conn.fetchval("SELECT COUNT(*) FROM ml_predictions WHERE is_anomaly=true") or 0
    return {
        "total_predictions": total, "anomalies_detected": anomalies,
        "anomaly_rate": round(anomalies / max(total, 1), 3),
        "engine": "heuristic+sklearn" if ML_AVAILABLE else "heuristic",
        "threshold": ANOMALY_THRESHOLD
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "mode": ML_MODE, "engine": "heuristic+sklearn" if ML_AVAILABLE else "heuristic"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
