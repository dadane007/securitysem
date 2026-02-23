"""
Plan Generator — Plans de sécurité NIST/ISO27001 automatiques
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncpg
import os
import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://siem_admin:SecurePass2024!@postgres:5432/siem_enterprise")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

db_pool: Optional[asyncpg.Pool] = None

PLANS = {
    "SQL_INJECTION": {
        "immediate": [
            "Bloquer immédiatement l'IP source au niveau du WAF",
            "Isoler l'endpoint vulnérable si possible",
            "Vérifier les logs PostgreSQL pour accès non autorisés",
            "Révoquer les sessions actives suspectes",
            "Activer la journalisation étendue sur la base de données"
        ],
        "corrective": [
            "Implémenter des requêtes préparées (prepared statements) sur tous les endpoints",
            "Valider et assainir toutes les entrées utilisateur côté serveur",
            "Appliquer le principe du moindre privilège aux comptes de base de données",
            "Effectuer un audit de code complet (SAST) sur l'application",
            "Mettre à jour les règles WAF pour bloquer les patterns d'injection SQL"
        ],
        "preventive": [
            "Intégrer SAST/DAST dans le pipeline CI/CD (NIST PR.DS-6)",
            "Former les développeurs sur OWASP Top 10 — A03: Injection (NIST PR.AT-1)",
            "Effectuer des tests d'intrusion trimestriels (NIST ID.RA-1)",
            "Déployer un WAF en mode blocking permanent (NIST PR.PS-6)",
            "Implémenter un programme de bug bounty (NIST ID.IM-1)",
            "Assurer conformité RGPD Art.32 — Mesures techniques de sécurité",
            "Documenter selon ISO 27001 A.14.2 — Sécurité du développement"
        ],
        "mitre": "T1190 — Exploit Public-Facing Application",
        "nist": ["PR.DS-6", "PR.AT-1", "DE.CM-4", "RS.MI-1", "ID.RA-1"],
        "iso": ["A.14.2.1", "A.16.1.5", "A.12.6.1"],
        "remediation_hours": 8
    },
    "XSS": {
        "immediate": [
            "Bloquer l'IP source et invalider les sessions actives",
            "Identifier les endpoints affectés et activer CSP d'urgence",
            "Analyser si des données utilisateurs ont été volées",
            "Notifier les utilisateurs potentiellement affectés",
            "Activer la journalisation étendue"
        ],
        "corrective": [
            "Implémenter l'encodage systématique des sorties HTML",
            "Configurer une Content Security Policy (CSP) stricte",
            "Utiliser des bibliothèques d'assainissement XSS (DOMPurify)",
            "Activer les headers X-XSS-Protection et HttpOnly sur les cookies",
            "Valider toutes les entrées avec une whitelist stricte"
        ],
        "preventive": [
            "Adopter un framework front-end sécurisé (React, Vue) avec auto-escaping",
            "Implémenter Subresource Integrity pour les scripts externes",
            "Effectuer des tests XSS automatisés dans le pipeline CI/CD",
            "Former les développeurs sur les attaques XSS (NIST PR.AT-1)",
            "Assurer conformité ISO 27001 A.14.2 — Sécurité du développement"
        ],
        "mitre": "T1059.007 — JavaScript",
        "nist": ["PR.DS-6", "DE.CM-4", "RS.MI-1"],
        "iso": ["A.14.2.1", "A.16.1.5"],
        "remediation_hours": 6
    },
    "PATH_TRAVERSAL": {
        "immediate": [
            "Bloquer l'IP source immédiatement",
            "Vérifier si des fichiers sensibles ont été accédés (/etc/passwd, .env)",
            "Auditer les logs d'accès aux fichiers système",
            "Restreindre les permissions du processus applicatif",
            "Isoler l'endpoint vulnérable"
        ],
        "corrective": [
            "Valider et canonicaliser tous les chemins de fichiers côté serveur",
            "Implémenter une whitelist des répertoires accessibles",
            "Utiliser des API de système de fichiers sécurisées",
            "Configurer chroot/jail pour isoler l'application",
            "Mettre à jour les règles WAF pour détecter les traversées de chemin"
        ],
        "preventive": [
            "Déployer en environnement conteneurisé (Docker) avec volumes restreints",
            "Appliquer le principe du moindre privilège aux permissions fichiers",
            "Tester régulièrement avec des outils DAST (NIST ID.RA-1)",
            "Assurer conformité ISO 27001 A.9.4.1 — Restriction d'accès"
        ],
        "mitre": "T1083 — File and Directory Discovery",
        "nist": ["PR.AC-4", "DE.CM-4", "RS.MI-1"],
        "iso": ["A.9.4.1", "A.14.2.1"],
        "remediation_hours": 4
    },
    "BRUTE_FORCE": {
        "immediate": [
            "Bloquer l'IP source pour minimum 24 heures",
            "Verrouiller les comptes ciblés temporairement",
            "Activer MFA obligatoire pour tous les comptes administrateurs",
            "Analyser si un compte a été compromis",
            "Alerter les utilisateurs ciblés"
        ],
        "corrective": [
            "Implémenter un verrouillage de compte après 5 tentatives",
            "Ajouter un délai progressif entre les tentatives (backoff exponentiel)",
            "Déployer CAPTCHA sur les formulaires d'authentification",
            "Implémenter MFA pour tous les comptes à privilèges",
            "Utiliser des algorithmes de hachage forts (Argon2, bcrypt)"
        ],
        "preventive": [
            "Déployer une solution de gestion des identités (IAM) centralisée",
            "Implémenter une politique de mots de passe forte",
            "Surveiller en continu les tentatives d'authentification (NIST DE.CM-1)",
            "Assurer conformité ISO 27001 A.9.4.3 — Système de gestion des mots de passe"
        ],
        "mitre": "T1110 — Brute Force",
        "nist": ["PR.AC-1", "DE.CM-1", "RS.MI-3"],
        "iso": ["A.9.4.2", "A.9.4.3"],
        "remediation_hours": 3
    },
    "COMMAND_INJECTION": {
        "immediate": [
            "Isoler IMMÉDIATEMENT le serveur affecté du réseau",
            "Capturer une image forensique du système",
            "Bloquer l'IP source et toutes les IPs associées",
            "Vérifier si une backdoor ou webshell a été installée",
            "Alerter l'équipe de réponse aux incidents"
        ],
        "corrective": [
            "Ne jamais passer des entrées utilisateurs à des fonctions shell",
            "Utiliser des API à la place des commandes shell système",
            "Valider et assainir toutes les entrées avec une whitelist stricte",
            "Exécuter l'application avec un utilisateur sans privilège",
            "Implémenter des sandboxes pour les opérations système"
        ],
        "preventive": [
            "Adopter le principe Zéro Confiance pour les appels système",
            "Déployer en conteneur avec seccomp et AppArmor",
            "Tests d'intrusion réguliers avec scan d'injection de commandes",
            "Assurer conformité ISO 27001 A.14.2.5 — Principes d'ingénierie sécurisée"
        ],
        "mitre": "T1059 — Command and Scripting Interpreter",
        "nist": ["PR.DS-6", "DE.AE-3", "RS.MI-1"],
        "iso": ["A.14.2.5", "A.16.1.5"],
        "remediation_hours": 16
    },
    "SSRF": {
        "immediate": [
            "Bloquer l'IP source et l'endpoint vulnérable",
            "Vérifier si des services internes ont été accédés",
            "Auditer les requêtes sortantes des dernières 24h",
            "Alerter l'équipe réseau pour analyse des flux",
            "Vérifier si des métadonnées cloud (169.254.x.x) ont été lues"
        ],
        "corrective": [
            "Valider et restreindre les URLs acceptées via une whitelist stricte",
            "Bloquer les requêtes vers les plages IP privées (RFC 1918)",
            "Désactiver les redirections HTTP non nécessaires",
            "Implémenter un proxy sortant avec filtrage",
            "Segmenter le réseau pour isoler les services internes"
        ],
        "preventive": [
            "Architecture Zero Trust — ne jamais faire confiance aux URLs fournies",
            "Tester avec des outils SSRF spécialisés (SSRFMap)",
            "Assurer conformité ISO 27001 A.13.1.3 — Ségrégation réseau"
        ],
        "mitre": "T1090.002 — External Proxy",
        "nist": ["PR.AC-5", "DE.CM-7", "RS.MI-1"],
        "iso": ["A.13.1.3", "A.14.2.1"],
        "remediation_hours": 6
    },
    "DEFAULT": {
        "immediate": [
            "Isoler les systèmes affectés pour limiter la propagation",
            "Préserver les preuves numériques et logs",
            "Alerter l'équipe SOC et le management",
            "Évaluer l'étendue de la compromission",
            "Activer le plan de réponse aux incidents"
        ],
        "corrective": [
            "Analyser la cause racine de l'incident",
            "Appliquer les correctifs de sécurité nécessaires",
            "Mettre à jour les règles de détection et prévention",
            "Renforcer les contrôles de sécurité affectés",
            "Documenter l'incident et les leçons apprises"
        ],
        "preventive": [
            "Renforcer la surveillance continue des systèmes (NIST DE.CM-1)",
            "Mettre à jour les politiques de sécurité (NIST GV.PO-1)",
            "Former les équipes sur ce type d'incident (NIST PR.AT-1)",
            "Effectuer des tests d'intrusion réguliers (NIST ID.RA-1)",
            "Assurer conformité ISO 27001 A.16 — Gestion des incidents"
        ],
        "mitre": "T1499 — Endpoint Denial of Service",
        "nist": ["DE.CM-1", "RS.MA-1", "PR.AT-1"],
        "iso": ["A.16.1.1", "A.16.1.5"],
        "remediation_hours": 4
    }
}

def get_template(attack_type: str) -> dict:
    attack_upper = attack_type.upper().replace(" ", "_")
    for key in PLANS:
        if key in attack_upper or attack_upper in key:
            return PLANS[key]
    return PLANS["DEFAULT"]

async def ensure_tables(conn):
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS security_plans (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            incident_id UUID,
            generated_at TIMESTAMPTZ DEFAULT NOW(),
            attack_type VARCHAR(100),
            immediate_actions TEXT NOT NULL,
            corrective_measures TEXT NOT NULL,
            preventive_recommendations TEXT NOT NULL,
            nist_controls_applied TEXT[],
            iso27001_controls TEXT[],
            mitre_technique VARCHAR(100),
            estimated_remediation_hours INTEGER,
            generated_by VARCHAR(50) DEFAULT 'TEMPLATE',
            confidence_score FLOAT DEFAULT 0.8,
            validated_by VARCHAR(100),
            implementation_status VARCHAR(20) DEFAULT 'PENDING'
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
            print("[PLANGEN] PostgreSQL connected")
            break
        except Exception as e:
            print(f"[PLANGEN] PG attempt {attempt+1}/15: {e}")
            await asyncio.sleep(3)
    yield
    if db_pool:
        await db_pool.close()

app = FastAPI(title="SIEM Plan Generator", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class GenerateRequest(BaseModel):
    incident_id: Optional[str] = None
    attack_type: str = "UNKNOWN"
    severity: str = "HIGH"
    source_ip: str = ""

class DirectGenerateRequest(BaseModel):
    attack_type: str
    severity: str = "HIGH"

@app.post("/api/generate")
async def generate_plan(req: GenerateRequest):
    try:
        attack_type = req.attack_type
        if req.incident_id:
            async with db_pool.acquire() as conn:
                inc = await conn.fetchrow("SELECT * FROM incidents WHERE id=$1", req.incident_id)
                if inc:
                    attack_type = inc["incident_type"]

        template = get_template(attack_type)
        plan = {
            "attack_type": attack_type,
            "immediate_actions": "\n".join(f"{i+1}. {a}" for i, a in enumerate(template["immediate"])),
            "corrective_measures": "\n".join(f"{i+1}. {a}" for i, a in enumerate(template["corrective"])),
            "preventive_recommendations": "\n".join(f"{i+1}. {a}" for i, a in enumerate(template["preventive"])),
            "nist_controls": template["nist"],
            "iso27001_controls": template["iso"],
            "mitre_technique": template["mitre"],
            "estimated_hours": template["remediation_hours"],
            "generated_by": "TEMPLATE_ENGINE",
            "confidence_score": 0.85
        }

        async with db_pool.acquire() as conn:
            plan_id = await conn.fetchval("""
                INSERT INTO security_plans (
                    incident_id, attack_type,
                    immediate_actions, corrective_measures, preventive_recommendations,
                    nist_controls_applied, iso27001_controls, mitre_technique,
                    estimated_remediation_hours, generated_by, confidence_score
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id
            """,
                req.incident_id, attack_type,
                plan["immediate_actions"], plan["corrective_measures"], plan["preventive_recommendations"],
                plan["nist_controls"], plan["iso27001_controls"], plan["mitre_technique"],
                plan["estimated_hours"], plan["generated_by"], plan["confidence_score"]
            )

        return {"success": True, "plan_id": str(plan_id), **plan}
    except Exception as e:
        raise HTTPException(500, f"Plan generation error: {str(e)}")

@app.post("/api/generate/direct")
async def generate_direct(req: DirectGenerateRequest):
    template = get_template(req.attack_type)
    return {
        "attack_type": req.attack_type,
        "immediate_actions": template["immediate"],
        "corrective_measures": template["corrective"],
        "preventive_recommendations": template["preventive"],
        "nist_controls": template["nist"],
        "iso27001_controls": template["iso"],
        "mitre_technique": template["mitre"],
        "estimated_hours": template["remediation_hours"]
    }

@app.get("/api/plans")
async def get_plans(limit: int = 20):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM security_plans ORDER BY generated_at DESC LIMIT $1", limit)
    return {"plans": [dict(r) for r in rows]}

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "plan-generator"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8005)
