# SIEM Enterprise v2.0

Système de sécurité web intelligent avec WAF, ML, SOAR et Dashboard professionnel.

## Architecture

```
Requête → WAF (8080) → Ingestion (8001) → PostgreSQL + MinIO
                                        → ML Engine (8002)
                                        → Risk Engine (8003)
                                        → SOAR (8004)
                                        → Plan Generator (8005)
                                        → Admin API (8000) → Dashboard (3000)
```

## Démarrage rapide

### Linux / Mac
```bash
chmod +x start.sh
./start.sh start
```

### Windows (PowerShell)
```powershell
.\start.ps1 start
```

### Manuel
```bash
docker compose up -d --build
```

## Interfaces

| Service | URL |
|---------|-----|
| **Dashboard** | http://localhost:3000 |
| **API Docs** | http://localhost:8000/docs |
| **WAF Admin** | http://localhost:8080/admin/stats |
| **MinIO Console** | http://localhost:9001 |

## Configuration (.env)

```env
WAF_MODE=audit              # audit | block | strict
AUTOMATION_LEVEL=semi-auto  # manual | semi-auto | auto | strict
ANOMALY_THRESHOLD=0.7       # 0.0 → 1.0
ENABLE_AUTO_BLOCK=true
```

## Services

| Service | Port | Rôle |
|---------|------|------|
| WAF | 8080 | Détection OWASP, Rate Limit, Blocage |
| Ingestion | 8001 | Normalisation OCSF, PostgreSQL, MinIO |
| ML Engine | 8002 | Détection anomalies + Classification |
| Risk Engine | 8003 | Score de risque pondéré |
| SOAR | 8004 | Réponse automatique aux incidents |
| Plan Generator | 8005 | Plans NIST/ISO 27001 automatiques |
| Admin API | 8000 | API REST complète |
| Dashboard | 3000 | Interface web React |

## Tests

```bash
# Test SQL Injection (WAF doit détecter)
curl "http://localhost:8080/test?id=1'+OR+'1'='1" -H "User-Agent: sqlmap/1.7"

# Health check
curl http://localhost:8000/api/services/health

# Stats temps réel
curl http://localhost:8001/api/stats/realtime
```

## Base de données

- **PostgreSQL** : Logs, prédictions ML, assessments risque, incidents, plans
- **Redis** : Rate limiting, IPs bloquées, stats temps réel
- **MinIO** : Archive logs JSON bruts (format OCSF 1.1.0)

## Commandes utiles

```bash
./start.sh logs waf           # Logs WAF en direct
./start.sh logs ml-engine     # Logs ML Engine
./start.sh status             # État de tous les services
./start.sh test               # Tests automatiques
./start.sh stop               # Arrêt propre
./start.sh clean              # Suppression complète
```
