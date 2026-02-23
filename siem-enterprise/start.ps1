# ═══════════════════════════════════════════════════════════════════════════
# SIEM Enterprise v2.0 — Script Windows PowerShell
# ═══════════════════════════════════════════════════════════════════════════

param([string]$Mode = "start", [string]$Service = "")

$Colors = @{ Cyan = 'Cyan'; Green = 'Green'; Red = 'Red'; Yellow = 'Yellow'; Blue = 'Blue' }

Write-Host @"
╔════════════════════════════════════════════════════╗
║         SIEM Enterprise v2.0 — Windows            ║
║   WAF · Ingestion · ML · Risk · SOAR · Dashboard  ║
╚════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Verify Docker
try { docker compose version | Out-Null }
catch { Write-Host "✗ Docker Compose requis" -ForegroundColor Red; exit 1 }
Write-Host "✓ Docker disponible" -ForegroundColor Green

switch ($Mode) {
    "start" {
        Write-Host "`n▶ Démarrage..." -ForegroundColor Blue
        docker compose up -d --build
        
        Write-Host "⏳ Initialisation (50s)..." -ForegroundColor Yellow
        Start-Sleep 50
        
        docker compose ps
        
        Write-Host @"

╔══════════════════════════════════════════╗
║  ✓ SIEM Enterprise opérationnel!         ║
╠══════════════════════════════════════════╣
║  Dashboard:  http://localhost:3000        ║
║  API Docs:   http://localhost:8000/docs   ║
║  WAF:        http://localhost:8080/health ║
║  MinIO:      http://localhost:9001        ║
║  PostgreSQL: localhost:5432               ║
╚══════════════════════════════════════════╝
"@ -ForegroundColor Green
    }
    "stop" {
        Write-Host "■ Arrêt..." -ForegroundColor Yellow
        docker compose down
        Write-Host "✓ Arrêté" -ForegroundColor Green
    }
    "restart" {
        docker compose down
        docker compose up -d --build
    }
    "logs" {
        if ($Service) { docker compose logs -f $Service }
        else { docker compose logs -f }
    }
    "status" { docker compose ps }
    "clean" {
        $confirm = Read-Host "Supprimer toutes les données? (y/N)"
        if ($confirm -eq 'y') {
            docker compose down -v --remove-orphans
            docker system prune -f
            Write-Host "✓ Nettoyage complet" -ForegroundColor Green
        }
    }
    "test" {
        Write-Host "🧪 Tests..." -ForegroundColor Blue
        $ports = @(8080,8001,8002,8003,8004,8005,8000)
        foreach ($port in $ports) {
            try {
                $r = Invoke-WebRequest -Uri "http://localhost:$port/health" -TimeoutSec 3 -UseBasicParsing
                Write-Host "  Port $port`: ✓ OK" -ForegroundColor Green
            } catch {
                Write-Host "  Port $port`: ✗ Indisponible" -ForegroundColor Red
            }
        }
    }
    default {
        Write-Host "Usage: .\start.ps1 [start|stop|restart|logs|status|clean|test]"
    }
}
