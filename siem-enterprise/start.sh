#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# SIEM Enterprise — Script de démarrage
# ═══════════════════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════╗"
echo "║         SIEM Enterprise v2.0 — Démarrage          ║"
echo "║   WAF · Ingestion · ML · Risk · SOAR · Dashboard  ║"
echo "╚════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker n'est pas installé${NC}"
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo -e "${RED}✗ Docker Compose v2 requis${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Docker disponible${NC}"

# Check .env
if [ ! -f .env ]; then
    echo -e "${YELLOW}⚠ Fichier .env manquant — création depuis modèle${NC}"
    cp .env.example .env 2>/dev/null || true
fi

# Mode argument
MODE=${1:-"start"}

case $MODE in
  "start")
    echo -e "\n${BLUE}▶ Démarrage de tous les services...${NC}"
    docker compose up -d --build
    
    echo -e "\n${YELLOW}⏳ Attente initialisation (45s)...${NC}"
    sleep 45
    
    echo -e "\n${BLUE}📊 État des services:${NC}"
    docker compose ps
    
    echo -e "\n${GREEN}╔══════════════════════════════════════════╗"
    echo "║  ✓ SIEM Enterprise opérationnel!         ║"
    echo "╠══════════════════════════════════════════╣"
    echo "║  Dashboard:  http://localhost:3000        ║"
    echo "║  API Docs:   http://localhost:8000/docs   ║"
    echo "║  WAF:        http://localhost:8080/health ║"
    echo "║  MinIO:      http://localhost:9001        ║"
    echo "║  PostgreSQL: localhost:5432               ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
    ;;
    
  "stop")
    echo -e "${YELLOW}■ Arrêt des services...${NC}"
    docker compose down
    echo -e "${GREEN}✓ Services arrêtés${NC}"
    ;;
    
  "restart")
    echo -e "${YELLOW}↺ Redémarrage...${NC}"
    docker compose down
    docker compose up -d --build
    ;;
    
  "logs")
    SERVICE=${2:-""}
    if [ -n "$SERVICE" ]; then
      docker compose logs -f $SERVICE
    else
      docker compose logs -f
    fi
    ;;
    
  "status")
    docker compose ps
    ;;
    
  "clean")
    echo -e "${RED}⚠ Suppression complète (données incluses)?${NC}"
    read -p "Confirmer [y/N]: " confirm
    if [[ $confirm == [yY] ]]; then
      docker compose down -v --remove-orphans
      docker system prune -f
      echo -e "${GREEN}✓ Nettoyage complet${NC}"
    fi
    ;;
    
  "test")
    echo -e "${BLUE}🧪 Tests de sécurité...${NC}"
    
    echo "1. Test SQL Injection:"
    curl -s "http://localhost:8080/test?id=1'+OR+'1'='1&ua=sqlmap" \
      -H "User-Agent: sqlmap/1.7" | python3 -m json.tool 2>/dev/null || echo "WAF actif"
    
    echo -e "\n2. Health Check services:"
    for port in 8080 8001 8002 8003 8004 8005 8000; do
      status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$port/health)
      if [ "$status" = "200" ]; then
        echo -e "  Port $port: ${GREEN}✓ OK${NC}"
      else
        echo -e "  Port $port: ${RED}✗ $status${NC}"
      fi
    done
    ;;
    
  *)
    echo "Usage: $0 [start|stop|restart|logs|status|clean|test]"
    exit 1
    ;;
esac
