"""
ML Engine — Feature Extraction Automatique
Extraction de 20+ features depuis raw_requests pour le ML
"""
import asyncpg
import numpy as np
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from urllib.parse import urlparse
import re
import math
from collections import Counter

async def extract_features(request_id: str, db_pool: asyncpg.Pool) -> Dict:
    """
    Extrait toutes les features ML pour une requête
    """
    async with db_pool.acquire() as conn:
        # Récupérer la requête
        request = await conn.fetchrow(
            "SELECT * FROM raw_requests WHERE id = $1",
            request_id
        )
        
        if not request:
            return None
        
        client_ip = request['client_ip']
        timestamp = request['timestamp']
        url = request['url']
        method = request['method']
        body = request['body'] or ""
        user_agent = request['user_agent'] or ""
        
        # ─── FEATURES TEMPORELLES ───────────────────────────────────
        
        # Requêtes par minute (dernière minute)
        one_min_ago = timestamp - timedelta(minutes=1)
        requests_per_minute = await conn.fetchval(
            """SELECT COUNT(*) FROM raw_requests 
               WHERE client_ip = $1 AND timestamp > $2""",
            client_ip, one_min_ago
        ) or 0
        
        # Requêtes dernière heure
        one_hour_ago = timestamp - timedelta(hours=1)
        requests_last_hour = await conn.fetchval(
            """SELECT COUNT(*) FROM raw_requests 
               WHERE client_ip = $1 AND timestamp > $2""",
            client_ip, one_hour_ago
        ) or 0
        
        # Requêtes dernier jour
        one_day_ago = timestamp - timedelta(days=1)
        requests_last_day = await conn.fetchval(
            """SELECT COUNT(*) FROM raw_requests 
               WHERE client_ip = $1 AND timestamp > $2""",
            client_ip, one_day_ago
        ) or 0
        
        # ─── FEATURES URL ───────────────────────────────────────────
        
        # Longueur URL
        url_length = len(url)
        
        # Entropie URL (mesure du désordre)
        url_entropy = calculate_entropy(url)
        
        # Endpoints uniques accédés par cette IP (24h)
        unique_endpoints = await conn.fetchval(
            """SELECT COUNT(DISTINCT path) FROM raw_requests 
               WHERE client_ip = $1 AND timestamp > $2""",
            client_ip, one_day_ago
        ) or 1
        
        # Caractères suspects dans URL
        suspicious_chars = len(re.findall(r"[<>'\";(){}]", url))
        
        # Profondeur path
        path_depth = url.count('/')
        
        # Paramètres GET
        query_param_count = url.count('&') + (1 if '?' in url else 0)
        
        # ─── FEATURES PAYLOAD ───────────────────────────────────────
        
        payload_length = len(body)
        payload_entropy = calculate_entropy(body) if body else 0.0
        
        # Ratio caractères spéciaux
        special_chars_count = len(re.findall(r"[^a-zA-Z0-9\s]", body))
        special_chars_ratio = special_chars_count / max(len(body), 1)
        
        # ─── FEATURES COMPORTEMENTALES ──────────────────────────────
        
        # Tentatives login échouées
        failed_logins = await conn.fetchval(
            """SELECT COUNT(*) FROM raw_requests 
               WHERE client_ip = $1 
               AND timestamp > $2 
               AND status_code IN (401, 403)""",
            client_ip, one_hour_ago
        ) or 0
        
        # Durée session (temps entre première et dernière requête)
        first_seen = await conn.fetchval(
            """SELECT MIN(timestamp) FROM raw_requests 
               WHERE client_ip = $1""",
            client_ip
        )
        session_duration_seconds = (timestamp - first_seen).total_seconds() if first_seen else 0
        
        # Taux d'erreur (4xx, 5xx)
        error_count = await conn.fetchval(
            """SELECT COUNT(*) FROM raw_requests 
               WHERE client_ip = $1 
               AND timestamp > $2 
               AND status_code >= 400""",
            client_ip, one_hour_ago
        ) or 0
        error_rate = error_count / max(requests_last_hour, 1)
        
        # User-agents distincts utilisés
        distinct_user_agents = await conn.fetchval(
            """SELECT COUNT(DISTINCT user_agent) FROM raw_requests 
               WHERE client_ip = $1 AND timestamp > $2""",
            client_ip, one_day_ago
        ) or 1
        
        # ─── FEATURES GÉOGRAPHIQUES ─────────────────────────────────
        
        # Changements de pays (TODO: nécessite GeoIP)
        country_changes = 0  # Placeholder
        is_known_vpn = False  # Placeholder
        is_tor_exit = False   # Placeholder
        
        # ─── FEATURES CONTEXTUELLES ─────────────────────────────────
        
        hour_of_day = timestamp.hour
        day_of_week = timestamp.weekday()
        is_business_hours = 9 <= hour_of_day <= 17 and day_of_week < 5
        
        # ─── FEATURES MÉTHODES HTTP ─────────────────────────────────
        
        method_variety = await conn.fetchval(
            """SELECT COUNT(DISTINCT method) FROM raw_requests 
               WHERE client_ip = $1 AND timestamp > $2""",
            client_ip, one_hour_ago
        ) or 1
        
        # Ratio POST/GET
        post_count = await conn.fetchval(
            """SELECT COUNT(*) FROM raw_requests 
               WHERE client_ip = $1 AND timestamp > $2 AND method = 'POST'""",
            client_ip, one_hour_ago
        ) or 0
        post_ratio = post_count / max(requests_last_hour, 1)
        
        # ─── CONSTRUIRE FEATURE VECTOR ──────────────────────────────
        
        feature_vector = [
            # Temporelles
            float(requests_per_minute),
            float(requests_last_hour),
            float(requests_last_day),
            
            # URL
            float(url_length),
            float(url_entropy),
            float(unique_endpoints),
            float(suspicious_chars),
            float(path_depth),
            float(query_param_count),
            
            # Payload
            float(payload_length),
            float(payload_entropy),
            float(special_chars_ratio),
            
            # Comportementales
            float(failed_logins),
            float(session_duration_seconds),
            float(error_rate),
            float(distinct_user_agents),
            float(method_variety),
            float(post_ratio),
            
            # Géographiques
            float(country_changes),
            float(is_known_vpn),
            float(is_tor_exit),
            
            # Contextuelles
            float(hour_of_day),
            float(day_of_week),
            float(is_business_hours),
        ]
        
        features = {
            "request_id": request_id,
            "computed_at": datetime.utcnow(),
            
            # Temporelles
            "requests_per_minute": requests_per_minute,
            "requests_last_hour": requests_last_hour,
            "requests_last_day": requests_last_day,
            
            # URL
            "url_length": url_length,
            "url_entropy": url_entropy,
            "unique_endpoints_count": unique_endpoints,
            "url_suspicious_chars_count": suspicious_chars,
            "path_depth": path_depth,
            "query_param_count": query_param_count,
            
            # Payload
            "payload_length": payload_length,
            "payload_entropy": payload_entropy,
            "special_chars_ratio": special_chars_ratio,
            
            # Comportementales
            "failed_login_attempts": failed_logins,
            "session_duration_seconds": session_duration_seconds,
            "error_rate": error_rate,
            "distinct_user_agents_count": distinct_user_agents,
            "method_variety": method_variety,
            "post_ratio": post_ratio,
            
            # Géographiques
            "country_changes_count": country_changes,
            "is_known_vpn": is_known_vpn,
            "is_tor_exit_node": is_tor_exit,
            
            # Contextuelles
            "hour_of_day": hour_of_day,
            "day_of_week": day_of_week,
            "is_business_hours": is_business_hours,
            
            # Vector complet
            "feature_vector": feature_vector
        }
        
        # Sauvegarder dans PostgreSQL
        await conn.execute("""
            INSERT INTO features (
                request_id, computed_at,
                requests_per_minute, requests_last_hour, requests_last_day,
                url_length, url_entropy, unique_endpoints_count, url_suspicious_chars_count,
                payload_length, payload_entropy, special_chars_ratio,
                failed_login_attempts, session_duration_seconds, error_rate,
                distinct_user_agents_count,
                country_changes_count, is_known_vpn, is_tor_exit_node,
                hour_of_day, day_of_week, is_business_hours,
                feature_vector
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23
            )
        """,
            request_id, features["computed_at"],
            requests_per_minute, requests_last_hour, requests_last_day,
            url_length, url_entropy, unique_endpoints, suspicious_chars,
            payload_length, payload_entropy, special_chars_ratio,
            failed_logins, session_duration_seconds, error_rate,
            distinct_user_agents,
            country_changes, is_known_vpn, is_tor_exit,
            hour_of_day, day_of_week, is_business_hours,
            feature_vector
        )
        
        return features


def calculate_entropy(text: str) -> float:
    """Calcule l'entropie de Shannon d'une chaîne"""
    if not text:
        return 0.0
    
    # Compter fréquence caractères
    counter = Counter(text)
    length = len(text)
    
    # Calculer entropie
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


async def extract_features_batch(request_ids: List[str], db_pool: asyncpg.Pool) -> List[Dict]:
    """Extrait features pour plusieurs requêtes en parallèle"""
    import asyncio
    tasks = [extract_features(req_id, db_pool) for req_id in request_ids]
    return await asyncio.gather(*tasks)
