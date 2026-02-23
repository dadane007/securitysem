-- ═══════════════════════════════════════════════════════════════════════════
-- SIEM Enterprise — Database Schema Complet
-- Modules: WAF, Ingestion, ML, Risk, SOAR, Plans
-- ═══════════════════════════════════════════════════════════════════════════

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- Pour recherche texte
CREATE EXTENSION IF NOT EXISTS "btree_gin"; -- Pour index optimisés

-- ─── TABLE 1: raw_requests (Logs WAF bruts) ────────────────────────────────
CREATE TABLE IF NOT EXISTS raw_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Requête HTTP
    method VARCHAR(10) NOT NULL,
    url TEXT NOT NULL,
    path VARCHAR(500),
    query_string TEXT,
    headers JSONB,
    body TEXT,
    user_agent TEXT,
    content_type VARCHAR(100),
    content_length INTEGER,
    
    -- Client
    client_ip VARCHAR(45) NOT NULL,
    client_port INTEGER,
    geo_country VARCHAR(2),
    geo_city VARCHAR(100),
    
    -- Réponse
    status_code INTEGER,
    response_time_ms FLOAT,
    response_size INTEGER,
    
    -- Session
    session_id VARCHAR(100),
    user_id VARCHAR(100),
    
    -- Flags WAF
    is_blocked BOOLEAN DEFAULT false,
    is_suspicious BOOLEAN DEFAULT false,
    waf_rules_triggered TEXT[],
    
    -- Stockage Data Lake
    minio_object_key VARCHAR(500)
);

CREATE INDEX idx_raw_requests_timestamp ON raw_requests(timestamp DESC);
CREATE INDEX idx_raw_requests_client_ip ON raw_requests(client_ip);
CREATE INDEX idx_raw_requests_blocked ON raw_requests(is_blocked) WHERE is_blocked = true;
CREATE INDEX idx_raw_requests_url_gin ON raw_requests USING gin(url gin_trgm_ops);

-- ─── TABLE 2: owasp_detections (Détections OWASP) ──────────────────────────
CREATE TABLE IF NOT EXISTS owasp_detections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id UUID REFERENCES raw_requests(id) ON DELETE CASCADE,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Classification OWASP
    owasp_category VARCHAR(50) NOT NULL,  -- SQL_INJECTION, XSS, etc.
    owasp_code VARCHAR(20),  -- A03:2021
    severity VARCHAR(20),  -- CRITICAL, HIGH, MEDIUM, LOW
    confidence FLOAT,  -- 0.0 - 1.0
    
    -- Détails
    payload_detected TEXT,
    detection_rule VARCHAR(100),
    false_positive BOOLEAN DEFAULT false
);

CREATE INDEX idx_owasp_timestamp ON owasp_detections(timestamp DESC);
CREATE INDEX idx_owasp_category ON owasp_detections(owasp_category);
CREATE INDEX idx_owasp_request ON owasp_detections(request_id);

-- ─── TABLE 3: features (Features ML) ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS features (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id UUID REFERENCES raw_requests(id) ON DELETE CASCADE,
    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Features temporelles
    requests_per_minute FLOAT,
    requests_last_hour INTEGER,
    requests_last_day INTEGER,
    
    -- Features URL
    url_length INTEGER,
    url_entropy FLOAT,
    unique_endpoints_count INTEGER,
    url_suspicious_chars_count INTEGER,
    
    -- Features payload
    payload_length INTEGER,
    payload_entropy FLOAT,
    special_chars_ratio FLOAT,
    
    -- Features comportementales
    failed_login_attempts INTEGER,
    session_duration_seconds INTEGER,
    error_rate FLOAT,
    distinct_user_agents_count INTEGER,
    
    -- Features géographiques
    country_changes_count INTEGER,
    is_known_vpn BOOLEAN,
    is_tor_exit_node BOOLEAN,
    
    -- Features contextuelles
    hour_of_day INTEGER,
    day_of_week INTEGER,
    is_business_hours BOOLEAN,
    
    -- Vector complet (pour ML)
    feature_vector FLOAT[]
);

CREATE INDEX idx_features_request ON features(request_id);
CREATE INDEX idx_features_timestamp ON features(computed_at DESC);

-- ─── TABLE 4: ml_predictions (Prédictions ML) ──────────────────────────────
CREATE TABLE IF NOT EXISTS ml_predictions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id UUID REFERENCES raw_requests(id) ON DELETE CASCADE,
    predicted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Anomaly Detection
    anomaly_score FLOAT,  -- 0.0 - 1.0
    is_anomaly BOOLEAN,
    anomaly_method VARCHAR(50),  -- IsolationForest, OneClassSVM
    
    -- Classification
    attack_type VARCHAR(100),
    attack_probability FLOAT,
    classification_method VARCHAR(50),  -- RandomForest, GradientBoosting
    
    -- Confiance
    confidence_level VARCHAR(20),  -- HIGH, MEDIUM, LOW
    model_version VARCHAR(50),
    
    -- Features importantes
    top_features JSONB  -- {"feature_name": importance_score}
);

CREATE INDEX idx_ml_predictions_request ON ml_predictions(request_id);
CREATE INDEX idx_ml_predictions_anomaly ON ml_predictions(is_anomaly) WHERE is_anomaly = true;
CREATE INDEX idx_ml_predictions_timestamp ON ml_predictions(predicted_at DESC);

-- ─── TABLE 5: risk_assessments (Évaluations de risque) ─────────────────────
CREATE TABLE IF NOT EXISTS risk_assessments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id UUID REFERENCES raw_requests(id) ON DELETE CASCADE,
    assessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Score de risque global
    risk_score FLOAT NOT NULL,  -- 0.0 - 1.0
    risk_level VARCHAR(20),  -- CRITICAL, HIGH, MEDIUM, LOW
    
    -- Composants du score
    ml_score_weight FLOAT,
    owasp_score_weight FLOAT,
    behavioral_score_weight FLOAT,
    geo_score_weight FLOAT,
    
    -- Décision recommandée
    recommended_action VARCHAR(50),  -- BLOCK, CAPTCHA, RATE_LIMIT, ALERT, ALLOW
    automation_level VARCHAR(20),  -- MANUAL, SEMI_AUTO, AUTO, STRICT
    
    -- Contexte
    contributing_factors JSONB,
    explanation TEXT
);

CREATE INDEX idx_risk_assessments_request ON risk_assessments(request_id);
CREATE INDEX idx_risk_assessments_level ON risk_assessments(risk_level);
CREATE INDEX idx_risk_assessments_timestamp ON risk_assessments(assessed_at DESC);

-- ─── TABLE 6: soar_actions (Actions SOAR exécutées) ────────────────────────
CREATE TABLE IF NOT EXISTS soar_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    risk_assessment_id UUID REFERENCES risk_assessments(id) ON DELETE CASCADE,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Action
    action_type VARCHAR(50) NOT NULL,  -- IP_BLOCK, CAPTCHA, RATE_LIMIT, etc.
    action_status VARCHAR(20),  -- PENDING, EXECUTED, FAILED, ROLLED_BACK
    
    -- Détails
    target_ip VARCHAR(45),
    target_session_id VARCHAR(100),
    duration_minutes INTEGER,
    
    -- Résultat
    execution_result TEXT,
    error_message TEXT,
    
    -- Validation
    requires_validation BOOLEAN DEFAULT false,
    validated_by VARCHAR(100),
    validated_at TIMESTAMP,
    
    -- Rollback
    rollback_at TIMESTAMP,
    rollback_reason TEXT
);

CREATE INDEX idx_soar_actions_risk ON soar_actions(risk_assessment_id);
CREATE INDEX idx_soar_actions_status ON soar_actions(action_status);
CREATE INDEX idx_soar_actions_timestamp ON soar_actions(executed_at DESC);
CREATE INDEX idx_soar_actions_ip ON soar_actions(target_ip);

-- ─── TABLE 7: incidents (Incidents de sécurité) ────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Classification
    incident_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20),  -- CRITICAL, HIGH, MEDIUM, LOW
    status VARCHAR(20) DEFAULT 'OPEN',  -- OPEN, INVESTIGATING, RESOLVED, CLOSED
    
    -- Source
    source_ip VARCHAR(45),
    affected_endpoints TEXT[],
    attack_vectors TEXT[],
    
    -- Compteurs
    total_requests_involved INTEGER,
    blocked_requests_count INTEGER,
    
    -- MITRE ATT&CK
    mitre_tactic VARCHAR(100),
    mitre_technique VARCHAR(100),
    
    -- Résolution
    resolved_at TIMESTAMP,
    resolution_time_minutes INTEGER,
    false_positive BOOLEAN DEFAULT false,
    
    -- Relations
    related_incidents UUID[]
);

CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_incidents_created ON incidents(created_at DESC);
CREATE INDEX idx_incidents_source_ip ON incidents(source_ip);

-- ─── TABLE 8: security_plans (Plans de sécurité générés) ───────────────────
CREATE TABLE IF NOT EXISTS security_plans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Plan d'action
    immediate_actions TEXT NOT NULL,
    corrective_measures TEXT NOT NULL,
    preventive_recommendations TEXT NOT NULL,
    
    -- Conformité
    nist_controls_applied TEXT[],
    iso27001_controls TEXT[],
    compliance_notes TEXT,
    
    -- Métadonnées
    generated_by VARCHAR(50),  -- AI, MANUAL, HYBRID
    confidence_score FLOAT,
    
    -- Validation
    validated_by VARCHAR(100),
    validated_at TIMESTAMP,
    implementation_status VARCHAR(20)  -- PENDING, IN_PROGRESS, COMPLETED
);

CREATE INDEX idx_security_plans_incident ON security_plans(incident_id);
CREATE INDEX idx_security_plans_timestamp ON security_plans(generated_at DESC);

-- ─── TABLE 9: ip_reputation (Réputation IPs) ───────────────────────────────
CREATE TABLE IF NOT EXISTS ip_reputation (
    ip_address VARCHAR(45) PRIMARY KEY,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Statistiques
    total_requests INTEGER DEFAULT 0,
    blocked_requests INTEGER DEFAULT 0,
    suspicious_requests INTEGER DEFAULT 0,
    
    -- Score de réputation
    reputation_score FLOAT,  -- 0.0 (très mauvais) - 1.0 (bon)
    trust_level VARCHAR(20),  -- TRUSTED, NEUTRAL, SUSPICIOUS, MALICIOUS
    
    -- Détails
    countries_seen TEXT[],
    user_agents_seen TEXT[],
    attack_types_detected TEXT[],
    
    -- Liste noire/blanche
    is_whitelisted BOOLEAN DEFAULT false,
    is_blacklisted BOOLEAN DEFAULT false,
    blacklist_reason TEXT,
    blacklist_expires_at TIMESTAMP
);

CREATE INDEX idx_ip_reputation_score ON ip_reputation(reputation_score);
CREATE INDEX idx_ip_reputation_trust ON ip_reputation(trust_level);
CREATE INDEX idx_ip_reputation_blacklist ON ip_reputation(is_blacklisted) WHERE is_blacklisted = true;

-- ─── TABLE 10: ml_models (Versions des modèles ML) ─────────────────────────
CREATE TABLE IF NOT EXISTS ml_models (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Modèle
    model_name VARCHAR(100) NOT NULL,
    model_type VARCHAR(50),  -- ANOMALY_DETECTION, CLASSIFICATION
    algorithm VARCHAR(50),  -- IsolationForest, RandomForest, etc.
    version VARCHAR(20) NOT NULL,
    
    -- Performance
    accuracy FLOAT,
    precision_score FLOAT,
    recall FLOAT,
    f1_score FLOAT,
    
    -- Training
    training_samples_count INTEGER,
    training_duration_seconds INTEGER,
    
    -- Déploiement
    is_active BOOLEAN DEFAULT false,
    deployed_at TIMESTAMP,
    
    -- Métadonnées
    hyperparameters JSONB,
    feature_importance JSONB,
    model_path VARCHAR(500)
);

CREATE INDEX idx_ml_models_active ON ml_models(is_active) WHERE is_active = true;
CREATE INDEX idx_ml_models_type ON ml_models(model_type, is_active);

-- ─── TABLE 11: system_config (Configuration système) ───────────────────────
CREATE TABLE IF NOT EXISTS system_config (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL,
    value_type VARCHAR(20),  -- STRING, INTEGER, FLOAT, BOOLEAN, JSON
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(100)
);

-- ─── TABLE 12: audit_log (Journal d'audit) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Événement
    event_type VARCHAR(50) NOT NULL,  -- CONFIG_CHANGE, MODEL_UPDATE, etc.
    event_category VARCHAR(50),  -- ADMIN, ML, SECURITY
    
    -- Utilisateur
    user_id VARCHAR(100),
    user_ip VARCHAR(45),
    
    -- Détails
    description TEXT,
    changes JSONB,
    
    -- Sécurité
    severity VARCHAR(20),
    requires_review BOOLEAN DEFAULT false
);

CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_user ON audit_log(user_id);

-- ─── Vue: dashboard_stats ───────────────────────────────────────────────────
CREATE OR REPLACE VIEW dashboard_stats AS
SELECT
    (SELECT COUNT(*) FROM raw_requests WHERE timestamp >= NOW() - INTERVAL '24 hours') as requests_24h,
    (SELECT COUNT(*) FROM raw_requests WHERE is_blocked = true AND timestamp >= NOW() - INTERVAL '24 hours') as blocked_24h,
    (SELECT COUNT(*) FROM incidents WHERE status IN ('OPEN', 'INVESTIGATING')) as open_incidents,
    (SELECT COUNT(DISTINCT client_ip) FROM raw_requests WHERE timestamp >= NOW() - INTERVAL '1 hour') as active_ips,
    (SELECT AVG(risk_score) FROM risk_assessments WHERE assessed_at >= NOW() - INTERVAL '24 hours') as avg_risk_score,
    (SELECT COUNT(*) FROM ml_predictions WHERE is_anomaly = true AND predicted_at >= NOW() - INTERVAL '24 hours') as anomalies_24h;

-- ─── Fonction: update_ip_reputation ─────────────────────────────────────────
CREATE OR REPLACE FUNCTION update_ip_reputation()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO ip_reputation (ip_address, last_seen, total_requests)
    VALUES (NEW.client_ip, NEW.timestamp, 1)
    ON CONFLICT (ip_address) DO UPDATE
    SET
        last_seen = NEW.timestamp,
        total_requests = ip_reputation.total_requests + 1,
        blocked_requests = ip_reputation.blocked_requests + (CASE WHEN NEW.is_blocked THEN 1 ELSE 0 END),
        suspicious_requests = ip_reputation.suspicious_requests + (CASE WHEN NEW.is_suspicious THEN 1 ELSE 0 END);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_ip_reputation
AFTER INSERT ON raw_requests
FOR EACH ROW
EXECUTE FUNCTION update_ip_reputation();

-- ═══════════════════════════════════════════════════════════════════════════
-- Initialisation données de base
-- ═══════════════════════════════════════════════════════════════════════════

-- Configuration par défaut
INSERT INTO system_config (key, value, value_type, description) VALUES
('waf_mode', 'audit', 'STRING', 'Mode WAF: audit ou block'),
('automation_level', 'semi-auto', 'STRING', 'Niveau automatisation: manual, semi-auto, auto, strict'),
('anomaly_threshold', '0.7', 'FLOAT', 'Seuil détection anomalies'),
('risk_threshold_block', '0.9', 'FLOAT', 'Seuil risque pour blocage automatique'),
('risk_threshold_captcha', '0.7', 'FLOAT', 'Seuil risque pour CAPTCHA'),
('enable_auto_block', 'true', 'BOOLEAN', 'Activer blocage automatique'),
('enable_ml', 'true', 'BOOLEAN', 'Activer ML'),
('enable_auto_plan', 'true', 'BOOLEAN', 'Activer génération automatique plans'),
('rate_limit_per_minute', '100', 'INTEGER', 'Limite requêtes par minute par IP')
ON CONFLICT (key) DO NOTHING;
