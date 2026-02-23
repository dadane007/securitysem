"""
ML Engine — Anomaly Detection Models
Isolation Forest + One-Class SVM
"""
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import os
from typing import Dict, List, Tuple
from datetime import datetime

MODEL_DIR = "/app/models"
os.makedirs(MODEL_DIR, exist_ok=True)

class AnomalyDetector:
    """Détecteur d'anomalies avec Isolation Forest et One-Class SVM"""
    
    def __init__(self):
        self.isolation_forest = None
        self.one_class_svm = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.version = None
        
    def train(
        self,
        X: np.ndarray,
        contamination: float = 0.1,
        n_estimators: int = 100,
        random_state: int = 42
    ) -> Dict:
        """
        Entraîne les deux modèles d'anomaly detection
        
        Args:
            X: Matrice features (n_samples, n_features)
            contamination: Proportion attendue d'anomalies (0.1 = 10%)
            n_estimators: Nombre d'arbres Isolation Forest
            random_state: Seed pour reproductibilité
        """
        print(f"[ANOMALY] Training on {X.shape[0]} samples, {X.shape[1]} features")
        
        # Normaliser features
        X_scaled = self.scaler.fit_transform(X)
        
        # 1. Isolation Forest
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            max_samples='auto',
            random_state=random_state,
            n_jobs=-1
        )
        self.isolation_forest.fit(X_scaled)
        
        # 2. One-Class SVM
        self.one_class_svm = OneClassSVM(
            kernel='rbf',
            gamma='auto',
            nu=contamination  # nu ≈ contamination attendue
        )
        self.one_class_svm.fit(X_scaled)
        
        self.is_trained = True
        self.version = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        
        # Évaluer sur training data
        iso_scores = self.isolation_forest.decision_function(X_scaled)
        iso_preds = self.isolation_forest.predict(X_scaled)
        iso_anomalies = (iso_preds == -1).sum()
        
        svm_scores = self.one_class_svm.decision_function(X_scaled)
        svm_preds = self.one_class_svm.predict(X_scaled)
        svm_anomalies = (svm_preds == -1).sum()
        
        metrics = {
            "version": self.version,
            "n_samples": X.shape[0],
            "n_features": X.shape[1],
            "contamination": contamination,
            "isolation_forest": {
                "anomalies_detected": int(iso_anomalies),
                "anomaly_rate": float(iso_anomalies / X.shape[0]),
                "score_mean": float(iso_scores.mean()),
                "score_std": float(iso_scores.std())
            },
            "one_class_svm": {
                "anomalies_detected": int(svm_anomalies),
                "anomaly_rate": float(svm_anomalies / X.shape[0]),
                "score_mean": float(svm_scores.mean()),
                "score_std": float(svm_scores.std())
            }
        }
        
        print(f"[ANOMALY] Training completed:")
        print(f"  - Isolation Forest: {iso_anomalies} anomalies ({iso_anomalies/X.shape[0]*100:.1f}%)")
        print(f"  - One-Class SVM: {svm_anomalies} anomalies ({svm_anomalies/X.shape[0]*100:.1f}%)")
        
        return metrics
    
    def predict(self, X: np.ndarray) -> Dict:
        """
        Prédit si les samples sont des anomalies
        
        Returns:
            Dict avec scores et prédictions des deux modèles
        """
        if not self.is_trained:
            raise ValueError("Models not trained yet")
        
        X_scaled = self.scaler.transform(X)
        
        # Isolation Forest
        iso_scores = self.isolation_forest.decision_function(X_scaled)
        iso_preds = self.isolation_forest.predict(X_scaled)
        
        # One-Class SVM
        svm_scores = self.one_class_svm.decision_function(X_scaled)
        svm_preds = self.one_class_svm.predict(X_scaled)
        
        # Normaliser scores en [0, 1] (plus haut = plus anormal)
        iso_scores_norm = 1 - (iso_scores - iso_scores.min()) / (iso_scores.max() - iso_scores.min() + 1e-8)
        svm_scores_norm = 1 - (svm_scores - svm_scores.min()) / (svm_scores.max() - svm_scores.min() + 1e-8)
        
        # Score combiné (moyenne pondérée)
        combined_scores = 0.6 * iso_scores_norm + 0.4 * svm_scores_norm
        
        # Prédiction combinée (anomalie si au moins un modèle détecte)
        combined_preds = (iso_preds == -1) | (svm_preds == -1)
        
        results = {
            "isolation_forest": {
                "scores": iso_scores.tolist(),
                "scores_normalized": iso_scores_norm.tolist(),
                "predictions": (iso_preds == -1).tolist()
            },
            "one_class_svm": {
                "scores": svm_scores.tolist(),
                "scores_normalized": svm_scores_norm.tolist(),
                "predictions": (svm_preds == -1).tolist()
            },
            "combined": {
                "scores": combined_scores.tolist(),
                "predictions": combined_preds.tolist(),
                "is_anomaly": combined_preds.tolist()
            }
        }
        
        return results
    
    def predict_single(self, x: np.ndarray) -> Dict:
        """Prédit pour un seul sample"""
        if x.ndim == 1:
            x = x.reshape(1, -1)
        
        results = self.predict(x)
        
        # Extraire résultat pour sample unique
        return {
            "anomaly_score": float(results["combined"]["scores"][0]),
            "is_anomaly": bool(results["combined"]["is_anomaly"][0]),
            "isolation_forest_score": float(results["isolation_forest"]["scores_normalized"][0]),
            "one_class_svm_score": float(results["one_class_svm"]["scores_normalized"][0]),
            "method": "Isolation Forest + One-Class SVM Ensemble",
            "confidence": "HIGH" if results["combined"]["scores"][0] > 0.8 else ("MEDIUM" if results["combined"]["scores"][0] > 0.5 else "LOW")
        }
    
    def save(self, filename: str = "anomaly_detector"):
        """Sauvegarde les modèles"""
        if not self.is_trained:
            raise ValueError("Cannot save untrained models")
        
        model_path = os.path.join(MODEL_DIR, f"{filename}_v{self.version}.pkl")
        
        joblib.dump({
            "isolation_forest": self.isolation_forest,
            "one_class_svm": self.one_class_svm,
            "scaler": self.scaler,
            "version": self.version
        }, model_path)
        
        print(f"[ANOMALY] Models saved to {model_path}")
        return model_path
    
    def load(self, filename: str = "anomaly_detector", version: str = None):
        """Charge les modèles depuis fichier"""
        if version:
            model_path = os.path.join(MODEL_DIR, f"{filename}_v{version}.pkl")
        else:
            # Charger dernière version
            import glob
            models = glob.glob(os.path.join(MODEL_DIR, f"{filename}_v*.pkl"))
            if not models:
                raise FileNotFoundError(f"No models found in {MODEL_DIR}")
            model_path = sorted(models)[-1]
        
        data = joblib.load(model_path)
        self.isolation_forest = data["isolation_forest"]
        self.one_class_svm = data["one_class_svm"]
        self.scaler = data["scaler"]
        self.version = data["version"]
        self.is_trained = True
        
        print(f"[ANOMALY] Models loaded from {model_path}")
        return model_path


# ═══════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def load_training_data_from_db(db_pool, limit: int = 10000) -> np.ndarray:
    """
    Charge les features depuis PostgreSQL pour entraînement
    """
    import asyncio
    
    async def fetch():
        async with db_pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT feature_vector 
                FROM features 
                WHERE feature_vector IS NOT NULL
                ORDER BY computed_at DESC
                LIMIT $1
            """, limit)
            
            if not rows:
                return None
            
            # Convertir en numpy array
            vectors = [row['feature_vector'] for row in rows]
            return np.array(vectors)
    
    return asyncio.run(fetch())


def auto_retrain_if_needed(
    detector: AnomalyDetector,
    db_pool,
    min_samples: int = 1000,
    retrain_interval_hours: int = 24
) -> bool:
    """
    Re-entraîne automatiquement si nécessaire
    """
    import asyncio
    
    async def check_and_retrain():
        async with db_pool.acquire() as conn:
            # Vérifier nombre de nouveaux samples
            last_retrain = await conn.fetchval("""
                SELECT MAX(training_duration_seconds) FROM ml_models 
                WHERE model_type = 'ANOMALY_DETECTION' AND is_active = true
            """)
            
            new_samples_count = await conn.fetchval("""
                SELECT COUNT(*) FROM features 
                WHERE computed_at > NOW() - INTERVAL '24 hours'
            """)
            
            if new_samples_count >= min_samples:
                print(f"[ANOMALY] Auto-retraining with {new_samples_count} new samples")
                X = load_training_data_from_db(db_pool, limit=10000)
                if X is not None and len(X) > 100:
                    metrics = detector.train(X)
                    detector.save()
                    
                    # Enregistrer dans DB
                    await conn.execute("""
                        INSERT INTO ml_models (
                            model_name, model_type, algorithm, version,
                            training_samples_count, is_active
                        ) VALUES ($1, $2, $3, $4, $5, true)
                    """,
                        "anomaly_detector",
                        "ANOMALY_DETECTION",
                        "Isolation Forest + One-Class SVM",
                        detector.version,
                        len(X)
                    )
                    
                    return True
        
        return False
    
    return asyncio.run(check_and_retrain())
