"""
ML Engine — Attack Classification
Random Forest + Gradient Boosting pour classifier les types d'attaques
"""
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support
import joblib
import os
from typing import Dict, List
from datetime import datetime

MODEL_DIR = "/app/models"

# Types d'attaques OWASP
ATTACK_TYPES = [
    "BENIGN",           # Trafic normal
    "SQL_INJECTION",
    "XSS",
    "PATH_TRAVERSAL",
    "COMMAND_INJECTION",
    "XXE",
    "SSRF",
    "RATE_LIMIT_ABUSE",
    "BRUTE_FORCE",
    "UNKNOWN"
]

class AttackClassifier:
    """Classificateur de types d'attaques"""
    
    def __init__(self):
        self.rf_model = None
        self.gb_model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.is_trained = False
        self.version = None
        self.feature_importance = None
        
    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        test_size: float = 0.2,
        n_estimators: int = 100,
        random_state: int = 42
    ) -> Dict:
        """
        Entraîne Random Forest + Gradient Boosting
        
        Args:
            X: Features (n_samples, n_features)
            y: Labels (n_samples,) — types d'attaques
        """
        print(f"[CLASSIFIER] Training on {X.shape[0]} samples")
        
        # Encoder labels
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Split train/test
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=test_size, random_state=random_state, stratify=y_encoded
        )
        
        # Normaliser
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # 1. Random Forest
        self.rf_model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=random_state,
            n_jobs=-1,
            class_weight='balanced'  # Important pour classes déséquilibrées
        )
        self.rf_model.fit(X_train_scaled, y_train)
        
        # 2. Gradient Boosting
        self.gb_model = GradientBoostingClassifier(
            n_estimators=n_estimators,
            max_depth=5,
            learning_rate=0.1,
            subsample=0.8,
            random_state=random_state
        )
        self.gb_model.fit(X_train_scaled, y_train)
        
        self.is_trained = True
        self.version = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        
        # Évaluation
        rf_pred = self.rf_model.predict(X_test_scaled)
        gb_pred = self.gb_model.predict(X_test_scaled)
        
        # Ensemble (vote majoritaire)
        ensemble_pred = np.where(rf_pred == gb_pred, rf_pred, rf_pred)  # Priorité RF en cas désaccord
        
        rf_acc = accuracy_score(y_test, rf_pred)
        gb_acc = accuracy_score(y_test, gb_pred)
        ensemble_acc = accuracy_score(y_test, ensemble_pred)
        
        # Précision, recall, F1
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, ensemble_pred, average='weighted', zero_division=0
        )
        
        # Feature importance (Random Forest)
        self.feature_importance = {
            f"feature_{i}": float(imp) 
            for i, imp in enumerate(self.rf_model.feature_importances_)
        }
        
        metrics = {
            "version": self.version,
            "n_samples": X.shape[0],
            "n_features": X.shape[1],
            "n_classes": len(self.label_encoder.classes_),
            "classes": self.label_encoder.classes_.tolist(),
            "test_size": test_size,
            
            "random_forest": {
                "accuracy": float(rf_acc),
                "n_estimators": n_estimators
            },
            "gradient_boosting": {
                "accuracy": float(gb_acc),
                "n_estimators": n_estimators
            },
            "ensemble": {
                "accuracy": float(ensemble_acc),
                "precision": float(precision),
                "recall": float(recall),
                "f1_score": float(f1)
            },
            "feature_importance_top5": dict(sorted(
                self.feature_importance.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5])
        }
        
        print(f"[CLASSIFIER] Training completed:")
        print(f"  - Random Forest:      {rf_acc:.3f} accuracy")
        print(f"  - Gradient Boosting:  {gb_acc:.3f} accuracy")
        print(f"  - Ensemble:           {ensemble_acc:.3f} accuracy")
        print(f"  - Precision:          {precision:.3f}")
        print(f"  - Recall:             {recall:.3f}")
        print(f"  - F1-Score:           {f1:.3f}")
        
        return metrics
    
    def predict(self, X: np.ndarray) -> Dict:
        """Prédit les types d'attaques"""
        if not self.is_trained:
            raise ValueError("Model not trained")
        
        X_scaled = self.scaler.transform(X)
        
        # Prédictions
        rf_pred = self.rf_model.predict(X_scaled)
        gb_pred = self.gb_model.predict(X_scaled)
        
        # Probabilités
        rf_proba = self.rf_model.predict_proba(X_scaled)
        gb_proba = self.gb_model.predict_proba(X_scaled)
        
        # Ensemble probabilités (moyenne)
        ensemble_proba = (rf_proba + gb_proba) / 2
        ensemble_pred = ensemble_proba.argmax(axis=1)
        
        # Décoder labels
        rf_labels = self.label_encoder.inverse_transform(rf_pred)
        gb_labels = self.label_encoder.inverse_transform(gb_pred)
        ensemble_labels = self.label_encoder.inverse_transform(ensemble_pred)
        
        results = {
            "random_forest": {
                "predictions": rf_labels.tolist(),
                "probabilities": rf_proba.tolist()
            },
            "gradient_boosting": {
                "predictions": gb_labels.tolist(),
                "probabilities": gb_proba.tolist()
            },
            "ensemble": {
                "predictions": ensemble_labels.tolist(),
                "probabilities": ensemble_proba.tolist(),
                "max_probabilities": ensemble_proba.max(axis=1).tolist()
            }
        }
        
        return results
    
    def predict_single(self, x: np.ndarray) -> Dict:
        """Prédit pour un seul sample"""
        if x.ndim == 1:
            x = x.reshape(1, -1)
        
        results = self.predict(x)
        
        attack_type = results["ensemble"]["predictions"][0]
        probability = float(results["ensemble"]["max_probabilities"][0])
        all_probas = {
            self.label_encoder.classes_[i]: float(prob)
            for i, prob in enumerate(results["ensemble"]["probabilities"][0])
        }
        
        # Confiance basée sur probabilité
        if probability >= 0.8:
            confidence = "HIGH"
        elif probability >= 0.5:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        
        return {
            "attack_type": attack_type,
            "probability": probability,
            "confidence": confidence,
            "all_probabilities": all_probas,
            "method": "Random Forest + Gradient Boosting Ensemble"
        }
    
    def save(self, filename: str = "attack_classifier"):
        """Sauvegarde le modèle"""
        if not self.is_trained:
            raise ValueError("Cannot save untrained model")
        
        model_path = os.path.join(MODEL_DIR, f"{filename}_v{self.version}.pkl")
        
        joblib.dump({
            "rf_model": self.rf_model,
            "gb_model": self.gb_model,
            "scaler": self.scaler,
            "label_encoder": self.label_encoder,
            "version": self.version,
            "feature_importance": self.feature_importance
        }, model_path)
        
        print(f"[CLASSIFIER] Model saved to {model_path}")
        return model_path
    
    def load(self, filename: str = "attack_classifier", version: str = None):
        """Charge le modèle"""
        if version:
            model_path = os.path.join(MODEL_DIR, f"{filename}_v{version}.pkl")
        else:
            import glob
            models = glob.glob(os.path.join(MODEL_DIR, f"{filename}_v*.pkl"))
            if not models:
                raise FileNotFoundError(f"No models found")
            model_path = sorted(models)[-1]
        
        data = joblib.load(model_path)
        self.rf_model = data["rf_model"]
        self.gb_model = data["gb_model"]
        self.scaler = data["scaler"]
        self.label_encoder = data["label_encoder"]
        self.version = data["version"]
        self.feature_importance = data["feature_importance"]
        self.is_trained = True
        
        print(f"[CLASSIFIER] Model loaded from {model_path}")
        return model_path
