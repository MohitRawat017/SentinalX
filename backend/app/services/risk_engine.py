"""
SentinelX AI Risk Engine
IsolationForest-based anomaly detection for login risk scoring
"""
import hashlib
import json
import math
import random
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# We'll use a simple feature importance approach instead of full SHAP
# to avoid heavy dependencies during hackathon demo


class RiskEngine:
    """AI-powered login risk scoring using IsolationForest"""

    _instance = None

    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self.feature_names = [
            "ip_entropy",
            "time_deviation",
            "device_fingerprint",
            "login_velocity",
            "wallet_age_score",
        ]
        self.training_data: List[Dict] = []
        self.is_trained = False
        self._seed_synthetic_data()
        self._train_model()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _seed_synthetic_data(self):
        """Generate synthetic normal login data for initial training"""
        np.random.seed(42)
        n_normal = 200

        normal_data = []
        for _ in range(n_normal):
            normal_data.append({
                "ip_entropy": np.random.normal(0.3, 0.1),
                "time_deviation": np.random.normal(0.2, 0.15),
                "device_fingerprint": np.random.normal(0.8, 0.1),
                "login_velocity": np.random.normal(0.1, 0.05),
                "wallet_age_score": np.random.normal(0.7, 0.15),
            })

        # Add some anomalous patterns
        n_anomalous = 20
        for _ in range(n_anomalous):
            normal_data.append({
                "ip_entropy": np.random.uniform(0.7, 1.0),
                "time_deviation": np.random.uniform(0.6, 1.0),
                "device_fingerprint": np.random.uniform(0.0, 0.3),
                "login_velocity": np.random.uniform(0.6, 1.0),
                "wallet_age_score": np.random.uniform(0.0, 0.3),
            })

        self.training_data = normal_data

    def _train_model(self):
        """Train IsolationForest on accumulated data"""
        if len(self.training_data) < 10:
            return

        df = pd.DataFrame(self.training_data)
        # Clip values to [0, 1]
        for col in self.feature_names:
            df[col] = df[col].clip(0.0, 1.0)

        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
            max_samples="auto",
        )
        self.model.fit(df[self.feature_names])
        self.is_trained = True

    def compute_features(
        self,
        ip_address: str = "0.0.0.0",
        user_agent: str = "",
        wallet_address: str = "",
        login_history: Optional[List[Dict]] = None,
        current_hour: Optional[int] = None,
    ) -> Dict[str, float]:
        """Compute the 5 risk features for a login event"""

        # Feature 1: IP Entropy — measures how unusual the IP is
        ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()
        ip_entropy = sum(c.isalpha() for c in ip_hash[:16]) / 16.0
        # Known suspicious IPs boost entropy
        if ip_address.startswith("10.") or ip_address == "0.0.0.0":
            ip_entropy = max(ip_entropy, 0.2)

        # Feature 2: Time Deviation — deviation from user's normal login time
        if current_hour is None:
            current_hour = datetime.utcnow().hour
        # Normal hours: 8-22, unusual: 0-6
        if 8 <= current_hour <= 22:
            time_deviation = abs(current_hour - 15) / 15.0 * 0.3
        else:
            time_deviation = 0.5 + abs(current_hour - 3) / 24.0

        # Feature 3: Device Fingerprint — similarity to known devices
        if user_agent:
            ua_hash = hashlib.md5(user_agent.encode()).hexdigest()
            device_fingerprint = 1.0 - (int(ua_hash[:4], 16) / 65535.0) * 0.4
        else:
            device_fingerprint = 0.3  # No device info = moderate risk

        # Feature 4: Login Velocity — how frequently logins are happening
        if login_history and len(login_history) > 1:
            recent = login_history[-5:]
            if len(recent) >= 2:
                time_diffs = []
                for i in range(1, len(recent)):
                    t1 = recent[i - 1].get("timestamp", 0)
                    t2 = recent[i].get("timestamp", 0)
                    if isinstance(t1, (int, float)) and isinstance(t2, (int, float)):
                        time_diffs.append(abs(t2 - t1))
                if time_diffs:
                    avg_diff = sum(time_diffs) / len(time_diffs)
                    login_velocity = max(0, 1.0 - avg_diff / 3600.0)
                else:
                    login_velocity = 0.1
            else:
                login_velocity = 0.1
        else:
            login_velocity = 0.1

        # Feature 5: Wallet Age Score — newer wallets are riskier
        wallet_hash = hashlib.sha256(wallet_address.lower().encode()).hexdigest()
        wallet_age_score = 0.5 + (int(wallet_hash[:4], 16) / 65535.0) * 0.5

        features = {
            "ip_entropy": round(min(max(ip_entropy, 0.0), 1.0), 4),
            "time_deviation": round(min(max(time_deviation, 0.0), 1.0), 4),
            "device_fingerprint": round(min(max(device_fingerprint, 0.0), 1.0), 4),
            "login_velocity": round(min(max(login_velocity, 0.0), 1.0), 4),
            "wallet_age_score": round(min(max(wallet_age_score, 0.0), 1.0), 4),
        }

        return features

    def score(self, features: Dict[str, float]) -> Tuple[float, str, Dict]:
        """
        Score a login event. Returns (risk_score, risk_level, explanation).
        risk_score: 0.0 (safe) to 1.0 (dangerous)
        """
        if not self.is_trained or self.model is None:
            return 0.5, "medium", {"note": "Model not trained yet"}

        feature_values = np.array([[features[f] for f in self.feature_names]])

        # IsolationForest: decision_function returns anomaly score
        # More negative = more anomalous
        raw_score = self.model.decision_function(feature_values)[0]

        # Convert to 0-1 risk score (more negative → higher risk)
        # decision_function typical range: -0.5 to 0.5
        risk_score = round(max(0.0, min(1.0, 0.5 - raw_score)), 4)

        # Determine risk level
        if risk_score < 0.3:
            risk_level = "low"
        elif risk_score < 0.7:
            risk_level = "medium"
        else:
            risk_level = "high"

        # Feature importance explanation (simple approach)
        explanation = self._explain(features, risk_score)

        return risk_score, risk_level, explanation

    def _explain(self, features: Dict[str, float], risk_score: float) -> Dict:
        """Generate explainability info for the risk score"""
        # Compute each feature's contribution relative to normal baseline
        baseline = {
            "ip_entropy": 0.3,
            "time_deviation": 0.2,
            "device_fingerprint": 0.8,
            "login_velocity": 0.1,
            "wallet_age_score": 0.7,
        }

        contributions = {}
        for feat in self.feature_names:
            diff = features[feat] - baseline[feat]
            # Higher ip_entropy, time_deviation, login_velocity = riskier
            # Lower device_fingerprint, wallet_age_score = riskier
            if feat in ["device_fingerprint", "wallet_age_score"]:
                contributions[feat] = round(-diff, 4)
            else:
                contributions[feat] = round(diff, 4)

        sorted_contribs = sorted(contributions.items(), key=lambda x: abs(x[1]), reverse=True)

        top_factors = []
        for feat, contrib in sorted_contribs[:3]:
            direction = "increasing" if contrib > 0 else "decreasing"
            labels = {
                "ip_entropy": "IP address pattern",
                "time_deviation": "Login time anomaly",
                "device_fingerprint": "Device recognition",
                "login_velocity": "Login frequency",
                "wallet_age_score": "Wallet trust score",
            }
            top_factors.append({
                "feature": feat,
                "label": labels.get(feat, feat),
                "contribution": contrib,
                "direction": direction,
                "value": features[feat],
            })

        return {
            "risk_score": risk_score,
            "contributions": contributions,
            "top_factors": top_factors,
            "model": "IsolationForest",
            "feature_count": len(self.feature_names),
        }

    def add_training_sample(self, features: Dict[str, float]):
        """Add a new login event to training data for incremental learning"""
        self.training_data.append(features)
        # Retrain every 50 new samples
        if len(self.training_data) % 50 == 0:
            self._train_model()
