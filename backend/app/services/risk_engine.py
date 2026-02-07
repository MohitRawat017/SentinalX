"""
SentinelX AI Risk Engine
Weighted history-aware login risk scoring
"""
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import LoginEvent


# ─── Weights from ADD_ON spec ────────────────────────────────────────
WEIGHT_NEW_DEVICE = 0.4
WEIGHT_NEW_COUNTRY = 0.4
WEIGHT_RAPID_ATTEMPTS = 0.6
WEIGHT_ABNORMAL_TIME = 0.2

MAX_RAW_SCORE = (WEIGHT_NEW_DEVICE + WEIGHT_NEW_COUNTRY +
                 WEIGHT_RAPID_ATTEMPTS + WEIGHT_ABNORMAL_TIME)  # 1.6

# Thresholds
THRESHOLD_LOW = 0.4
THRESHOLD_HIGH = 0.7

# Rapid-attempts: 3+ logins within this window triggers the factor
RAPID_WINDOW_MINUTES = 10
RAPID_COUNT_THRESHOLD = 3

# Normal hours range (inclusive)
NORMAL_HOUR_START = 6
NORMAL_HOUR_END = 22


class RiskEngine:
    """History-aware weighted login risk scoring"""

    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ─── Core scoring (async, needs DB) ──────────────────────────────

    async def score(
        self,
        db: AsyncSession,
        wallet_address: str,
        ip_address: str = "0.0.0.0",
        user_agent: str = "",
        geo_country: Optional[str] = None,
        current_hour: Optional[int] = None,
    ) -> Tuple[float, str, Dict]:
        """
        Compute risk score for a login attempt using wallet history.
        Returns (risk_score, risk_level, explanation).
        """
        wallet = wallet_address.lower()
        if current_hour is None:
            current_hour = datetime.utcnow().hour

        # Fetch recent login history for this wallet
        history = await self._get_history(db, wallet)

        # Compute graduated factors (each 0.0 to 1.0)
        new_device = self._check_new_device(user_agent, history)
        new_country = self._check_new_country(geo_country, history)
        rapid_attempts = self._check_rapid_attempts(history)
        abnormal_time = self._check_abnormal_time(current_hour)

        # Weighted sum → normalize to 0-1
        raw_score = (
            new_device * WEIGHT_NEW_DEVICE +
            new_country * WEIGHT_NEW_COUNTRY +
            rapid_attempts * WEIGHT_RAPID_ATTEMPTS +
            abnormal_time * WEIGHT_ABNORMAL_TIME
        )
        risk_score = round(min(raw_score / MAX_RAW_SCORE, 1.0), 4)

        # Risk level
        if risk_score < THRESHOLD_LOW:
            risk_level = "low"
        elif risk_score < THRESHOLD_HIGH:
            risk_level = "medium"
        else:
            risk_level = "high"

        # Build features dict (for storage in LoginEvent.risk_features)
        features = {
            "new_device": new_device,
            "new_country": new_country,
            "rapid_attempts": rapid_attempts,
            "abnormal_time": abnormal_time,
        }

        # Build explanation
        explanation = self._explain(features, risk_score, risk_level)

        return risk_score, risk_level, explanation

    # ─── Factor checks ───────────────────────────────────────────────

    def _check_new_device(self, user_agent: str, history: List[LoginEvent]) -> float:
        """Score based on device familiarity and device diversity."""
        if not user_agent or not history:
            return 1.0
        ua_hash = hashlib.md5(user_agent.encode()).hexdigest()
        known_devices = set()
        for event in history:
            if event.user_agent:
                known_devices.add(hashlib.md5(event.user_agent.encode()).hexdigest())
        if ua_hash in known_devices:
            return 0.0
        # New device: less alarming if user regularly uses multiple devices
        if len(known_devices) >= 5:
            return 0.4
        elif len(known_devices) >= 3:
            return 0.6
        return 1.0

    def _check_new_country(self, geo_country: Optional[str], history: List[LoginEvent]) -> float:
        """Score based on geographic familiarity."""
        if not geo_country:
            return 0.0
        if not history:
            return 0.5  # first login, moderate
        known_countries = {e.geo_country for e in history if e.geo_country}
        if geo_country in known_countries:
            return 0.0
        # New country: less suspicious if user travels frequently
        if len(known_countries) >= 5:
            return 0.5
        return 1.0

    def _check_rapid_attempts(self, history: List[LoginEvent]) -> float:
        """Graduated score based on login frequency in recent window."""
        if not history:
            return 0.0
        cutoff = datetime.utcnow() - timedelta(minutes=RAPID_WINDOW_MINUTES)
        recent_count = sum(1 for e in history if e.timestamp and e.timestamp >= cutoff)
        if recent_count < 2:
            return 0.0
        elif recent_count == 2:
            return 0.3
        elif recent_count == 3:
            return 0.6
        elif recent_count == 4:
            return 0.8
        else:
            return 1.0

    def _check_abnormal_time(self, current_hour: int) -> float:
        """Graduated score based on how far outside normal hours."""
        if NORMAL_HOUR_START <= current_hour <= NORMAL_HOUR_END:
            return 0.0
        # How far outside normal hours?
        if current_hour < NORMAL_HOUR_START:
            distance = NORMAL_HOUR_START - current_hour
        else:
            distance = current_hour - NORMAL_HOUR_END
        if distance <= 2:
            return 0.4
        elif distance <= 4:
            return 0.7
        return 1.0

    # ─── History lookup ──────────────────────────────────────────────

    async def _get_history(self, db: AsyncSession, wallet: str, limit: int = 50) -> List[LoginEvent]:
        """Fetch recent login history for a wallet."""
        result = await db.execute(
            select(LoginEvent)
            .where(LoginEvent.wallet_address == wallet)
            .order_by(desc(LoginEvent.timestamp))
            .limit(limit)
        )
        return list(result.scalars().all())

    # ─── Explanation ─────────────────────────────────────────────────

    def _explain(self, features: Dict[str, float], risk_score: float, risk_level: str) -> Dict:
        """Generate human-readable explanation of the risk score."""
        labels = {
            "new_device": "New device / browser",
            "new_country": "New geographic location",
            "rapid_attempts": "Rapid login attempts",
            "abnormal_time": "Login at unusual hour",
        }
        weights = {
            "new_device": WEIGHT_NEW_DEVICE,
            "new_country": WEIGHT_NEW_COUNTRY,
            "rapid_attempts": WEIGHT_RAPID_ATTEMPTS,
            "abnormal_time": WEIGHT_ABNORMAL_TIME,
        }

        top_factors = []
        for feat, value in features.items():
            contribution = round(value * weights[feat] / MAX_RAW_SCORE, 4)
            top_factors.append({
                "feature": feat,
                "label": labels[feat],
                "triggered": value >= 0.5,
                "weight": weights[feat],
                "contribution": contribution,
                "value": value,
            })

        # Sort by contribution descending
        top_factors.sort(key=lambda f: f["contribution"], reverse=True)

        actions = {
            "low": "Allow — no friction",
            "medium": "Step-up verification required",
            "high": "Block — require re-authentication",
        }

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "action": actions.get(risk_level, "unknown"),
            "factors": top_factors,
            "model": "weighted_history_graduated",
            "formula": "min((device*0.4 + country*0.4 + rapid*0.6 + time*0.2) / 1.6, 1.0) — graduated factors",
        }
