"""
SentinelX Transaction Risk Engine
Behavioral financial firewall for in-chat ETH transfers.
"""
import hashlib
import json
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import TransactionEvent


# ─── Weights ─────────────────────────────────────────────────────────
WEIGHT_AMOUNT_DEVIATION = 0.35
WEIGHT_FREQUENCY_ANOMALY = 0.25
WEIGHT_FIRST_RECIPIENT = 0.20
WEIGHT_URGENCY_LANGUAGE = 0.20

MAX_RAW_SCORE = (WEIGHT_AMOUNT_DEVIATION + WEIGHT_FREQUENCY_ANOMALY +
                 WEIGHT_FIRST_RECIPIENT + WEIGHT_URGENCY_LANGUAGE)

# Thresholds (0-1 normalized → mapped to 0-100 display)
THRESHOLD_SAFE = 0.3       # < 0.3 = safe (80-100 display)
THRESHOLD_STEP_UP = 0.6    # 0.3-0.6 = step-up (50-79 display)
# > 0.6 = blocked + cooldown (< 50 display)

COOLDOWN_MINUTES = 1  # 1 minute (reduced for testing)

# Urgency phrases for social engineering detection
URGENCY_PHRASES = [
    "urgent", "immediately", "right now", "asap", "hurry",
    "send now", "quick", "emergency", "don't wait", "act fast",
    "limited time", "last chance", "before it's too late",
    "trust me", "don't tell anyone", "keep this between us",
    "once in a lifetime", "guaranteed", "wire immediately",
]


class TransactionRiskEngine:
    """Behavioral risk scoring for ETH transfers."""

    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def evaluate(
        self,
        db: AsyncSession,
        sender_wallet: str,
        recipient_wallet: str,
        amount_eth: float,
        chat_context: Optional[str] = None,
    ) -> Tuple[float, str, Dict]:
        """
        Evaluate risk of a proposed ETH transfer.
        Returns (risk_score 0-1, risk_level, explanation dict).
        """
        sender = sender_wallet.lower()
        recipient = recipient_wallet.lower()

        history = await self._get_history(db, sender)

        # Compute graduated factors (each 0.0 to 1.0)
        amount_dev = self._check_amount_deviation(amount_eth, history)
        freq_anomaly = self._check_frequency_anomaly(history)
        first_recipient = self._check_first_recipient(recipient, history)
        urgency = self._check_urgency_language(chat_context)

        raw_score = (
            amount_dev * WEIGHT_AMOUNT_DEVIATION +
            freq_anomaly * WEIGHT_FREQUENCY_ANOMALY +
            first_recipient * WEIGHT_FIRST_RECIPIENT +
            urgency * WEIGHT_URGENCY_LANGUAGE
        )
        risk_score = round(min(raw_score / MAX_RAW_SCORE, 1.0), 4)

        if risk_score < THRESHOLD_SAFE:
            risk_level = "low"
        elif risk_score < THRESHOLD_STEP_UP:
            risk_level = "medium"
        else:
            risk_level = "high"

        # Check if sender is in cooldown
        in_cooldown = await self._check_cooldown(db, sender)
        if in_cooldown:
            risk_level = "high"
            risk_score = max(risk_score, 0.9)

        # Compute display score (0-100 inverted: high risk_score → low trust)
        display_score = max(0, round((1 - risk_score) * 100))

        factors = {
            "amount_deviation": amount_dev,
            "frequency_anomaly": freq_anomaly,
            "first_time_recipient": first_recipient,
            "urgency_language": urgency,
        }

        explanation = self._explain(factors, risk_score, risk_level, display_score, in_cooldown)

        # Build event hash
        event_data = json.dumps({
            "sender": sender, "recipient": recipient,
            "amount": amount_eth, "risk_score": risk_score,
            "timestamp": datetime.utcnow().isoformat(),
        }, sort_keys=True)
        event_hash = hashlib.sha256(event_data.encode()).hexdigest()

        explanation["event_hash"] = event_hash
        explanation["display_score"] = display_score
        explanation["in_cooldown"] = in_cooldown

        return risk_score, risk_level, explanation

    # ─── Factor Checks ────────────────────────────────────────────────

    def _check_amount_deviation(self, amount_eth: float, history: List[TransactionEvent]) -> float:
        """Graduated score based on how much amount deviates from historical average."""
        if not history:
            # First transaction: graduated by absolute amount
            if amount_eth <= 0.01:
                return 0.1
            return min(1.0, 0.3 + 0.3 * math.log10(amount_eth / 0.01))

        avg = sum(e.amount_eth for e in history) / len(history)
        if avg <= 0:
            if amount_eth <= 0.01:
                return 0.1
            return min(1.0, 0.3 + 0.3 * math.log10(amount_eth / 0.01))

        ratio = amount_eth / avg
        if ratio <= 1.5:
            return 0.0  # within normal range
        # Log scale: ratio 1.5 → 0.0, ratio 50 → 1.0
        return min(1.0, math.log(ratio / 1.5) / math.log(50 / 1.5))

    def _check_frequency_anomaly(self, history: List[TransactionEvent]) -> float:
        """Graduated score based on transaction frequency in last 30 minutes."""
        if not history:
            return 0.0
        cutoff = datetime.utcnow() - timedelta(minutes=30)
        recent = sum(1 for e in history if e.created_at and e.created_at >= cutoff)
        if recent <= 1:
            return 0.0
        elif recent == 2:
            return 0.3
        elif recent == 3:
            return 0.6
        elif recent == 4:
            return 0.8
        else:
            return 1.0

    def _check_first_recipient(self, recipient: str, history: List[TransactionEvent]) -> float:
        """Score based on recipient familiarity and sender's diversity."""
        if not history:
            return 1.0
        known_recipients = {e.recipient_wallet for e in history}
        if recipient in known_recipients:
            return 0.0
        # New recipient: less alarming if sender has diverse history
        diversity = len(known_recipients)
        if diversity >= 10:
            return 0.4
        elif diversity >= 5:
            return 0.6
        return 1.0

    def _check_urgency_language(self, chat_context: Optional[str]) -> float:
        """Graduated score based on number of urgency/manipulation phrases."""
        if not chat_context:
            return 0.0
        lower = chat_context.lower()
        matches = sum(1 for phrase in URGENCY_PHRASES if phrase in lower)
        if matches == 0:
            return 0.0
        elif matches == 1:
            return 0.3
        elif matches == 2:
            return 0.6
        elif matches == 3:
            return 0.8
        else:
            return 1.0

    async def _check_cooldown(self, db: AsyncSession, wallet: str) -> bool:
        """Check if wallet has an active cooldown."""
        result = await db.execute(
            select(TransactionEvent).where(
                TransactionEvent.sender_wallet == wallet,
                TransactionEvent.cooldown_until != None,
                TransactionEvent.cooldown_until > datetime.utcnow(),
            ).limit(1)
        )
        return result.scalar() is not None

    # ─── History ──────────────────────────────────────────────────────

    async def _get_history(self, db: AsyncSession, wallet: str, limit: int = 50) -> List[TransactionEvent]:
        """Fetch only COMPLETED transactions (actually sent) for risk baseline."""
        result = await db.execute(
            select(TransactionEvent)
            .where(
                TransactionEvent.sender_wallet == wallet,
                TransactionEvent.status == "completed",
            )
            .order_by(desc(TransactionEvent.created_at))
            .limit(limit)
        )
        return list(result.scalars().all())

    # ─── Explanation ──────────────────────────────────────────────────

    def _explain(self, factors: Dict, risk_score: float, risk_level: str, display_score: int, in_cooldown: bool) -> Dict:
        labels = {
            "amount_deviation": "Amount deviates from historical average",
            "frequency_anomaly": "Unusual transaction frequency",
            "first_time_recipient": "First-time recipient wallet",
            "urgency_language": "Urgency / manipulation language detected",
        }
        weights = {
            "amount_deviation": WEIGHT_AMOUNT_DEVIATION,
            "frequency_anomaly": WEIGHT_FREQUENCY_ANOMALY,
            "first_time_recipient": WEIGHT_FIRST_RECIPIENT,
            "urgency_language": WEIGHT_URGENCY_LANGUAGE,
        }

        factor_list = []
        for feat, value in factors.items():
            contribution = round(value * weights[feat] / MAX_RAW_SCORE, 4)
            factor_list.append({
                "feature": feat,
                "label": labels[feat],
                "triggered": value >= 0.5,
                "weight": weights[feat],
                "contribution": contribution,
                "value": value,
            })
        factor_list.sort(key=lambda f: f["contribution"], reverse=True)

        actions = {
            "low": "Safe — proceed to MetaMask",
            "medium": "Step-up verification required",
            "high": "Blocked — cooldown applied",
        }

        result = {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "display_score": display_score,
            "action": actions.get(risk_level, "unknown"),
            "factors": factor_list,
            "step_up_required": risk_level == "medium",
            "blocked": risk_level == "high",
            "cooldown_minutes": COOLDOWN_MINUTES if risk_level == "high" else 0,
        }

        if in_cooldown:
            result["action"] = f"Blocked — active cooldown ({COOLDOWN_MINUTES}min)"

        return result
