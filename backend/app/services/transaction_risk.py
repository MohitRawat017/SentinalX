"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     SentinelX Transaction Risk Engine                         ║
║                     Behavioral Financial Firewall for ETH Transfers           ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ PURPOSE: Evaluate ETH transfer attempts for risk using behavioral analysis    ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ WHY TRANSACTION RISK SCORING?                                                 ║
║ ═════════════════════════════════════════════════════════════════════════════║
║                                                                               ║
║ In Web3, once a transaction is sent, it CANNOT be reversed:                  ║
║ - No bank to call for chargeback                                             ║
║ - No customer support to help                                                ║
║ - Irreversible by design (blockchain immutability)                           ║
║                                                                               ║
║ THIS ENGINE PROTECTS AGAINST:                                                 ║
║ 1. Social Engineering: Scammers convincing users to send ETH                ║
║ 2. Account Takeover: Attacker trying to drain wallet                        ║
║ 3. Phishing: Fake urgency to bypass user's normal caution                    ║
║ 4. Money Laundering: Unusual transaction patterns                            ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ RISK FACTORS ANALYZED:                                                        ║
║ ═════════════════════════════════════════════════════════════════════════════║
║                                                                               ║
║ 1. AMOUNT DEVIATION (Weight: 0.35)                                           ║
║    - Is this amount unusual for this user?                                   ║
║    - Uses log scale to handle wide range of ETH values                       ║
║    - First transaction uses absolute thresholds                              ║
║                                                                               ║
║ 2. FREQUENCY ANOMALY (Weight: 0.25)                                          ║
║    - Too many transactions in short time?                                    ║
║    - Detects rapid-fire attempts (account takeover)                         ║
║                                                                               ║
║ 3. FIRST-TIME RECIPIENT (Weight: 0.20)                                       ║
║    - Has user sent to this address before?                                   ║
║    - Less suspicious if user has many recipients (diverse history)          ║
║                                                                               ║
║ 4. URGENCY LANGUAGE (Weight: 0.20)                                           ║
║    - Does chat context contain manipulation phrases?                         ║
║    - "urgent", "send now", "don't tell anyone"                               ║
║                                                                               ║
║ INTERVIEW QUESTION: Why analyze chat context?                                ║
║ ANSWER: Social engineering attacks often happen in chat:                    ║
║ - "This is urgent, send 5 ETH to this address immediately!"                 ║
║ - Without context analysis, this looks like a normal transfer               ║
║ - Urgency phrases are strong indicators of scams                            ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
import hashlib
import json
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import TransactionEvent
from app.services.blockchain import get_transaction_network


# ───────────────────────────────────────────────────────────────────────────────
# RISK WEIGHTS CONFIGURATION
# ───────────────────────────────────────────────────────────────────────────────
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║ WEIGHTS DETERMINE THE IMPORTANCE OF EACH RISK FACTOR                          ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║ WEIGHT_AMOUNT_DEVIATION (0.35):                                               ║
║ - HIGHEST weight - unusual amounts are strong signals                        ║
║ - Scammers often request specific unusual amounts                           ║
║                                                                               ║
║ WEIGHT_FREQUENCY_ANOMALY (0.25):                                              ║
║ - HIGH weight - rapid transactions = account takeover                       ║
║                                                                               ║
║ WEIGHT_FIRST_RECIPIENT (0.20):                                                ║
║ - MEDIUM weight - new recipient is common but worth checking                ║
║                                                                               ║
║ WEIGHT_URGENCY_LANGUAGE (0.20):                                               ║
║ - MEDIUM weight - social engineering indicator                              ║
║                                                                               ║
║ Total = 1.0 (normalized)                                                     ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
WEIGHT_AMOUNT_DEVIATION = 0.35
WEIGHT_FREQUENCY_ANOMALY = 0.25
WEIGHT_FIRST_RECIPIENT = 0.20
WEIGHT_URGENCY_LANGUAGE = 0.20

MAX_RAW_SCORE = (WEIGHT_AMOUNT_DEVIATION + WEIGHT_FREQUENCY_ANOMALY +
                 WEIGHT_FIRST_RECIPIENT + WEIGHT_URGENCY_LANGUAGE)

# ───────────────────────────────────────────────────────────────────────────────
# RISK THRESHOLDS
# ───────────────────────────────────────────────────────────────────────────────
"""
Risk Level Thresholds (normalized 0-1 scale):

THRESHOLD_SAFE (0.3):
- Below this = LOW risk
- Action: Allow transfer, proceed to MetaMask

THRESHOLD_STEP_UP (0.6):
- Between SAFE and STEP_UP = MEDIUM risk
- Action: Require step-up verification
- Above STEP_UP = HIGH risk
- Action: Block transfer, apply cooldown
"""
THRESHOLD_SAFE = 0.3
THRESHOLD_STEP_UP = 0.6

# Cooldown duration for high-risk transactions
# Short (1 minute) for demo - would be longer in production
COOLDOWN_MINUTES = 1


# ───────────────────────────────────────────────────────────────────────────────
# URGENCY PHRASES - Social Engineering Detection
# ───────────────────────────────────────────────────────────────────────────────
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║ SOCIAL ENGINEERING RED FLAGS                                                  ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║ These phrases are common in:                                                  ║
║ - Romance scams: "trust me", "keep this between us"                          ║
║ - Investment scams: "guaranteed", "once in a lifetime"                       ║
║ - Impersonation scams: "urgent", "send now", "emergency"                     ║
║ - Panic scams: "before it's too late", "act fast"                            ║
║                                                                               ║
║ WHY MULTIPLE MATCHES MATTER:                                                  ║
║ 1 match: Might be legitimate urgency                                         ║
║ 3+ matches: Almost certainly manipulation attempt                            ║
║                                                                               ║
║ INTERVIEW QUESTION: How do you avoid false positives?                        ║
║ ANSWER: Graduated scoring:                                                   ║
║ - 0 matches: 0.0 risk                                                        ║
║ - 1 match: 0.3 (might be legitimate)                                         ║
║ - 3+ matches: 0.8-1.0 (highly suspicious)                                    ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
URGENCY_PHRASES = [
    "urgent", "immediately", "right now", "asap", "hurry",
    "send now", "quick", "emergency", "don't wait", "act fast",
    "limited time", "last chance", "before it's too late",
    "trust me", "don't tell anyone", "keep this between us",
    "once in a lifetime", "guaranteed", "wire immediately",
]


class TransactionRiskEngine:
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ TRANSACTION RISK ENGINE - Singleton                                       ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ RESPONSIBILITIES:                                                          ║
    ║ 1. Evaluate proposed ETH transfers for risk                              ║
    ║ 2. Compare against user's historical patterns                             ║
    ║ 3. Detect social engineering in chat context                              ║
    ║ 4. Recommend action (allow, step-up, block)                               ║
    ║                                                                           ║
    ║ SINGLETON PATTERN:                                                         ║
    ║ - Consistent scoring across the application                               ║
    ║ - Access via TransactionRiskEngine.get_instance()                         ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """

    _instance = None

    @classmethod
    def get_instance(cls):
        """Get singleton instance of TransactionRiskEngine."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ═══════════════════════════════════════════════════════════════════════════
    # MAIN EVALUATION METHOD
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def evaluate(
        self,
        db: AsyncSession,
        sender_wallet: str,
        recipient_wallet: str,
        amount_eth: float,
        chat_context: Optional[str] = None,
    ) -> Tuple[float, str, Dict]:
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ EVALUATE RISK OF A PROPOSED ETH TRANSFER                                  ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ @param db: AsyncSession - Database connection                             ║
        ║ @param sender_wallet: str - Sender's wallet address                       ║
        ║ @param recipient_wallet: str - Recipient's wallet address                 ║
        ║ @param amount_eth: float - Amount to transfer in ETH                      ║
        ║ @param chat_context: Optional[str] - Chat messages before transfer        ║
        ║ @returns: Tuple[float, str, Dict] - (risk_score, risk_level, explanation) ║
        ║                                                                           ║
        ║ ALGORITHM:                                                                 ║
        ║ 1. Fetch user's transaction history                                       ║
        ║ 2. Compute each risk factor (0.0 to 1.0)                                  ║
        ║ 3. Apply weights and normalize                                            ║
        ║ 4. Check for active cooldown                                              ║
        ║ 5. Determine risk level and action                                        ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        sender = sender_wallet.lower()
        recipient = recipient_wallet.lower()

        # Get user's completed transaction history for pattern analysis
        history = await self._get_history(db, sender)

        # ─── COMPUTE RISK FACTORS ─────────────────────────────────────────
        # Each factor returns 0.0 to 1.0 (graduated, not binary)
        
        # Check if amount is unusual for this user
        amount_dev = self._check_amount_deviation(amount_eth, history)
        
        # Check for rapid transaction frequency
        freq_anomaly = self._check_frequency_anomaly(history)
        
        # Check if this is a first-time recipient
        first_recipient = self._check_first_recipient(recipient, history)
        
        # Check for social engineering phrases in chat
        urgency = self._check_urgency_language(chat_context)

        # ─── COMPUTE WEIGHTED SCORE ──────────────────────────────────────
        raw_score = (
            amount_dev * WEIGHT_AMOUNT_DEVIATION +
            freq_anomaly * WEIGHT_FREQUENCY_ANOMALY +
            first_recipient * WEIGHT_FIRST_RECIPIENT +
            urgency * WEIGHT_URGENCY_LANGUAGE
        )
        risk_score = round(min(raw_score / MAX_RAW_SCORE, 1.0), 4)

        # ─── DETERMINE RISK LEVEL ────────────────────────────────────────
        if risk_score < THRESHOLD_SAFE:
            risk_level = "low"
        elif risk_score < THRESHOLD_STEP_UP:
            risk_level = "medium"
        else:
            risk_level = "high"

        # ─── CHECK COOLDOWN ──────────────────────────────────────────────
        # If user is in cooldown from previous high-risk transaction
        in_cooldown = await self._check_cooldown(db, sender)
        if in_cooldown:
            risk_level = "high"
            risk_score = max(risk_score, 0.9)

        # ─── COMPUTE DISPLAY SCORE ──────────────────────────────────────
        # Convert to 0-100 scale (inverted: high risk = low score)
        display_score = max(0, round((1 - risk_score) * 100))

        factors = {
            "amount_deviation": amount_dev,
            "frequency_anomaly": freq_anomaly,
            "first_time_recipient": first_recipient,
            "urgency_language": urgency,
        }

        explanation = self._explain(factors, risk_score, risk_level, display_score, in_cooldown)

        # ─── BUILD EVENT HASH ───────────────────────────────────────────
        # Hash for audit trail and Merkle tree inclusion
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

    # ═══════════════════════════════════════════════════════════════════════════
    # RISK FACTOR COMPUTATION METHODS
    # ═══════════════════════════════════════════════════════════════════════════

    def _check_amount_deviation(self, amount_eth: float, history: List[TransactionEvent]) -> float:
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ CHECK IF TRANSFER AMOUNT IS UNUSUAL FOR THIS USER                         ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ GRADUATED SCORING:                                                         ║
        ║ - Within 1.5x of historical average: 0.0 (normal)                         ║
        ║ - Above average: Log scale based on ratio                                 ║
        ║ - First transaction: Based on absolute amount                            ║
        ║                                                                           ║
        ║ WHY LOG SCALE?                                                             ║
        ║ ETH amounts vary widely (0.001 to 100+ ETH).                              ║
        ║ Linear scale would be dominated by large amounts.                         ║
        ║ Log scale handles the wide range fairly.                                   ║
        ║                                                                           ║
        ║ EXAMPLES:                                                                  ║
        ║ - User typically sends 1 ETH                                              ║
        ║ - Sending 1.5 ETH: 0.0 risk (within normal)                               ║
        ║ - Sending 5 ETH: ~0.4 risk (moderate)                                     ║
        ║ - Sending 50 ETH: ~1.0 risk (very unusual)                                ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        if not history:
            # First transaction: graduated by absolute amount
            if amount_eth <= 0.01:
                return 0.1  # Small amount = low risk
            # Larger amounts have higher base risk for first transaction
            return min(1.0, 0.3 + 0.3 * math.log10(amount_eth / 0.01))

        # Calculate historical average
        avg = sum(e.amount_eth for e in history) / len(history)
        if avg <= 0:
            if amount_eth <= 0.01:
                return 0.1
            return min(1.0, 0.3 + 0.3 * math.log10(amount_eth / 0.01))

        # Calculate ratio to average
        ratio = amount_eth / avg
        if ratio <= 1.5:
            return 0.0  # Within normal range (150% of average)
        
        # Log scale: ratio 1.5 → 0.0, ratio 50 → 1.0
        return min(1.0, math.log(ratio / 1.5) / math.log(50 / 1.5))

    def _check_frequency_anomaly(self, history: List[TransactionEvent]) -> float:
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ CHECK FOR UNUSUAL TRANSACTION FREQUENCY                                   ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ WHAT THIS DETECTS:                                                         ║
        ║ - Account takeover: Attacker trying to drain wallet quickly              ║
        ║ - Scripted attacks: Bots making rapid transactions                       ║
        ║ - Panic behavior: User being manipulated to send multiple times          ║
        ║                                                                           ║
        ║ WINDOW: Last 30 minutes                                                    ║
        ║                                                                           ║
        ║ GRADUATED SCORING:                                                         ║
        ║ - 0-1 transactions: 0.0 (normal)                                          ║
        ║ - 2 transactions: 0.3 (slightly elevated)                                 ║
        ║ - 3 transactions: 0.6 (suspicious)                                        ║
        ║ - 4 transactions: 0.8 (very suspicious)                                   ║
        ║ - 5+ transactions: 1.0 (almost certainly attack)                          ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        if not history:
            return 0.0
        
        # Count transactions in last 30 minutes
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
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ CHECK IF THIS IS A FIRST-TIME RECIPIENT                                   ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ WHY THIS MATTERS:                                                          ║
        ║ - Scammers direct victims to new addresses                                ║
        ║ - Account takeovers send to attacker's address                            ║
        ║ - New recipient = less trust established                                   ║
        ║                                                                           ║
        ║ BUT CONTEXT MATTERS:                                                       ║
        ║ - User with 10+ recipients: More likely to legitimately add new one      ║
        ║ - User with 1 recipient: New recipient is more suspicious                ║
        ║                                                                           ║
        ║ GRADUATED SCORING:                                                         ║
        ║ - Known recipient: 0.0                                                    ║
        ║ - New recipient + 10+ known addresses: 0.4                               ║
        ║ - New recipient + 5-9 known addresses: 0.6                               ║
        ║ - New recipient + <5 known addresses: 1.0                                ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        if not history:
            return 1.0  # First transaction ever = always first recipient
        
        # Build set of known recipients
        known_recipients = {e.recipient_wallet for e in history}
        
        # Check if recipient is known
        if recipient in known_recipients:
            return 0.0  # Known recipient = no risk
        
        # New recipient - factor in user's diversity
        diversity = len(known_recipients)
        if diversity >= 10:
            return 0.4  # User sends to many addresses, new one is less suspicious
        elif diversity >= 5:
            return 0.6
        return 1.0  # User has few recipients, new one is suspicious

    def _check_urgency_language(self, chat_context: Optional[str]) -> float:
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ CHECK FOR SOCIAL ENGINEERING PHRASES IN CHAT CONTEXT                      ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ WHAT THIS DETECTS:                                                         ║
        ║ - Romance scams: "trust me", "keep this between us"                       ║
        ║ - Investment scams: "guaranteed", "once in a lifetime"                    ║
        ║ - Impersonation: "urgent", "emergency", "send now"                        ║
        ║ - Panic induction: "before it's too late", "act fast"                     ║
        ║                                                                           ║
        ║ GRADUATED SCORING:                                                         ║
        ║ - 0 matches: 0.0                                                          ║
        ║ - 1 match: 0.3 (could be legitimate)                                      ║
        ║ - 2 matches: 0.6 (suspicious)                                             ║
        ║ - 3 matches: 0.8 (very suspicious)                                        ║
        ║ - 4+ matches: 1.0 (almost certainly a scam)                               ║
        ║                                                                           ║
        ║ INTERVIEW QUESTION: What if someone legitimately needs to send urgently? ║
        ║ ANSWER: That's why it's graduated, not binary.                            ║
        ║ - 1 phrase match = 0.3 (low contribution)                                  ║
        ║ - Combined with other low factors, still might be approved                ║
        ║ - Multiple matches = higher contribution → step-up or block               ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        if not chat_context:
            return 0.0
        
        # Count matching phrases
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

    # ═══════════════════════════════════════════════════════════════════════════
    # HELPER METHODS
    # ═══════════════════════════════════════════════════════════════════════════

    async def _check_cooldown(self, db: AsyncSession, wallet: str) -> bool:
        """
        Check if wallet has an active cooldown from a previous blocked transaction.
        
        Cooldown prevents users from bypassing blocks by retrying immediately.
        """
        result = await db.execute(
            select(TransactionEvent).where(
                TransactionEvent.sender_wallet == wallet,
                TransactionEvent.network == get_transaction_network(),
                TransactionEvent.cooldown_until != None,
                TransactionEvent.cooldown_until > datetime.utcnow(),
            ).limit(1)
        )
        return result.scalar() is not None

    async def _get_history(self, db: AsyncSession, wallet: str, limit: int = 50) -> List[TransactionEvent]:
        """
        Fetch user's COMPLETED transaction history for pattern analysis.
        
        Only includes completed transactions (not blocked/pending) because:
        - We want to learn from successful behavior
        - Blocked transactions might be attacks (not representative)
        """
        result = await db.execute(
            select(TransactionEvent)
            .where(
                TransactionEvent.sender_wallet == wallet,
                TransactionEvent.network == get_transaction_network(),
                TransactionEvent.status == "completed",
            )
            .order_by(desc(TransactionEvent.created_at))
            .limit(limit)
        )
        return list(result.scalars().all())

    # ═══════════════════════════════════════════════════════════════════════════
    # EXPLANATION GENERATOR
    # ═══════════════════════════════════════════════════════════════════════════

    def _explain(self, factors: Dict, risk_score: float, risk_level: str, display_score: int, in_cooldown: bool) -> Dict:
        """
        Generate human-readable explanation of the risk score.
        
        Provides detailed breakdown for:
        - User understanding ("Why was my transfer flagged?")
        - Audit trail (what factors contributed?)
        - Debugging (why did this get blocked?)
        """
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

        # Build detailed factor breakdown
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

        # Map risk level to action
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


# ═══════════════════════════════════════════════════════════════════════════════
# INTERVIEW QUESTIONS FOR transaction_risk.py
# ═══════════════════════════════════════════════════════════════════════════════
"""
Q1: Why use log scale for amount deviation?
A1: ETH amounts span many orders of magnitude (0.001 to 100+ ETH).
    Linear scale would make small differences in large amounts dominate.
    Log scale handles the wide range fairly:
    - 10x increase = same score increase regardless of base amount
    - 0.01 → 0.1 ETH same as 1 → 10 ETH

Q2: How does the cooldown mechanism work?
A2: When a transaction is blocked (high risk):
    1. Cooldown timestamp is set (1 minute for demo)
    2. Future transactions during cooldown get max risk
    3. Prevents attackers from rapid retry attempts
    4. User must wait for cooldown to expire

Q3: Why only use completed transactions for history?
A3: We want to learn from successful behavior patterns.
    Blocked transactions might be:
    - Attack attempts (shouldn't affect baseline)
    - Accidental mistakes (not representative)
    Using completed transactions gives accurate user behavior model.

Q4: How would you improve this for a real banking app?
A4: Additional factors:
    - Time-of-day patterns (is 3 AM transfer unusual?)
    - Location data (is this IP/location normal?)
    - Device fingerprint (new device?)
    - Transaction velocity (acceleration of amounts?)
    - Recipient reputation (is address flagged?)
    - AI/ML model trained on fraud data

Q5: What's the difference between this and login risk engine?
A5: Login Risk Engine:
    - Checks identity verification
    - Factors: device, location, time
    - Goal: Is this really the user?
    
    Transaction Risk Engine:
    - Checks behavioral patterns
    - Factors: amount, frequency, recipient, context
    - Goal: Is this action legitimate?
    
    They complement each other - both are needed for security.
"""
