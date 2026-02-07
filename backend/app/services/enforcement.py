"""
SentinelX Security Enforcement Service
Central module that evaluates trust score and enforces security policy.

Trust Score Bands:
  80-100  → active     (normal operation)
  50-79   → step_up_required (wallet re-sign needed for sensitive actions)
  <50     → restricted/locked (sensitive actions disabled, cooldown applied)
"""
from datetime import datetime, timedelta
from typing import Optional, Tuple

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import (
    LoginEvent, GuardEvent, TransactionEvent, SecurityState,
)

# ── Thresholds ────────────────────────────────────────────────────────
TRUST_ACTIVE_THRESHOLD = 80       # >= 80 → active
TRUST_STEP_UP_THRESHOLD = 50      # 50-79 → step_up_required
# <50 → restricted / locked
LOCKOUT_COOLDOWN_MINUTES = 30     # how long a "locked" session lasts


class SecurityEnforcement:
    """Singleton security enforcement engine."""

    _instance: Optional["SecurityEnforcement"] = None

    @classmethod
    def get_instance(cls) -> "SecurityEnforcement":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ── Core: evaluate trust and update security state ───────────────
    async def evaluate_and_enforce(
        self,
        db: AsyncSession,
        wallet_address: str,
    ) -> dict:
        """
        Recompute trust score from all risk events and update the
        SecurityState row.  Returns the current enforcement verdict.
        """
        w = wallet_address.lower()

        # 1. Gather recent risk events
        login_events = (await db.execute(
            select(LoginEvent).where(LoginEvent.wallet_address == w)
            .order_by(desc(LoginEvent.timestamp)).limit(100)
        )).scalars().all()

        guard_events = (await db.execute(
            select(GuardEvent).where(GuardEvent.wallet_address == w)
            .order_by(desc(GuardEvent.timestamp)).limit(100)
        )).scalars().all()

        tx_events = (await db.execute(
            select(TransactionEvent).where(
                (TransactionEvent.sender_wallet == w) |
                (TransactionEvent.recipient_wallet == w)
            ).order_by(desc(TransactionEvent.created_at)).limit(100)
        )).scalars().all()

        # 2. Compute trust score
        trust_score = self._compute_trust_score(login_events, guard_events, tx_events)

        # 3. Determine enforcement status
        now = datetime.utcnow()
        security_status, cooldown_reason, locked_until = self._determine_status(
            trust_score, login_events, tx_events, now,
        )

        # 4. Upsert SecurityState
        result = await db.execute(
            select(SecurityState).where(SecurityState.wallet_address == w)
        )
        state = result.scalar_one_or_none()

        if state is None:
            state = SecurityState(
                wallet_address=w,
                trust_score=trust_score,
                security_status=security_status,
                locked_until=locked_until,
                cooldown_reason=cooldown_reason,
                last_evaluated=now,
                updated_at=now,
            )
            db.add(state)
        else:
            # If currently locked and cooldown not expired, keep locked
            if state.security_status == "locked" and state.locked_until and state.locked_until > now:
                security_status = "locked"
                locked_until = state.locked_until
                cooldown_reason = state.cooldown_reason
            state.trust_score = trust_score
            state.security_status = security_status
            state.locked_until = locked_until
            state.cooldown_reason = cooldown_reason
            state.last_evaluated = now
            state.updated_at = now

        await db.commit()

        return {
            "trust_score": trust_score,
            "security_status": security_status,
            "locked_until": locked_until.isoformat() + "Z" if locked_until else None,
            "cooldown_reason": cooldown_reason,
        }

    # ── Quick check without recomputation ─────────────────────────────
    async def get_security_state(
        self, db: AsyncSession, wallet_address: str,
    ) -> dict:
        """Return stored security state for a wallet (fast lookup)."""
        w = wallet_address.lower()
        result = await db.execute(
            select(SecurityState).where(SecurityState.wallet_address == w)
        )
        state = result.scalar_one_or_none()
        if state is None:
            return {
                "trust_score": 100,
                "security_status": "active",
                "locked_until": None,
                "cooldown_reason": None,
            }

        now = datetime.utcnow()
        # Auto-unlock if cooldown expired
        if state.security_status == "locked" and state.locked_until and state.locked_until <= now:
            state.security_status = "step_up_required"
            state.locked_until = None
            state.cooldown_reason = None
            state.updated_at = now
            await db.commit()

        return {
            "trust_score": state.trust_score,
            "security_status": state.security_status,
            "locked_until": state.locked_until.isoformat() + "Z" if state.locked_until else None,
            "cooldown_reason": state.cooldown_reason,
        }

    # ── Check if action is allowed ────────────────────────────────────
    async def check_action_allowed(
        self, db: AsyncSession, wallet_address: str, action: str = "sensitive",
    ) -> Tuple[bool, str]:
        """
        Returns (allowed, reason).
        action can be: 'login', 'transfer', 'chat_send', 'sensitive'
        """
        state = await self.get_security_state(db, wallet_address)
        status = state["security_status"]

        if status == "locked":
            return False, f"Account temporarily locked. {state['cooldown_reason'] or 'Suspicious activity detected.'}  Unlocks at {state['locked_until'] or 'soon'}."

        if status == "restricted":
            if action in ("transfer", "sensitive"):
                return False, "Account restricted due to suspicious activity. Transfers and sensitive actions are disabled."
            # Allow read-only, login, chat viewing
            return True, ""

        if status == "step_up_required":
            if action == "transfer":
                return True, "step_up_required"  # extra confirmation needed
            return True, ""

        return True, ""

    # ── Private helpers ───────────────────────────────────────────────
    def _compute_trust_score(self, login_events, guard_events, tx_events) -> int:
        score = 100.0

        # Login penalties (weight: 40%)
        if login_events:
            high_logins = sum(1 for e in login_events if e.risk_level == "high")
            medium_logins = sum(1 for e in login_events if e.risk_level == "medium")
            login_penalty = min(40, high_logins * 8 + medium_logins * 3)
            score -= login_penalty

        # Guard penalties (weight: 30%)
        if guard_events:
            threats = sum(1 for e in guard_events if e.risk_detected)
            overrides = sum(1 for e in guard_events if e.user_override)
            guard_penalty = min(30, threats * 5 + overrides * 2)
            score -= guard_penalty

        # Transaction penalties (weight: 30%)
        if tx_events:
            blocked = sum(1 for e in tx_events if e.status == "blocked")
            cooldowns = sum(1 for e in tx_events if e.cooldown_until is not None)
            tx_penalty = min(30, blocked * 10 + cooldowns * 5)
            score -= tx_penalty

        return max(0, round(score))

    def _determine_status(
        self, trust_score: int, login_events, tx_events, now: datetime,
    ) -> Tuple[str, Optional[str], Optional[datetime]]:
        """Returns (status, cooldown_reason, locked_until)."""

        if trust_score >= TRUST_ACTIVE_THRESHOLD:
            return "active", None, None

        if trust_score >= TRUST_STEP_UP_THRESHOLD:
            return "step_up_required", None, None

        # Below 50 → check severity
        recent_high_logins = sum(
            1 for e in login_events[:20] if e.risk_level == "high"
        )
        recent_blocked_tx = sum(
            1 for e in tx_events[:20] if e.status == "blocked"
        )

        if recent_high_logins >= 3 or recent_blocked_tx >= 2:
            # Hard lock
            return (
                "locked",
                "Multiple high-risk events detected. Temporary session lock applied.",
                now + timedelta(minutes=LOCKOUT_COOLDOWN_MINUTES),
            )

        # Soft restriction
        return (
            "restricted",
            "Elevated risk level. Sensitive actions disabled until trust is restored.",
            None,
        )
