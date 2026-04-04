"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     SentinelX Security Enforcement Service                     ║
║                     Trust Score & Adaptive Security System                     ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ PURPOSE: Central module that evaluates trust score and enforces security      ║
║          policy based on accumulated risk events.                             ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ TRUST SCORE SYSTEM:                                                           ║
║ ═════════════════════════════════════════════════════════════════════════════║
║                                                                               ║
║ TRUST SCORE (0-100):                                                          ║
║ - Starts at 100 (trusted)                                                    ║
║ - Decreases based on risk events                                             ║
║ - Can be restored through step-up verification                               ║
║                                                                               ║
║ TRUST BANDS:                                                                  ║
║ ┌─────────────────────────────────────────────────────────────────────────┐   ║
║ │  80-100  → ACTIVE          Normal operation, no restrictions           │   ║
║ │  50-79   → STEP_UP_REQUIRED  Wallet re-sign needed for sensitive actions│  ║
║ │  <50     → RESTRICTED/LOCKED  Sensitive actions disabled, cooldown     │   ║
║ └─────────────────────────────────────────────────────────────────────────┘   ║
║                                                                               ║
║ HOW TRUST SCORE IS COMPUTED:                                                  ║
║                                                                               ║
║   Base Score: 100                                                            ║
║   - Login Penalties (max 40): Based on risk_level with recency decay        ║
║   - Guard Penalties (max 30): For DLP violations and overrides             ║
║   - Transaction Penalties (max 30): For blocked/flagged transactions       ║
║   + Trust Bonus: From completed step-up verifications                       ║
║   ─────────────────────────────────────────────                            ║
║   = Final Trust Score (0-100)                                               ║
║                                                                               ║
║ RECENCY DECAY:                                                                ║
║ Events are weighted by recency. Older events have less impact.              ║
║ Formula: recency_factor = max(0.5, 1.0 - index * 0.015)                     ║
║ Most recent event has factor 1.0, decays to minimum 0.5                    ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ SECURITY STATUSES:                                                            ║
║ ═════════════════════════════════════════════════════════════════════════════║
║                                                                               ║
║ ACTIVE:                                                                       ║
║ - User can perform all actions                                               ║
║ - No additional verification required                                        ║
║                                                                               ║
║ STEP_UP_REQUIRED:                                                             ║
║ - User must re-sign with wallet for sensitive actions                       ║
║ - Can still view data, chat, perform low-risk actions                       ║
║                                                                               ║
║ RESTRICTED:                                                                   ║
║ - Sensitive actions disabled (transfers, etc.)                               ║
║ - Can still login and view data                                              ║
║                                                                               ║
║ LOCKED:                                                                       ║
║ - Temporary lockout (1 minute for demo, longer in production)               ║
║ - Cannot login until cooldown expires                                        ║
║ - Triggered by severe patterns (multiple high-risk events)                  ║
║                                                                               ║
║ INTERVIEW QUESTION: Why use trust score instead of binary block/allow?      ║
║ ANSWER: Graduated system provides:                                           ║
║ 1. Better UX - not locked out for one mistake                               ║
║ 2. Path to recovery - step-up verification restores trust                   ║
║ 3. Context awareness - considers behavior patterns over time                ║
║ 4. Adaptive security - response matches risk level                          ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
from datetime import datetime, timedelta
from typing import Optional, Tuple

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import (
    LoginEvent, GuardEvent, TransactionEvent, SecurityState,
)
from app.services.blockchain import get_transaction_network

# ───────────────────────────────────────────────────────────────────────────────
# TRUST SCORE THRESHOLDS
# ───────────────────────────────────────────────────────────────────────────────
"""
Thresholds that determine security status transitions.

TRUST_ACTIVE_THRESHOLD (80):
- Score >= 80: User is fully trusted
- All actions allowed without friction

TRUST_STEP_UP_THRESHOLD (50):
- Score 50-79: User needs verification
- Sensitive actions require wallet re-sign

Below 50:
- User is restricted or locked
- Sensitive actions blocked
"""
TRUST_ACTIVE_THRESHOLD = 80
TRUST_STEP_UP_THRESHOLD = 50

# Cooldown duration for locked accounts
# Short (1 minute) for demo purposes - would be longer in production
LOCKOUT_COOLDOWN_MINUTES = 1


class SecurityEnforcement:
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ SECURITY ENFORCEMENT ENGINE - Singleton                                   ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ RESPONSIBILITIES:                                                          ║
    ║ 1. Compute trust score from all risk events                               ║
    ║ 2. Determine security status (active, step_up, restricted, locked)        ║
    ║ 3. Handle step-up verification bonuses                                    ║
    ║ 4. Enforce action restrictions based on status                            ║
    ║                                                                           ║
    ║ SINGLETON PATTERN:                                                         ║
    ║ - One instance shared across application                                  ║
    ║ - Consistent enforcement decisions                                        ║
    ║ - Access via SecurityEnforcement.get_instance()                           ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """

    _instance: Optional["SecurityEnforcement"] = None

    @classmethod
    def get_instance(cls) -> "SecurityEnforcement":
        """Get singleton instance of SecurityEnforcement."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ═══════════════════════════════════════════════════════════════════════════
    # CORE METHOD: Evaluate and Enforce
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def evaluate_and_enforce(
        self,
        db: AsyncSession,
        wallet_address: str,
    ) -> dict:
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ RECOMPUTE TRUST SCORE AND UPDATE SECURITY STATE                           ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ ALGORITHM:                                                                 ║
        ║ 1. Gather all recent risk events for the wallet                          ║
        ║ 2. Compute trust score using weighted formula                             ║
        ║ 3. Add persisted step-up bonus (survives re-evaluation)                   ║
        ║ 4. Determine security status from score                                   ║
        ║ 5. Upsert SecurityState record in database                                ║
        ║                                                                           ║
        ║ @param db: AsyncSession - Database connection                             ║
        ║ @param wallet_address: str - Wallet to evaluate                           ║
        ║ @returns: dict - {trust_score, security_status, locked_until, ...}        ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        w = wallet_address.lower()

        # ─── STEP 1: GATHER RISK EVENTS ─────────────────────────────────────
        # Fetch recent events from all sources (login, guard, transactions)
        
        # Login events - for login anomaly penalties
        login_events = (await db.execute(
            select(LoginEvent).where(LoginEvent.wallet_address == w)
            .order_by(desc(LoginEvent.timestamp)).limit(100)
        )).scalars().all()

        # Guard events - for DLP violation penalties
        guard_events = (await db.execute(
            select(GuardEvent).where(GuardEvent.wallet_address == w)
            .order_by(desc(GuardEvent.timestamp)).limit(100)
        )).scalars().all()

        # Transaction events - for risky transaction penalties
        tx_events = (await db.execute(
            select(TransactionEvent).where(
                (TransactionEvent.sender_wallet == w) |
                (TransactionEvent.recipient_wallet == w),
                TransactionEvent.network == get_transaction_network(),
            ).order_by(desc(TransactionEvent.created_at)).limit(100)
        )).scalars().all()

        # ─── STEP 2: COMPUTE TRUST SCORE ───────────────────────────────────
        trust_score = self._compute_trust_score(login_events, guard_events, tx_events)

        # ─── STEP 2b: ADD PERSISTED BONUS ───────────────────────────────────
        # Bonus from step-up verifications survives across evaluations
        existing = await db.execute(
            select(SecurityState).where(SecurityState.wallet_address == w)
        )
        existing_state = existing.scalar_one_or_none()
        bonus = (existing_state.trust_bonus or 0) if existing_state else 0
        trust_score = min(100, trust_score + bonus)

        # ─── STEP 3: DETERMINE SECURITY STATUS ─────────────────────────────
        now = datetime.utcnow()
        security_status, cooldown_reason, locked_until = self._determine_status(
            trust_score, login_events, tx_events, now,
        )

        # ─── STEP 4: UPSERT SECURITY STATE ─────────────────────────────────
        state = existing_state

        if state is None:
            # Create new state record
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
            # Handle existing lock state
            if state.security_status == "locked" and state.locked_until and state.locked_until > now:
                # Still locked - keep status
                security_status = "locked"
                locked_until = state.locked_until
                cooldown_reason = state.cooldown_reason
            elif state.security_status == "locked" and state.locked_until and state.locked_until <= now:
                # Lock just expired - transition gracefully
                if security_status == "locked":
                    security_status = "step_up_required"
                    locked_until = None
                    cooldown_reason = None
            
            # Update state
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

    # ═══════════════════════════════════════════════════════════════════════════
    # STEP-UP VERIFICATION BONUS
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def complete_step_up(
        self,
        db: AsyncSession,
        wallet_address: str,
        boost: int = 20,
    ) -> dict:
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ COMPLETE STEP-UP VERIFICATION - BOOST TRUST SCORE                         ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ WHAT THIS DOES:                                                            ║
        ║ Called after user successfully re-signs with wallet (proves identity)     ║
        ║ Increases trust bonus, which persists across re-evaluations               ║
        ║                                                                           ║
        ║ WHY PERSISTED BONUS?                                                       ║
        ║ - User proved identity, should benefit immediately                       ║
        ║ - Bonus survives even if new risk events occur                           ║
        ║ - Maximum bonus capped at 40 (prevents gaming the system)                ║
        ║                                                                           ║
        ║ @param wallet_address: str - Wallet that completed step-up                ║
        ║ @param boost: int - Points to add (default 20)                            ║
        ║ @returns: dict - Updated enforcement state                                ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        w = wallet_address.lower()
        now = datetime.utcnow()

        result = await db.execute(
            select(SecurityState).where(SecurityState.wallet_address == w)
        )
        state = result.scalar_one_or_none()

        if state is None:
            # No state = clean slate
            return {
                "trust_score": 100,
                "security_status": "active",
                "locked_until": None,
                "cooldown_reason": None,
                "boosted": False,
            }

        old_score = state.trust_score
        
        # Accumulate bonus (capped at 40)
        state.trust_bonus = min(40, (state.trust_bonus or 0) + boost)
        new_score = min(100, old_score + boost)
        state.trust_score = new_score

        # Re-determine status from boosted score
        if new_score >= TRUST_ACTIVE_THRESHOLD:
            state.security_status = "active"
            state.cooldown_reason = None
        elif new_score >= TRUST_STEP_UP_THRESHOLD:
            state.security_status = "step_up_required"

        state.last_evaluated = now
        state.updated_at = now
        await db.commit()

        return {
            "trust_score": new_score,
            "security_status": state.security_status,
            "locked_until": state.locked_until.isoformat() + "Z" if state.locked_until else None,
            "cooldown_reason": state.cooldown_reason,
            "boosted": True,
            "previous_score": old_score,
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # STATE LOOKUP
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def get_security_state(
        self, db: AsyncSession, wallet_address: str,
    ) -> dict:
        """
        Get stored security state for a wallet (fast lookup).
        Also handles auto-unlock if cooldown has expired.
        """
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

    # ═══════════════════════════════════════════════════════════════════════════
    # ACTION CHECK
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def check_action_allowed(
        self, db: AsyncSession, wallet_address: str, action: str = "sensitive",
    ) -> Tuple[bool, str]:
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ CHECK IF AN ACTION IS ALLOWED FOR THIS WALLET                             ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ ACTION TYPES:                                                              ║
        ║ - login: Can user log in?                                                 ║
        ║ - transfer: Can user send ETH?                                            ║
        ║ - chat_send: Can user send messages?                                      ║
        ║ - sensitive: Can user perform sensitive actions?                          ║
        ║                                                                           ║
        ║ @returns: Tuple[bool, str] - (allowed, reason_if_not_allowed)             ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
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
                return True, "step_up_required"  # Extra confirmation needed
            return True, ""

        return True, ""

    # ═══════════════════════════════════════════════════════════════════════════
    # PRIVATE HELPERS
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _compute_trust_score(self, login_events, guard_events, tx_events) -> int:
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ COMPUTE TRUST SCORE FROM ALL RISK EVENTS                                  ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ FORMULA:                                                                   ║
        ║   score = 100                                                              ║
        ║   score -= login_penalties (max 40)                                       ║
        ║   score -= guard_penalties (max 30)                                       ║
        ║   score -= tx_penalties (max 30)                                          ║
        ║   score = max(0, score)                                                   ║
        ║                                                                           ║
        ║ RECENCY DECAY:                                                             ║
        ║ Events are weighted by how recent they are.                               ║
        ║ recency = max(0.5, 1.0 - index * 0.015)                                   ║
        ║ Most recent: 1.0, decays linearly to minimum 0.5                          ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        score = 100.0

        # ─── LOGIN Penalties (max 40) ───────────────────────────────────────
        if login_events:
            login_penalty = 0.0
            for i, e in enumerate(login_events):
                # Recency decay: older events have less impact
                recency = max(0.5, 1.0 - i * 0.015)
                severity = e.risk_score if e.risk_score else 0.5
                if e.risk_level == "high":
                    login_penalty += 10 * severity * recency
                elif e.risk_level == "medium":
                    login_penalty += 4 * severity * recency
            score -= min(40, login_penalty)

        # ─── Guard Penalties (max 30) ───────────────────────────────────────
        if guard_events:
            guard_penalty = 0.0
            for i, e in enumerate(guard_events):
                recency = max(0.5, 1.0 - i * 0.015)
                if e.risk_detected:
                    guard_penalty += 5 * recency
                if e.user_override:
                    guard_penalty += 2 * recency  # Override shows user ignored warning
            score -= min(30, guard_penalty)

        # ─── Transaction Penalties (max 30) ─────────────────────────────────
        if tx_events:
            tx_penalty = 0.0
            for i, e in enumerate(tx_events):
                recency = max(0.5, 1.0 - i * 0.015)
                severity = e.risk_score if e.risk_score else 0.5
                if e.status == "blocked":
                    tx_penalty += 12 * severity * recency
                elif e.cooldown_until is not None:
                    tx_penalty += 6 * severity * recency
            score -= min(30, tx_penalty)

        return max(0, round(score))

    def _determine_status(
        self, trust_score: int, login_events, tx_events, now: datetime,
    ) -> Tuple[str, Optional[str], Optional[datetime]]:
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ DETERMINE SECURITY STATUS FROM TRUST SCORE AND RECENT EVENTS              ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ LOGIC:                                                                     ║
        ║ 1. If score >= 80: ACTIVE                                                ║
        ║ 2. If score >= 50: STEP_UP_REQUIRED                                      ║
        ║ 3. If score < 50: Check for severe patterns                              ║
        ║    - Multiple recent high-risk logins → LOCKED                           ║
        ║    - Multiple blocked transactions → LOCKED                              ║
        ║    - Otherwise → RESTRICTED                                               ║
        ║                                                                           ║
        ║ @returns: Tuple[status, reason, locked_until]                             ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        if trust_score >= TRUST_ACTIVE_THRESHOLD:
            return "active", None, None

        if trust_score >= TRUST_STEP_UP_THRESHOLD:
            return "step_up_required", None, None

        # Below 50 - check severity
        # Only consider events in recent window for lock decision
        lock_window = now - timedelta(minutes=LOCKOUT_COOLDOWN_MINUTES * 3)
        
        recent_high_logins = sum(
            1 for e in login_events[:20]
            if e.risk_level == "high" and e.timestamp and e.timestamp > lock_window
        )
        recent_blocked_tx = sum(
            1 for e in tx_events[:20]
            if e.status == "blocked" and e.created_at and e.created_at > lock_window
        )

        if recent_high_logins >= 3 or recent_blocked_tx >= 2:
            # Hard lock - severe pattern detected
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


# ═══════════════════════════════════════════════════════════════════════════════
# INTERVIEW QUESTIONS FOR enforcement.py
# ═══════════════════════════════════════════════════════════════════════════════
"""
Q1: Why use recency decay in trust score computation?
A1: Recency decay ensures:
    - Recent events have more impact (current behavior matters more)
    - Users can recover over time (old mistakes don't haunt forever)
    - Captures changing behavior patterns
    - Minimum factor of 0.5 ensures all events still have some impact

Q2: What's the difference between RESTRICTED and LOCKED?
A2: 
    RESTRICTED:
    - Can still login and view data
    - Cannot perform sensitive actions (transfers)
    - Triggered by moderately low trust score (<50)
    
    LOCKED:
    - Cannot login at all
    - Temporary lockout with cooldown
    - Triggered by severe patterns (multiple high-risk events)

Q3: How does the step-up bonus work?
A3: When user completes step-up verification:
    - They prove identity by re-signing with wallet
    - Trust bonus accumulates (up to 40 points max)
    - Bonus persists across re-evaluations
    - Helps users recover to ACTIVE status faster
    - Rewards good security behavior

Q4: How would you prevent users from gaming the trust score?
A4: Several safeguards:
    - Bonus capped at 40 (can't max out just by step-up)
    - Recent events have more weight
    - Severe patterns trigger immediate lock regardless of score
    - Cooldown prevents rapid step-up attempts
    - Override penalties (ignoring DLP warnings hurts score)

Q5: How would you implement this in a microservices architecture?
A5: Changes needed:
    - Replace singleton with shared state (Redis)
    - Event-driven architecture (events trigger re-evaluation)
    - Cache security state with TTL
    - API endpoint for other services to check status
    - Consider event sourcing for audit trail
"""
