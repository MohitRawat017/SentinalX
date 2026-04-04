"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     SentinelX AI Risk Engine                                  ║
║                     Weighted History-Aware Login Risk Scoring                 ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ PURPOSE: Analyze login attempts and compute risk scores using behavioral      ║
║          analysis and weighted risk factors.                                  ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ AI/ML INTEGRATION APPROACH:                                                   ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ This is a RULE-BASED AI system (not neural networks). Why?                    ║
║                                                                               ║
║ 1. EXPLAINABILITY: Every risk factor can be explained to users              ║
║    "Your login was flagged because: New device + New country"                ║
║                                                                               ║
║ 2. AUDITABILITY: Financial/security systems require clear reasoning          ║
║    Neural networks are "black boxes" - can't explain decisions               ║
║                                                                               ║
║ 3. TUNABILITY: Weights can be adjusted without retraining                    ║
║    No need for labeled training data                                         ║
║                                                                               ║
║ 4. REAL-TIME: No inference latency from model loading                        ║
║    Instant scoring for every login attempt                                   ║
║                                                                               ║
║ ALGORITHM: Weighted Sum of Risk Factors                                      ║
║ ─────────────────────────────────────                                        ║
║ risk_score = (device_weight × device_factor +                                ║
║               country_weight × country_factor +                              ║
║               rapid_weight × rapid_factor +                                  ║
║               time_weight × time_factor) / MAX_RAW_SCORE                     ║
║                                                                               ║
║ Each factor is GRADUATED (0.0 to 1.0), not binary:                           ║
║ - Binary: "New device? Yes/No" → 1 or 0                                      ║
║ - Graduated: "New device? User has 5 known devices" → 0.4                    ║
║                                                                               ║
║ INTERVIEW QUESTION: Why not use machine learning for risk scoring?           ║
║ ANSWER: ML requires:                                                         ║
║ 1. Large labeled dataset (legitimate vs fraudulent logins)                   ║
║ 2. Training infrastructure                                                   ║
║ 3. Cannot explain decisions (GDPR "right to explanation")                    ║
║ 4. Model drift - needs retraining over time                                  ║
║ Rule-based systems are preferred for:                                        ║
║ - Financial applications (audit trails)                                      ║
║ - Security systems (explainability)                                          ║
║ - Startup MVPs (no training data needed)                                     ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import LoginEvent


# ───────────────────────────────────────────────────────────────────────────────
# RISK WEIGHTS CONFIGURATION
# ───────────────────────────────────────────────────────────────────────────────
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║ WEIGHTS DETERMINE THE IMPORTANCE OF EACH RISK FACTOR                          ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ HIGHER WEIGHT = MORE IMPACT ON FINAL SCORE                                    ║
║                                                                               ║
║ WEIGHT_NEW_DEVICE (0.4):                                                      ║
║ - Moderate impact - could be legitimate new phone/laptop                     ║
║                                                                               ║
║ WEIGHT_NEW_COUNTRY (0.4):                                                     ║
║ - Moderate impact - user might be traveling                                  ║
║                                                                               ║
║ WEIGHT_RAPID_ATTEMPTS (0.6):                                                  ║
║ - HIGH impact - strong signal of brute force attack                          ║
║                                                                               ║
║ WEIGHT_ABNORMAL_TIME (0.2):                                                   ║
║ - Low impact - user might be working late/early                              ║
║                                                                               ║
║ HOW TO TUNE:                                                                  ║
║ Analyze false positive/negative rates and adjust.                            ║
║ For stricter security: increase all weights                                   ║
║ For less friction: decrease weights                                           ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

WEIGHT_NEW_DEVICE = 0.4      # New device/browser fingerprint
WEIGHT_NEW_COUNTRY = 0.4     # Login from new geographic location
WEIGHT_RAPID_ATTEMPTS = 0.6  # Multiple logins in short time window (brute force)
WEIGHT_ABNORMAL_TIME = 0.2   # Login at unusual hours (3 AM for example)

# Maximum possible raw score (sum of all weights)
# Used to normalize the final score to 0-1 range
MAX_RAW_SCORE = (WEIGHT_NEW_DEVICE + WEIGHT_NEW_COUNTRY +
                 WEIGHT_RAPID_ATTEMPTS + WEIGHT_ABNORMAL_TIME)  # = 1.6

# ───────────────────────────────────────────────────────────────────────────────
# RISK THRESHOLDS
# ───────────────────────────────────────────────────────────────────────────────
"""
Risk Level Thresholds (normalized 0-1 scale):

THRESHOLD_LOW (0.4):
- Below this = LOW risk
- Action: Allow login with no friction

THRESHOLD_HIGH (0.7):
- Between LOW and HIGH = MEDIUM risk
- Action: Require step-up verification (wallet re-sign)
- Above HIGH = HIGH risk
- Action: Block login or require additional verification
"""
THRESHOLD_LOW = 0.4
THRESHOLD_HIGH = 0.7

# ───────────────────────────────────────────────────────────────────────────────
# RAPID ATTEMPT DETECTION PARAMETERS
# ───────────────────────────────────────────────────────────────────────────────
"""
RAPID_WINDOW_MINUTES: Time window to count rapid attempts
RAPID_COUNT_THRESHOLD: Number of logins within window to trigger factor

If 3+ logins within 10 minutes, the rapid_attempts factor increases.
This detects brute force attacks and credential stuffing.
"""
RAPID_WINDOW_MINUTES = 10
RAPID_COUNT_THRESHOLD = 3

# ───────────────────────────────────────────────────────────────────────────────
# NORMAL HOURS DEFINITION
# ───────────────────────────────────────────────────────────────────────────────
"""
Hours considered "normal" for login (in UTC).
Logins outside this range increase abnormal_time factor.

This is a simplified approach. In production, you would:
1. Track each user's typical login hours
2. Use their timezone
3. Allow for flexible work hours
"""
NORMAL_HOUR_START = 6   # 6 AM UTC
NORMAL_HOUR_END = 22    # 10 PM UTC


class RiskEngine:
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ RISK ENGINE - History-aware weighted login risk scoring                   ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║ SINGLETON PATTERN: Only one instance exists throughout the application    ║
    ║                                                                           ║
    ║ WHY SINGLETON?                                                             ║
    ║ - Shared state not needed (stateless computation)                         ║
    ║ - Consistent scoring across all requests                                  ║
    ║ - Easy to access from anywhere: RiskEngine.get_instance()                 ║
    ║                                                                           ║
    ║ INTERVIEW QUESTION: Is singleton pattern good for testing?                ║
    ║ ANSWER: Singletons can make testing harder because state persists.        ║
    ║ Better approach: Use dependency injection. Pass RiskEngine instance       ║
    ║ to functions that need it. This allows mocking in tests.                  ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """

    _instance = None

    @classmethod
    def get_instance(cls):
        """
        Get the singleton instance of RiskEngine.
        
        Creates instance on first call, returns existing instance on subsequent calls.
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ═══════════════════════════════════════════════════════════════════════════
    # CORE SCORING METHOD
    # ═══════════════════════════════════════════════════════════════════════════
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
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ COMPUTE RISK SCORE FOR LOGIN ATTEMPT                                      ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ ALGORITHM OVERVIEW:                                                        ║
        ║ 1. Fetch user's login history from database                               ║
        ║ 2. Compute each risk factor (0.0 to 1.0)                                  ║
        ║ 3. Apply weights to each factor                                           ║
        ║ 4. Normalize to 0-1 scale                                                 ║
        ║ 5. Determine risk level (low/medium/high)                                 ║
        ║ 6. Generate explanation for the user                                      ║
        ║                                                                           ║
        ║ ═════════════════════════════════════════════════════════════════════════║
        ║ PARAMETERS:                                                                ║
        ║ ═════════════════════════════════════════════════════════════════════════║
        ║ @param db: AsyncSession - Database connection for fetching history        ║
        ║ @param wallet_address: str - User's wallet (0x...)                       ║
        ║ @param ip_address: str - Client IP for geo/location analysis             ║
        ║ @param user_agent: str - Browser fingerprint for device detection        ║
        ║ @param geo_country: Optional[str] - Country from IP geolocation          ║
        ║ @param current_hour: Optional[int] - Hour of login (0-23) for time check ║
        ║                                                                           ║
        ║ @returns: Tuple[float, str, Dict]                                         ║
        ║   - risk_score: float (0.0 to 1.0)                                        ║
        ║   - risk_level: str ("low", "medium", "high")                            ║
        ║   - explanation: Dict with detailed factor breakdown                      ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        # Normalize wallet address to lowercase for consistent lookups
        wallet = wallet_address.lower()
        
        # Use current hour if not provided
        if current_hour is None:
            current_hour = datetime.utcnow().hour

        # ─── STEP 1: FETCH LOGIN HISTORY ─────────────────────────────────────
        # Get recent logins for this wallet to compare against
        history = await self._get_history(db, wallet)

        # ─── STEP 2: COMPUTE GRADUATED FACTORS ───────────────────────────────
        # Each factor returns 0.0 to 1.0 (not binary!)
        
        # Check if this is a new/unknown device
        new_device = self._check_new_device(user_agent, history)
        
        # Check if this is a new geographic location
        new_country = self._check_new_country(geo_country, history)
        
        # Check for rapid successive login attempts (brute force detection)
        rapid_attempts = self._check_rapid_attempts(history)
        
        # Check if login time is unusual
        abnormal_time = self._check_abnormal_time(current_hour)

        # ─── STEP 3: APPLY WEIGHTS ───────────────────────────────────────────
        # Weighted sum of all factors
        raw_score = (
            new_device * WEIGHT_NEW_DEVICE +
            new_country * WEIGHT_NEW_COUNTRY +
            rapid_attempts * WEIGHT_RAPID_ATTEMPTS +
            abnormal_time * WEIGHT_ABNORMAL_TIME
        )
        
        # ─── STEP 4: NORMALIZE TO 0-1 ────────────────────────────────────────
        # Divide by max possible score to get 0-1 range
        risk_score = round(min(raw_score / MAX_RAW_SCORE, 1.0), 4)

        # ─── STEP 5: DETERMINE RISK LEVEL ────────────────────────────────────
        if risk_score < THRESHOLD_LOW:
            risk_level = "low"
        elif risk_score < THRESHOLD_HIGH:
            risk_level = "medium"
        else:
            risk_level = "high"

        # ─── STEP 6: BUILD EXPLANATION ───────────────────────────────────────
        # Create detailed breakdown for audit and user communication
        features = {
            "new_device": new_device,
            "new_country": new_country,
            "rapid_attempts": rapid_attempts,
            "abnormal_time": abnormal_time,
        }

        explanation = self._explain(features, risk_score, risk_level)

        return risk_score, risk_level, explanation

    # ═══════════════════════════════════════════════════════════════════════════
    # RISK FACTOR COMPUTATION METHODS
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _check_new_device(self, user_agent: str, history: List[LoginEvent]) -> float:
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ CHECK IF THIS IS A NEW/UNKNOWN DEVICE                                     ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ GRADUATED SCORING:                                                         ║
        ║ - Return 0.0 if device is known                                           ║
        ║ - Return 0.4 if user has 5+ known devices (they're a "device hoarder")   ║
        ║ - Return 0.6 if user has 3-4 known devices                               ║
        ║ - Return 1.0 if this is a truly new device for this user                 ║
        ║                                                                           ║
        ║ WHY GRADUATED?                                                             ║
        ║ Users with many devices are more likely to legitimately use a new one.   ║
        ║ Power users have phones, tablets, laptops, work computers, etc.          ║
        ║ A new device for them is less suspicious than for someone with 1 device.║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        # No user agent = can't determine device
        if not user_agent or not history:
            return 1.0  # Maximum suspicion if we can't verify
        
        # Hash the user agent for comparison
        # MD5 is fine here - not for security, just for consistent fingerprinting
        ua_hash = hashlib.md5(user_agent.encode()).hexdigest()
        
        # Build set of known device hashes from login history
        known_devices = set()
        for event in history:
            if event.user_agent:
                known_devices.add(hashlib.md5(event.user_agent.encode()).hexdigest())
        
        # Device is known - no risk
        if ua_hash in known_devices:
            return 0.0
        
        # New device - factor in user's device diversity
        if len(known_devices) >= 5:
            return 0.4  # User has many devices, new one is less suspicious
        elif len(known_devices) >= 3:
            return 0.6  # Moderate suspicion
        return 1.0  # High suspicion - first new device for this user

    def _check_new_country(self, geo_country: Optional[str], history: List[LoginEvent]) -> float:
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ CHECK IF THIS IS A NEW GEOGRAPHIC LOCATION                                ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ GRADUATED SCORING:                                                         ║
        ║ - Return 0.0 if country is known                                          ║
        ║ - Return 0.5 if user has logged in from 5+ countries (frequent traveler) ║
        ║ - Return 1.0 if this is a new country for this user                       ║
        ║                                                                           ║
        ║ WHY GRADUATED?                                                             ║
        ║ Frequent travelers legitimately log in from new countries often.          ║
        ║ Digital nomads, business travelers, VPN users have diverse locations.    ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        # No geo data available - can't determine
        if not geo_country:
            return 0.0  # Don't penalize if we can't determine location
        
        # First login - moderate risk (can't compare to history)
        if not history:
            return 0.5
        
        # Build set of known countries from history
        known_countries = {e.geo_country for e in history if e.geo_country}
        
        # Country is known - no risk
        if geo_country in known_countries:
            return 0.0
        
        # New country - factor in travel diversity
        if len(known_countries) >= 5:
            return 0.5  # User travels a lot, new country is less suspicious
        return 1.0  # New country is suspicious

    def _check_rapid_attempts(self, history: List[LoginEvent]) -> float:
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ CHECK FOR RAPID SUCCESSIVE LOGIN ATTEMPTS (BRUTE FORCE DETECTION)         ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ WHAT THIS DETECTS:                                                         ║
        ║ - Brute force attacks (trying many passwords quickly)                     ║
        ║ - Credential stuffing (using leaked credentials from other sites)         ║
        ║ - Automated bots hitting the login endpoint                               ║
        ║                                                                           ║
        ║ GRADUATED SCORING:                                                         ║
        ║ - 0-1 recent logins: 0.0 (normal)                                         ║
        ║ - 2 recent logins: 0.3 (slightly elevated)                                ║
        ║ - 3 recent logins: 0.6 (suspicious)                                       ║
        ║ - 4 recent logins: 0.8 (very suspicious)                                  ║
        ║ - 5+ recent logins: 1.0 (almost certainly attack)                         ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        if not history:
            return 0.0  # No history = no rapid attempts
        
        # Count logins within the rapid detection window
        cutoff = datetime.utcnow() - timedelta(minutes=RAPID_WINDOW_MINUTES)
        recent_count = sum(1 for e in history if e.timestamp and e.timestamp >= cutoff)
        
        # Graduated scoring based on count
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
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ CHECK IF LOGIN TIME IS UNUSUAL                                            ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ NORMAL HOURS: 6 AM to 10 PM UTC                                          ║
        ║ ABNORMAL HOURS: 10 PM to 6 AM UTC                                        ║
        ║                                                                           ║
        ║ GRADUATED SCORING:                                                         ║
        ║ - Within normal hours: 0.0                                                ║
        ║ - 1-2 hours outside: 0.4 (slightly unusual)                              ║
        ║ - 2-4 hours outside: 0.7 (moderately unusual)                            ║
        ║ - 4+ hours outside: 1.0 (very unusual)                                   ║
        ║                                                                           ║
        ║ LIMITATION: This doesn't account for:                                     ║
        ║ - User's actual timezone                                                  ║
        ║ - Night shift workers                                                     ║
        ║ - Individual patterns                                                     ║
        ║                                                                           ║
        ║ IMPROVEMENT: Track each user's typical login times and compare           ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        # Within normal hours - no risk
        if NORMAL_HOUR_START <= current_hour <= NORMAL_HOUR_END:
            return 0.0
        
        # Calculate how far outside normal hours
        if current_hour < NORMAL_HOUR_START:
            distance = NORMAL_HOUR_START - current_hour
        else:
            distance = current_hour - NORMAL_HOUR_END
        
        # Graduated scoring based on distance from normal hours
        if distance <= 2:
            return 0.4
        elif distance <= 4:
            return 0.7
        return 1.0

    # ═══════════════════════════════════════════════════════════════════════════
    # HELPER METHODS
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def _get_history(self, db: AsyncSession, wallet: str, limit: int = 50) -> List[LoginEvent]:
        """
        Fetch recent login history for a wallet.
        
        Used for comparing current login against historical patterns.
        Limited to 50 most recent events for performance.
        """
        result = await db.execute(
            select(LoginEvent)
            .where(LoginEvent.wallet_address == wallet)
            .order_by(desc(LoginEvent.timestamp))
            .limit(limit)
        )
        return list(result.scalars().all())

    def _explain(self, features: Dict[str, float], risk_score: float, risk_level: str) -> Dict:
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ GENERATE HUMAN-READABLE EXPLANATION OF RISK SCORE                         ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ EXPLAINABILITY IS CRITICAL FOR:                                           ║
        ║ 1. User trust - "Why was my login flagged?"                               ║
        ║ 2. Security audits - "What factors contributed to this score?"            ║
        ║ 3. Regulatory compliance - GDPR "right to explanation"                    ║
        ║ 4. Debugging - "Why is this user getting high risk scores?"               ║
        ║                                                                           ║
        ║ RETURNS:                                                                   ║
        ║ - risk_score: The computed score                                          ║
        ║ - risk_level: low/medium/high                                             ║
        ║ - action: What should happen (allow, step-up, block)                      ║
        ║ - factors: Detailed breakdown of each factor                              ║
        ║ - model: Which algorithm was used                                         ║
        ║ - formula: The exact formula (for documentation)                          ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        # Human-readable labels for each factor
        labels = {
            "new_device": "New device / browser",
            "new_country": "New geographic location",
            "rapid_attempts": "Rapid login attempts",
            "abnormal_time": "Login at unusual hour",
        }
        
        # Map feature names to their weights
        weights = {
            "new_device": WEIGHT_NEW_DEVICE,
            "new_country": WEIGHT_NEW_COUNTRY,
            "rapid_attempts": WEIGHT_RAPID_ATTEMPTS,
            "abnormal_time": WEIGHT_ABNORMAL_TIME,
        }

        # Build detailed factor breakdown
        top_factors = []
        for feat, value in features.items():
            # Calculate this factor's contribution to final score
            contribution = round(value * weights[feat] / MAX_RAW_SCORE, 4)
            top_factors.append({
                "feature": feat,
                "label": labels[feat],
                "triggered": value >= 0.5,  # Is this factor actually triggered?
                "weight": weights[feat],
                "contribution": contribution,  # How much did this add to the score?
                "value": value,  # Raw factor value (0.0 to 1.0)
            })

        # Sort by contribution (highest first)
        top_factors.sort(key=lambda f: f["contribution"], reverse=True)

        # Map risk level to recommended action
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


# ═══════════════════════════════════════════════════════════════════════════════
# INTERVIEW QUESTIONS FOR risk_engine.py
# ═══════════════════════════════════════════════════════════════════════════════
"""
Q1: Why use graduated scoring instead of binary (triggered/not triggered)?
A1: Graduated scoring provides:
    - More nuanced risk assessment (not just 0 or 1)
    - Better user experience (reduces false positives)
    - Context-aware (considers user's history)
    Example: A new device for a user with 5 devices is less suspicious than
    for a user with 1 device.

Q2: How would you improve this risk engine with ML?
A2: Several approaches:
    1. Anomaly detection: Train on normal login patterns, flag deviations
    2. Supervised learning: If you have labeled data (legitimate vs fraud)
    3. Hybrid: Use ML for scoring, keep rules for explainability
    Key consideration: Maintain explainability for compliance.

Q3: What are the limitations of this approach?
A3: Current limitations:
    - Time zone: Uses UTC, doesn't account for user's actual timezone
    - VPN detection: Can't detect if user is behind VPN
    - Device fingerprinting: User agent can be spoofed
    - No behavioral biometrics: Typing speed, mouse patterns
    Improvements: Integrate with device fingerprinting services,
    add timezone detection, use ML for anomaly detection.

Q4: How would you handle the case where a user is actually traveling?
A4: Several strategies:
    - Trust score: Frequent travelers build up trust
    - Step-up verification: Ask for additional confirmation
    - Location pre-registration: Let users notify of travel
    - Behavioral analysis: If login is from "travel pattern" (hotel IP),
      treat differently than sudden login from high-risk country

Q5: What's the formula for the final risk score?
A5: risk_score = min(
        (device_factor × 0.4 + 
         country_factor × 0.4 + 
         rapid_factor × 0.6 + 
         time_factor × 0.2) / 1.6,
        1.0
    )
    
    The division by 1.6 (MAX_RAW_SCORE) normalizes to 0-1.
    min() ensures we never exceed 1.0.
"""