"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     SentinelX GuardLayer — DLP Service                        ║
║                     LLM + Regex Data Leak Prevention                          ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ PURPOSE: Prevent sensitive data leaks through dual-layer content scanning     ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ DUAL-LAYER ARCHITECTURE:                                                      ║
║ ═════════════════════════════════════════════════════════════════════════════║
║                                                                               ║
║ LAYER 1: REGEX PATTERN MATCHING (Fast, Deterministic)                        ║
║ ───────────────────────────────────────────────────────────                  ║
║ - Matches known patterns (credit cards, SSNs, API keys)                      ║
║ - Instant, no API calls needed                                               ║
║ - 100% deterministic - same input = same output                              ║
║ - Can produce false positives (e.g., "example credit card 4111...")         ║
║                                                                               ║
║ LAYER 2: LLM ANALYSIS (Deep, Contextual)                                     ║
║ ─────────────────────────────────────────────                                ║
║ - Understands context (e.g., "my SSN is" vs "SSN stands for")               ║
║ - Can detect patterns regex misses (e.g., obfuscated data)                  ║
║ - Slower, requires API call to OpenRouter/Llama                             ║
║ - May produce inconsistent results                                           ║
║                                                                               ║
║ WHY BOTH LAYERS?                                                              ║
║ - Regex is fast and cheap, catches obvious leaks                            ║
║ - LLM catches subtle leaks that regex misses                                 ║
║ - Defense in depth: if one layer misses, other might catch                  ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ AI/LLM INTEGRATION DETAILS:                                                   ║
║ ═════════════════════════════════════════════════════════════════════════════║
║                                                                               ║
║ PROVIDER: OpenRouter (https://openrouter.ai)                                 ║
║ - Single API for multiple LLM providers                                      ║
║ - Cost-effective (free tier available)                                       ║
║ - Access to Llama 3.2 3B (used for speed and cost)                          ║
║                                                                               ║
║ MODEL: meta-llama/llama-3.2-3b-instruct:free                                 ║
║ - 3 billion parameters (small but capable)                                   ║
║ - Instruction-tuned for following prompts                                    ║
║ - Free tier available on OpenRouter                                          ║
║                                                                               ║
║ WHY NOT GPT-4?                                                                ║
║ - Cost: GPT-4 is ~100x more expensive per token                             ║
║ - Latency: GPT-4 is slower                                                   ║
║ - For DLP, a smaller model is sufficient (pattern matching, not reasoning)  ║
║                                                                               ║
║ INTERVIEW QUESTION: Why use LLM for DLP instead of just regex?              ║
║ ANSWER: Regex limitations:                                                   ║
║ 1. Can't understand context ("SSN is 123-45-6789" vs "SSN format is XXX")   ║
║ 2. Can't detect obfuscated data ("my social is one two three...")          ║
║ 3. Can't adapt to new patterns without code changes                         ║
║ LLM addresses these but has trade-offs (cost, latency, consistency)         ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
import hashlib
import json
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from app.config import settings

# ───────────────────────────────────────────────────────────────────────────────
# LLM CLIENT IMPORT (with graceful fallback)
# ───────────────────────────────────────────────────────────────────────────────
"""
Attempt to import OpenAI client. If not available, system still works
with regex-only mode. This makes the application more resilient.

INTERVIEW QUESTION: Why graceful fallback instead of failing fast?
ANSWER: For a security product, availability matters. If LLM API is down,
we still want basic DLP protection via regex. This is "defense in depth"
applied to the service itself.
"""
try:
    from openai import AsyncOpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False


# ───────────────────────────────────────────────────────────────────────────────
# RISK SCORING CONSTANTS
# ───────────────────────────────────────────────────────────────────────────────
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║ RISK SCORES ARE CUMULATIVE                                                    ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ Each detected pattern adds to the total risk score.                          ║
║                                                                               ║
║ SCORE_HIGH_CRITICAL (80):                                                     ║
║ - Private keys, API keys, credit cards, SSNs                                ║
║ - Immediate block recommended                                                ║
║                                                                               ║
║ SCORE_SENSITIVE (50):                                                         ║
║ - Emails, phone numbers, Aadhaar (India ID)                                 ║
║ - Warning + confirmation recommended                                         ║
║                                                                               ║
║ SCORE_CONTEXTUAL (25):                                                        ║
║ - Urgency keywords, Ethereum addresses, IP addresses                        ║
║ - Flag for review, may be legitimate                                         ║
║                                                                               ║
║ THRESHOLD_BLOCK (70):                                                         ║
║ - Score >= 70: Block content, require explicit override                     ║
║                                                                               ║
║ THRESHOLD_WARN (40):                                                          ║
║ - Score >= 40: Warn user, show what was detected                            ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
SCORE_HIGH_CRITICAL = 80
SCORE_SENSITIVE = 50
SCORE_CONTEXTUAL = 25
THRESHOLD_BLOCK = 70
THRESHOLD_WARN = 40

# ───────────────────────────────────────────────────────────────────────────────
# FALSE POSITIVE REDUCTION
# ───────────────────────────────────────────────────────────────────────────────
"""
Pattern to detect if content is example/test data.
If this matches, risk score is reduced by up to 50%.

WHY: "My test credit card is 4111111111111111" should not trigger
the same response as an actual credit card leak.

LIMITATION: Sophisticated attackers might use this to bypass detection.
In production, you'd want more sophisticated context analysis.
"""
FALSE_POSITIVE_PATTERN = re.compile(
    r"\b(example|dummy|test data|sample|placeholder|mock|fake|lorem)\b", re.IGNORECASE
)


# ───────────────────────────────────────────────────────────────────────────────
# ESCALATION RULES - Combined Pattern Detection
# ───────────────────────────────────────────────────────────────────────────────
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║ ESCALATION RULES detect dangerous COMBINATIONS of patterns                   ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║ WHY COMBINED DETECTION?                                                       ║
║ Individual patterns might be benign, but together they're suspicious.        ║
║                                                                               ║
║ EXAMPLES:                                                                     ║
║ - Email alone: "Contact me at john@example.com" (score: 50, warning)        ║
║ - Password alone: "Password: secret123" (score: 80, block)                  ║
║ - Both together: "Email: john@example.com, Password: secret123"             ║
║   → This is MUCH more dangerous (credential dump) → +30 escalation bonus    ║
║                                                                               ║
║ RULES:                                                                        ║
║ - email_password_combo: Credentials being shared                             ║
║ - urgency_eth_transfer: Social engineering + crypto = scam                  ║
║ - wallet_large_amount: Unknown wallet + large amount = money laundering     ║
║ - aadhaar_mobile_combo: PII combination (India specific)                    ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
ESCALATION_RULES = [
    {
        "name": "email_password_combo",
        "label": "Email + Password in same message",
        "patterns": [
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",  # Email
            r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*\S+",  # Password
        ],
    },
    {
        "name": "urgency_eth_transfer",
        "label": "Urgency language + ETH transfer mention",
        "patterns": [
            r"(?i)\b(?:urgent|immediately|right now|act fast|limited time|verify now|hurry|asap)\b",  # Urgency
            r"(?i)\b(?:send|transfer)\s+\d+(?:\.\d+)?\s*(?:eth|usdt|btc)\b",  # Crypto transfer
        ],
    },
    {
        "name": "wallet_large_amount",
        "label": "New wallet address + large number",
        "patterns": [
            r"\b0x[a-fA-F0-9]{40}\b",  # Ethereum address
            r"\b\d{3,}\b",  # Number with 3+ digits
        ],
    },
    {
        "name": "aadhaar_mobile_combo",
        "label": "Aadhaar + Mobile in same message",
        "patterns": [
            r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b",  # Aadhaar (India ID)
            r"\b[6-9]\d{9}\b",  # Indian mobile
        ],
    },
]


class GuardLayer:
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ GUARDLAYER - Dual-layer content scanning for data leak prevention        ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ USAGE:                                                                     ║
    ║   guard = GuardLayer()                                                    ║
    ║   result = await guard.scan("My credit card is 4532...")                 ║
    ║   if result["is_risky"]:                                                  ║
    ║       # Block or warn user                                                ║
    ║                                                                           ║
    ║ RETURNS:                                                                   ║
    ║   - is_risky: bool - Should this content be blocked?                      ║
    ║   - severity: str - "low", "medium", "high", "critical"                   ║
    ║   - risk_score: int - Cumulative score from all matches                   ║
    ║   - categories: list - What types of sensitive data were found            ║
    ║   - regex_findings: list - Detailed breakdown of regex matches            ║
    ║   - llm_result: dict - LLM analysis (if available)                        ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """

    # ═══════════════════════════════════════════════════════════════════════════
    # CATEGORY 1: HIGH-CRITICAL PATTERNS (Auto-block recommended)
    # ═══════════════════════════════════════════════════════════════════════════
    """
    These patterns indicate HIGH SEVERITY data leaks.
    Each match contributes +80 to the risk score.

    INTERVIEW QUESTION: How did you choose these patterns?
    ANSWER: Based on:
    1. OWASP sensitive data categories
    2. Common data breach patterns
    3. Industry standards (PCI-DSS for credit cards)
    4. Actual patterns seen in real data leaks
    """
    HIGH_CRITICAL_PATTERNS = {
        # Ethereum Private Key - 64 hex chars with 0x prefix
        # DANGER: Anyone with this can drain the wallet
        "eth_private_key_0x": {
            "pattern": r"\b0x[a-fA-F0-9]{64}\b",
            "label": "Ethereum Private Key (0x format)",
        },
        # Raw Private Key - 64 hex chars without prefix
        # DANGER: Could be any blockchain private key
        "raw_hex_private_key": {
            "pattern": r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])",
            "label": "Private Key (Raw 64 hex)",
        },
        # BIP39 Seed Phrase - 12-24 words
        # DANGER: Can recover any wallet derived from this seed
        "bip39_seed_phrase": {
            "pattern": r"\b(\w+\s+){11,23}\w+\b",
            "label": "BIP39 Seed Phrase (12-24 words)",
        },
        # OpenAI API Key - starts with sk-
        # DANGER: Attacker can use your API credits
        "openai_api_key": {
            "pattern": r"\bsk-[A-Za-z0-9]{20,}\b",
            "label": "OpenAI API Key",
        },
        # AWS Access Key - starts with AKIA
        # DANGER: Full AWS account access
        "aws_access_key": {
            "pattern": r"\bAKIA[0-9A-Z]{16}\b",
            "label": "AWS Access Key",
        },
        # Google API Key - starts with AIza
        # DANGER: Access to Google Cloud services
        "google_api_key": {
            "pattern": r"\bAIza[0-9A-Za-z\-_]{35}\b",
            "label": "Google API Key",
        },
        # GitHub Token - starts with ghp_
        # DANGER: Repository access, could leak source code
        "github_token": {
            "pattern": r"\bghp_[A-Za-z0-9]{36}\b",
            "label": "GitHub Token",
        },
        # Credit Card Number - Major card formats
        # DANGER: Financial fraud
        "credit_card": {
            "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b",
            "label": "Credit Card Number",
        },
        # US Social Security Number - XXX-XX-XXXX
        # DANGER: Identity theft
        "ssn": {
            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
            "label": "Social Security Number",
        },
        # Password in Plaintext
        # DANGER: Credential exposure
        "password_plaintext": {
            "pattern": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\"']?.+[\"']?",
            "label": "Password in Plaintext",
        },
    }

    # ═══════════════════════════════════════════════════════════════════════════
    # CATEGORY 2: SENSITIVE PATTERNS (Warn + confirm)
    # ═══════════════════════════════════════════════════════════════════════════
    """
    These patterns indicate MODERATE SEVERITY data exposure.
    Each match contributes +50 to the risk score.
    """
    SENSITIVE_PATTERNS = {
        # Aadhaar Number - India's national ID (12 digits)
        # Format: XXXX XXXX XXXX (may have spaces)
        "aadhaar_number": {
            "pattern": r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b",
            "label": "Aadhaar Number (India)",
        },
        # Indian Mobile Number - 10 digits starting with 6-9
        "indian_mobile": {
            "pattern": r"\b[6-9]\d{9}\b",
            "label": "Indian Mobile Number",
        },
        # Email Address
        # Common but can be PII
        "email": {
            "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "label": "Email Address",
        },
        # Generic Secret/API Key Pattern
        # Catches "api_key = xxx" or "secret: xxx"
        "generic_secret": {
            "pattern": r"(?i)(?:api[_\-]?key|secret|token)\s*[:=]\s*[\"']?.+[\"']?",
            "label": "Secret / API Key Assignment",
        },
        # IBAN - International Bank Account Number
        "iban": {
            "pattern": r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
            "label": "IBAN Number",
        },
        # SWIFT/BIC Code - Bank identifier
        "swift_bic": {
            "pattern": r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
            "label": "SWIFT / BIC Code",
        },
        # Phone Number - US format
        "phone": {
            "pattern": r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b",
            "label": "Phone Number",
        },
        # Confidential Keywords
        # Documents marked as confidential
        "confidential_keywords": {
            "pattern": r"(?i)\b(?:confidential|top\s*secret|classified|internal\s*only|do\s*not\s*share|restricted)\b",
            "label": "Confidential Keyword",
        },
    }

    # ═══════════════════════════════════════════════════════════════════════════
    # CATEGORY 3: CONTEXTUAL PATTERNS (Scoring only, may be legitimate)
    # ═══════════════════════════════════════════════════════════════════════════
    """
    These patterns indicate CONTEXTUAL RISK.
    Each match contributes +25 to the risk score.
    May be legitimate in many contexts.
    """
    CONTEXTUAL_PATTERNS = {
        # Urgency Keywords - Common in social engineering
        "urgency_keywords": {
            "pattern": r"(?i)\b(?:urgent|immediately|right now|act fast|limited time|verify now)\b",
            "label": "Urgency Keywords",
        },
        # Manipulation Phrases - Social engineering indicators
        "manipulation_phrases": {
            "pattern": r"(?i)\b(?:trust me|don'?t tell anyone|do not tell anyone|account will be suspended)\b",
            "label": "Manipulation Phrases",
        },
        # Crypto Transfer Mention
        "crypto_transfer_mention": {
            "pattern": r"(?i)\b(?:send|transfer)\s+\d+(?:\.\d+)?\s*(?:eth|usdt|btc)\b",
            "label": "Crypto Transfer Mention",
        },
        # Ethereum Address - 40 hex chars with 0x prefix
        # Could be legitimate (receiving address) or suspicious (unknown wallet)
        "eth_address": {
            "pattern": r"\b0x[a-fA-F0-9]{40}\b",
            "label": "Ethereum Address",
        },
        # IP Address - Could be internal network info
        "ip_address": {
            "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "label": "IP Address",
        },
    }

    # ═══════════════════════════════════════════════════════════════════════════
    # LLM PROMPTS
    # ═══════════════════════════════════════════════════════════════════════════
    """
    Prompts for LLM-based analysis and redaction.
    
    INTERVIEW QUESTION: Why specific JSON format in the prompt?
    ANSWER: Structured output makes parsing reliable. We need consistent
    response format to integrate with our system. JSON allows us to
    extract specific fields (is_sensitive, categories, etc.) programmatically.
    """
    
    LLM_PROMPT = """You are a data loss prevention (DLP) security scanner. Analyze the following text for sensitive information leakage.

Check for:
1. Personally Identifiable Information (PII): names, addresses, SSN, ID numbers
2. Financial data: credit card numbers, bank accounts, transactions
3. Credentials: passwords, API keys, tokens, private keys, seed phrases
4. Confidential markers: internal documents, classified data, trade secrets
5. Health information: medical records, diagnoses, prescriptions

Text to scan:
---
{text}
---

Respond in JSON format:
{{
  "is_sensitive": true/false,
  "confidence": 0.0-1.0,
  "categories": ["category1", "category2"],
  "reasons": ["reason1", "reason2"],
  "severity": "low|medium|high|critical"
}}

Only respond with the JSON, nothing else."""

    REDACT_PROMPT = """You are a data redaction engine. Replace ALL sensitive data in the text with redaction placeholders.

Rules:
- Credit card numbers -> [REDACTED-CREDIT_CARD]
- Social Security Numbers -> [REDACTED-SSN]
- Email addresses -> [REDACTED-EMAIL]
- Phone numbers -> [REDACTED-PHONE]
- API keys / tokens -> [REDACTED-API_KEY]
- Private keys -> [REDACTED-PRIVATE_KEY]
- Passwords -> [REDACTED-PASSWORD]
- Names of people -> [REDACTED-NAME]
- Physical addresses -> [REDACTED-ADDRESS]
- Medical information -> [REDACTED-MEDICAL]
- Financial amounts / accounts -> [REDACTED-FINANCIAL]
- Any other sensitive data -> [REDACTED]

Return ONLY the redacted text, nothing else.

Text to redact:
---
{text}
---"""

    def __init__(self):
        """
        Initialize GuardLayer with LLM client if available.
        
        Uses OpenRouter API (OpenAI-compatible) for LLM access.
        Falls back to regex-only mode if LLM unavailable.
        """
        self.openai_client = None
        if HAS_OPENAI and settings.OPENROUTER_API_KEY:
            try:
                # OpenRouter uses OpenAI-compatible API
                # Base URL points to OpenRouter instead of OpenAI
                self.openai_client = AsyncOpenAI(
                    api_key=settings.OPENROUTER_API_KEY,
                    base_url="https://openrouter.ai/api/v1",
                )
            except Exception:
                # Graceful fallback - regex-only mode
                pass

    # ═══════════════════════════════════════════════════════════════════════════
    # REGEX SCANNING (Layer 1)
    # ═══════════════════════════════════════════════════════════════════════════
    
    def scan_regex(self, text: str) -> Tuple[List[Dict], int]:
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ COMPREHENSIVE REGEX SCAN WITH CUMULATIVE RISK SCORING                     ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ ALGORITHM:                                                                 ║
        ║ 1. Check for false positive indicators (example/test data)                ║
        ║ 2. Scan all HIGH_CRITICAL patterns → add +80 per match                    ║
        ║ 3. Scan all SENSITIVE patterns → add +50 per match                        ║
        ║ 4. Scan all CONTEXTUAL patterns → add +25 per match                       ║
        ║ 5. Check ESCALATION rules for pattern combinations → add +30              ║
        ║ 6. Reduce score if false positive context detected                        ║
        ║                                                                           ║
        ║ @param text: str - Content to scan                                        ║
        ║ @returns: Tuple[List[Dict], int] - (findings, cumulative_risk_score)      ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        findings = []
        risk_score = 0

        # ─── STEP 1: Check for false positive indicators ─────────────────────
        has_false_positive = bool(FALSE_POSITIVE_PATTERN.search(text))

        # ─── STEP 2: Scan HIGH_CRITICAL patterns ─────────────────────────────
        for key, config in self.HIGH_CRITICAL_PATTERNS.items():
            matches = re.findall(config["pattern"], text)
            if matches:
                findings.append({
                    "type": key,
                    "label": config["label"],
                    "severity": "critical",
                    "category": "high_critical",
                    "matches": len(matches),
                    "sample": matches[0][:20] + "..." if len(str(matches[0])) > 20 else str(matches[0]),
                    "score_contribution": SCORE_HIGH_CRITICAL,
                })
                risk_score += SCORE_HIGH_CRITICAL

        # ─── STEP 3: Scan SENSITIVE patterns ─────────────────────────────────
        for key, config in self.SENSITIVE_PATTERNS.items():
            matches = re.findall(config["pattern"], text)
            if matches:
                findings.append({
                    "type": key,
                    "label": config["label"],
                    "severity": "high",
                    "category": "sensitive",
                    "matches": len(matches),
                    "sample": matches[0][:20] + "..." if len(str(matches[0])) > 20 else str(matches[0]),
                    "score_contribution": SCORE_SENSITIVE,
                })
                risk_score += SCORE_SENSITIVE

        # ─── STEP 4: Scan CONTEXTUAL patterns ────────────────────────────────
        for key, config in self.CONTEXTUAL_PATTERNS.items():
            matches = re.findall(config["pattern"], text)
            if matches:
                findings.append({
                    "type": key,
                    "label": config["label"],
                    "severity": "medium",
                    "category": "contextual",
                    "matches": len(matches),
                    "sample": matches[0][:20] + "..." if len(str(matches[0])) > 20 else str(matches[0]),
                    "score_contribution": SCORE_CONTEXTUAL,
                })
                risk_score += SCORE_CONTEXTUAL

        # ─── STEP 5: Check ESCALATION rules ─────────────────────────────────
        for rule in ESCALATION_RULES:
            # All patterns in the rule must match for escalation
            all_matched = all(
                re.search(p, text) for p in rule["patterns"]
            )
            if all_matched:
                escalation_bonus = 30
                findings.append({
                    "type": rule["name"],
                    "label": rule["label"],
                    "severity": "critical",
                    "category": "escalation",
                    "matches": 1,
                    "sample": "Combined pattern match",
                    "score_contribution": escalation_bonus,
                })
                risk_score += escalation_bonus

        # ─── STEP 6: False positive mitigation ──────────────────────────────
        if has_false_positive and risk_score > 0:
            reduction = min(risk_score // 2, 40)  # Reduce by up to half, max 40
            risk_score -= reduction
            if reduction > 0:
                findings.append({
                    "type": "false_positive_reduction",
                    "label": "Test/example context detected — risk reduced",
                    "severity": "info",
                    "category": "mitigation",
                    "matches": 0,
                    "sample": "",
                    "score_contribution": -reduction,
                })

        return findings, risk_score

    # ═══════════════════════════════════════════════════════════════════════════
    # LLM SCANNING (Layer 2)
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def scan_llm(self, text: str) -> Optional[Dict]:
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ LLM-BASED DEEP ANALYSIS (Second Layer)                                    ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ WHAT LLM PROVIDES THAT REGEX CAN'T:                                        ║
        ║ - Context understanding ("my SSN is" vs "SSN format is")                  ║
        ║ - Obfuscation detection ("one two three four five" = 12345)              ║
        ║ - Semantic analysis (is this actually sensitive?)                         ║
        ║                                                                           ║
        ║ TRADE-OFFS:                                                                ║
        ║ - Latency: ~1-3 seconds for API call                                      ║
        ║ - Cost: ~$0.0001 per request (with free tier)                             ║
        ║ - Consistency: Same input may produce slightly different output           ║
        ║                                                                           ║
        ║ @param text: str - Content to analyze (limited to 2000 chars)             ║
        ║ @returns: Optional[Dict] - LLM analysis result or None if unavailable     ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        if not self.openai_client:
            return {
                "is_sensitive": False,
                "confidence": 0.0,
                "categories": [],
                "reasons": ["LLM not available — regex-only mode"],
                "severity": "low",
                "llm_available": False,
            }

        try:
            # Call OpenRouter API (OpenAI-compatible)
            # Using Llama 3.2 3B for speed and cost efficiency
            response = await self.openai_client.chat.completions.create(
                model="meta-llama/llama-3.2-3b-instruct:free",
                messages=[
                    {"role": "system", "content": "You are a data loss prevention security scanner. Respond only with valid JSON."},
                    {"role": "user", "content": self.LLM_PROMPT.format(text=text[:2000])},  # Limit text length
                ],
                temperature=0.1,  # Low temperature for consistent outputs
                max_tokens=500,   # Response doesn't need many tokens
            )
            
            result_text = response.choices[0].message.content.strip()
            
            # Strip markdown code fences if LLM wraps response
            if result_text.startswith("```"):
                result_text = re.sub(r"^```(?:json)?\s*", "", result_text)
                result_text = re.sub(r"\s*```$", "", result_text)
            
            result = json.loads(result_text)
            result["llm_available"] = True
            return result
            
        except json.JSONDecodeError:
            # LLM returned invalid JSON
            return {
                "is_sensitive": False,
                "confidence": 0.0,
                "categories": [],
                "reasons": ["LLM returned invalid JSON — regex-only mode"],
                "severity": "low",
                "llm_available": False,
            }
        except Exception as e:
            # API error, rate limit, etc.
            return {
                "is_sensitive": False,
                "confidence": 0.0,
                "categories": [],
                "reasons": [f"LLM scan error: {str(e)}"],
                "severity": "low",
                "llm_available": False,
            }

    # ═══════════════════════════════════════════════════════════════════════════
    # MAIN SCAN METHOD
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def scan(self, text: str, use_llm: bool = True) -> Dict:
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ FULL DUAL-LAYER SCAN                                                      ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ FLOW:                                                                      ║
        ║ 1. Layer 1: Regex scan (always runs, instant)                             ║
        ║ 2. Layer 2: LLM scan (optional, runs if text > 50 chars and use_llm=True)║
        ║ 3. Merge results from both layers                                         ║
        ║ 4. Generate content hash and event hash for audit trail                   ║
        ║                                                                           ║
        ║ @param text: str - Content to scan                                        ║
        ║ @param use_llm: bool - Whether to use LLM analysis (default: True)        ║
        ║ @returns: Dict - Complete scan results                                    ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        # ─── LAYER 1: REGEX SCAN ─────────────────────────────────────────────
        regex_findings, regex_risk_score = self.scan_regex(text)

        # Determine severity from cumulative score
        if regex_risk_score >= THRESHOLD_BLOCK:
            max_severity = "critical"
        elif regex_risk_score >= THRESHOLD_WARN:
            max_severity = "high"
        elif regex_risk_score > 0:
            max_severity = "medium"
        else:
            max_severity = "low"

        is_risky = regex_risk_score >= THRESHOLD_WARN
        categories = list(set(f["type"] for f in regex_findings if f["category"] != "mitigation"))

        # ─── LAYER 2: LLM SCAN ──────────────────────────────────────────────
        llm_result = None
        if use_llm and len(text) > 50:  # Only use LLM for substantial text
            llm_result = await self.scan_llm(text)

        # Merge LLM results if available
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        if llm_result and llm_result.get("is_sensitive"):
            is_risky = True
            categories.extend(llm_result.get("categories", []))
            llm_severity = llm_result.get("severity", "low")
            if severity_order.get(llm_severity, 0) > severity_order.get(max_severity, 0):
                max_severity = llm_severity

        # ─── GENERATE HASHES ────────────────────────────────────────────────
        # Content hash: SHA-256 of content (for storage, never store raw content)
        content_hash = hashlib.sha256(text.encode()).hexdigest()

        # Event hash: For audit trail and Merkle tree inclusion
        event_data = json.dumps({
            "content_hash": content_hash,
            "timestamp": datetime.utcnow().isoformat(),
            "is_risky": is_risky,
            "categories": list(set(categories)),
        }, sort_keys=True)
        event_hash = hashlib.sha256(event_data.encode()).hexdigest()

        return {
            "is_risky": is_risky,
            "severity": max_severity,
            "risk_score": regex_risk_score,
            "threshold_block": THRESHOLD_BLOCK,
            "threshold_warn": THRESHOLD_WARN,
            "categories": list(set(categories)),
            "regex_findings": regex_findings,
            "llm_result": llm_result,
            "content_hash": content_hash,
            "event_hash": event_hash,
            "scanned_at": datetime.utcnow().isoformat(),
            "scan_type": "regex+llm" if (llm_result and llm_result.get("llm_available")) else "regex",
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # REDACTION METHOD
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def redact(self, text: str) -> Dict:
        """
        ╔═══════════════════════════════════════════════════════════════════════════╗
        ║ REDACT SENSITIVE DATA FROM TEXT                                           ║
        ╠═══════════════════════════════════════════════════════════════════════════╣
        ║                                                                           ║
        ║ PRIORITY: REGEX FIRST, LLM FALLBACK                                       ║
        ║                                                                           ║
        ║ WHY REGEX FIRST?                                                           ║
        ║ - Deterministic: Same input always produces same output                   ║
        ║ - Preserves surrounding text exactly                                      ║
        ║ - Instant, no API call needed                                             ║
        ║                                                                           ║
        ║ WHY LLM FALLBACK?                                                          ║
        ║ - Regex might miss contextually sensitive data                            ║
        ║ - LLM can understand and redact obfuscated data                           ║
        ║ - But LLM might change non-sensitive parts of text                        ║
        ║                                                                           ║
        ║ @param text: str - Content to redact                                      ║
        ║ @returns: Dict - {original_hash, redacted_text, method}                   ║
        ╚═══════════════════════════════════════════════════════════════════════════╝
        """
        original_hash = hashlib.sha256(text.encode()).hexdigest()

        # ─── PRIMARY: REGEX REDACTION ────────────────────────────────────────
        redacted_text = text
        
        # Redact high-critical patterns
        for key, config in self.HIGH_CRITICAL_PATTERNS.items():
            label = key.upper()
            redacted_text = re.sub(config["pattern"], f"[REDACTED-{label}]", redacted_text)
        
        # Redact sensitive patterns
        for key, config in self.SENSITIVE_PATTERNS.items():
            label = key.upper()
            redacted_text = re.sub(config["pattern"], f"[REDACTED-{label}]", redacted_text)

        # If regex caught something, use it
        if redacted_text != text:
            return {
                "original_hash": original_hash,
                "redacted_text": redacted_text,
                "method": "regex",
            }

        # ─── FALLBACK: LLM REDACTION ─────────────────────────────────────────
        if self.openai_client:
            try:
                response = await self.openai_client.chat.completions.create(
                    model="meta-llama/llama-3.2-3b-instruct:free",
                    messages=[
                        {"role": "system", "content": "You are a data redaction engine. Return only the redacted text. Keep all non-sensitive words intact."},
                        {"role": "user", "content": self.REDACT_PROMPT.format(text=text[:2000])},
                    ],
                    temperature=0.0,  # Zero temperature for deterministic output
                    max_tokens=1000,
                )
                llm_redacted = response.choices[0].message.content.strip()
                
                # Sanity check: LLM should preserve most of the text
                if llm_redacted and len(llm_redacted) >= len(text) * 0.3 and llm_redacted.lower() != "[redacted]":
                    return {
                        "original_hash": original_hash,
                        "redacted_text": llm_redacted,
                        "method": "llm",
                    }
            except Exception:
                pass

        # Nothing to redact
        return {
            "original_hash": original_hash,
            "redacted_text": redacted_text,
            "method": "regex",
        }


# ═══════════════════════════════════════════════════════════════════════════════
# INTERVIEW QUESTIONS FOR guard_layer.py
# ═══════════════════════════════════════════════════════════════════════════════
"""
Q1: How do you prevent false positives in DLP?
A1: Several strategies implemented:
    1. False positive pattern detection (example, test, dummy keywords)
    2. Graduated scoring (not binary, gives score levels)
    3. LLM context understanding (distinguishes "SSN is 123" from "SSN format")
    4. User override option (let users make final decision)
    5. Category-based thresholds (different actions for different severities)

Q2: Why store content_hash instead of the actual content?
A2: Security and privacy:
    - If database is breached, sensitive data isn't exposed
    - Compliance with data minimization principles
    - Hash proves what was scanned without storing the evidence
    - Can still verify/audit without storing raw content

Q3: How would you scale this for high-volume applications?
A3: Several approaches:
    1. Caching: Cache results for identical content hashes
    2. Async processing: Queue scans, process in background
    3. Batch LLM calls: Group multiple texts in one API call
    4. Tiered scanning: Quick regex first, LLM only for flagged content
    5. Local LLM: Deploy smaller model locally to avoid API latency

Q4: What patterns would you add for a banking application?
A4: Additional patterns:
    - Account numbers (specific to bank format)
    - Routing numbers
    - Transaction IDs
    - PINs (4-6 digit sequences near "PIN" keyword)
    - Balance information
    - Loan amounts and account details
    - KYC document numbers

Q5: How does the escalation system work?
A5: Escalation rules detect COMBINATIONS of patterns:
    - Email + Password = Credential dump (very dangerous)
    - Urgency + Crypto transfer = Likely scam
    - New wallet + Large amount = Possible money laundering
    Each combination adds +30 bonus to risk score because the COMBINATION
    is more dangerous than individual patterns.
"""