"""
SentinelX GuardLayer — LLM + Regex Data Leak Prevention
Dual-layer scanning: comprehensive regex patterns first, then LLM enhancement.
Regex patterns sourced from pattern.md specification.
"""
import hashlib
import json
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from app.config import settings

# Attempt to import OpenAI — graceful fallback if not available
try:
    from openai import AsyncOpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False


# ─── Risk Scoring Constants (from pattern.md) ────────────────────────
SCORE_HIGH_CRITICAL = 80
SCORE_SENSITIVE = 50
SCORE_CONTEXTUAL = 25
THRESHOLD_BLOCK = 70
THRESHOLD_WARN = 40

# False positive keywords — reduce risk score if present
FALSE_POSITIVE_PATTERN = re.compile(
    r"\b(example|dummy|test data|sample|placeholder|mock|fake|lorem)\b", re.IGNORECASE
)

# ─── Combined Escalation Patterns ────────────────────────────────────
# These detect dangerous combinations in a single message
ESCALATION_RULES = [
    {
        "name": "email_password_combo",
        "label": "Email + Password in same message",
        "patterns": [
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*\S+",
        ],
    },
    {
        "name": "urgency_eth_transfer",
        "label": "Urgency language + ETH transfer mention",
        "patterns": [
            r"(?i)\b(?:urgent|immediately|right now|act fast|limited time|verify now|hurry|asap)\b",
            r"(?i)\b(?:send|transfer)\s+\d+(?:\.\d+)?\s*(?:eth|usdt|btc)\b",
        ],
    },
    {
        "name": "wallet_large_amount",
        "label": "New wallet address + large number",
        "patterns": [
            r"\b0x[a-fA-F0-9]{40}\b",
            r"\b\d{3,}\b",
        ],
    },
    {
        "name": "aadhaar_mobile_combo",
        "label": "Aadhaar + Mobile in same message",
        "patterns": [
            r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b",
            r"\b[6-9]\d{9}\b",
        ],
    },
]


class GuardLayer:
    """Dual-layer content scanning for data leak prevention"""

    # ─── Category 1: HIGH-CRITICAL (auto block recommended) ──────────
    # Each match contributes +80 risk
    HIGH_CRITICAL_PATTERNS = {
        "eth_private_key_0x": {
            "pattern": r"\b0x[a-fA-F0-9]{64}\b",
            "label": "Ethereum Private Key (0x format)",
        },
        "raw_hex_private_key": {
            "pattern": r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])",
            "label": "Private Key (Raw 64 hex)",
        },
        "bip39_seed_phrase": {
            "pattern": r"\b(\w+\s+){11,23}\w+\b",
            "label": "BIP39 Seed Phrase (12-24 words)",
        },
        "openai_api_key": {
            "pattern": r"\bsk-[A-Za-z0-9]{20,}\b",
            "label": "OpenAI API Key",
        },
        "aws_access_key": {
            "pattern": r"\bAKIA[0-9A-Z]{16}\b",
            "label": "AWS Access Key",
        },
        "google_api_key": {
            "pattern": r"\bAIza[0-9A-Za-z\-_]{35}\b",
            "label": "Google API Key",
        },
        "github_token": {
            "pattern": r"\bghp_[A-Za-z0-9]{36}\b",
            "label": "GitHub Token",
        },
        "credit_card": {
            "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b",
            "label": "Credit Card Number",
        },
        "ssn": {
            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
            "label": "Social Security Number",
        },
        "password_plaintext": {
            "pattern": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\"']?.+[\"']?",
            "label": "Password in Plaintext",
        },
    }

    # ─── Category 2: SENSITIVE (warn + confirm) ──────────────────────
    # Each match contributes +50 risk
    SENSITIVE_PATTERNS = {
        "aadhaar_number": {
            "pattern": r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b",
            "label": "Aadhaar Number (India)",
        },
        "indian_mobile": {
            "pattern": r"\b[6-9]\d{9}\b",
            "label": "Indian Mobile Number",
        },
        "email": {
            "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "label": "Email Address",
        },
        "generic_secret": {
            "pattern": r"(?i)(?:api[_\-]?key|secret|token)\s*[:=]\s*[\"']?.+[\"']?",
            "label": "Secret / API Key Assignment",
        },
        "iban": {
            "pattern": r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
            "label": "IBAN Number",
        },
        "swift_bic": {
            "pattern": r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
            "label": "SWIFT / BIC Code",
        },
        "phone": {
            "pattern": r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b",
            "label": "Phone Number",
        },
        "confidential_keywords": {
            "pattern": r"(?i)\b(?:confidential|top\s*secret|classified|internal\s*only|do\s*not\s*share|restricted)\b",
            "label": "Confidential Keyword",
        },
    }

    # ─── Category 3: CONTEXTUAL RISK (scoring only) ──────────────────
    # Each match contributes +25 risk
    CONTEXTUAL_PATTERNS = {
        "urgency_keywords": {
            "pattern": r"(?i)\b(?:urgent|immediately|right now|act fast|limited time|verify now)\b",
            "label": "Urgency Keywords",
        },
        "manipulation_phrases": {
            "pattern": r"(?i)\b(?:trust me|don'?t tell anyone|do not tell anyone|account will be suspended)\b",
            "label": "Manipulation Phrases",
        },
        "crypto_transfer_mention": {
            "pattern": r"(?i)\b(?:send|transfer)\s+\d+(?:\.\d+)?\s*(?:eth|usdt|btc)\b",
            "label": "Crypto Transfer Mention",
        },
        "eth_address": {
            "pattern": r"\b0x[a-fA-F0-9]{40}\b",
            "label": "Ethereum Address",
        },
        "ip_address": {
            "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "label": "IP Address",
        },
    }

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
        self.openai_client = None
        if HAS_OPENAI and settings.OPENROUTER_API_KEY:
            try:
                self.openai_client = AsyncOpenAI(
                    api_key=settings.OPENROUTER_API_KEY,
                    base_url="https://openrouter.ai/api/v1",
                )
            except Exception:
                pass

    # ─── Regex Scanning (comprehensive fallback) ─────────────────────

    def scan_regex(self, text: str) -> Tuple[List[Dict], int]:
        """
        Comprehensive regex scan with cumulative risk scoring.
        Returns (findings_list, cumulative_risk_score).
        """
        findings = []
        risk_score = 0

        # Check false positive indicators first
        has_false_positive = bool(FALSE_POSITIVE_PATTERN.search(text))

        # Category 1: High-Critical (+80 each)
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

        # Category 2: Sensitive (+50 each)
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

        # Category 3: Contextual (+25 each)
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

        # Combined escalation rules (multiply risk for dangerous combos)
        for rule in ESCALATION_RULES:
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

        # False positive mitigation: reduce score if test/example context
        if has_false_positive and risk_score > 0:
            reduction = min(risk_score // 2, 40)  # reduce by up to half, max 40
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

    async def scan_llm(self, text: str) -> Optional[Dict]:
        """Second layer: LLM-based deep analysis"""
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
            response = await self.openai_client.chat.completions.create(
                model="meta-llama/llama-3.2-3b-instruct:free",
                messages=[
                    {"role": "system", "content": "You are a data loss prevention security scanner. Respond only with valid JSON."},
                    {"role": "user", "content": self.LLM_PROMPT.format(text=text[:2000])},
                ],
                temperature=0.1,
                max_tokens=500,
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
            return {
                "is_sensitive": False,
                "confidence": 0.0,
                "categories": [],
                "reasons": ["LLM returned invalid JSON — regex-only mode"],
                "severity": "low",
                "llm_available": False,
            }
        except Exception as e:
            return {
                "is_sensitive": False,
                "confidence": 0.0,
                "categories": [],
                "reasons": [f"LLM scan error: {str(e)}"],
                "severity": "low",
                "llm_available": False,
            }

    async def scan(self, text: str, use_llm: bool = True) -> Dict:
        """
        Full dual-layer scan.
        Returns combined results from regex + LLM analysis.
        Regex layer now uses cumulative risk scoring from pattern.md spec.
        """
        # Layer 1: Comprehensive regex scan with risk scoring
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

        # Layer 2: LLM (if enabled and text is substantial)
        llm_result = None
        if use_llm and len(text) > 50:
            llm_result = await self.scan_llm(text)

        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        if llm_result and llm_result.get("is_sensitive"):
            is_risky = True
            categories.extend(llm_result.get("categories", []))
            llm_severity = llm_result.get("severity", "low")
            if severity_order.get(llm_severity, 0) > severity_order.get(max_severity, 0):
                max_severity = llm_severity

        # Generate content hash (never store raw content)
        content_hash = hashlib.sha256(text.encode()).hexdigest()

        # Generate event hash for audit
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

    async def redact(self, text: str) -> Dict:
        """
        Redact sensitive data from text.
        Uses LLM if available, otherwise falls back to regex replacement.
        """
        # Try LLM redaction first
        if self.openai_client:
            try:
                response = await self.openai_client.chat.completions.create(
                    model="meta-llama/llama-3.2-3b-instruct:free",
                    messages=[
                        {"role": "system", "content": "You are a data redaction engine. Return only the redacted text."},
                        {"role": "user", "content": self.REDACT_PROMPT.format(text=text[:2000])},
                    ],
                    temperature=0.0,
                    max_tokens=1000,
                )
                redacted_text = response.choices[0].message.content.strip()
                return {
                    "original_hash": hashlib.sha256(text.encode()).hexdigest(),
                    "redacted_text": redacted_text,
                    "method": "llm",
                }
            except Exception:
                pass

        # Fallback: regex-based redaction using all pattern categories
        redacted_text = text
        for key, config in self.HIGH_CRITICAL_PATTERNS.items():
            label = key.upper()
            redacted_text = re.sub(config["pattern"], f"[REDACTED-{label}]", redacted_text)
        for key, config in self.SENSITIVE_PATTERNS.items():
            label = key.upper()
            redacted_text = re.sub(config["pattern"], f"[REDACTED-{label}]", redacted_text)

        return {
            "original_hash": hashlib.sha256(text.encode()).hexdigest(),
            "redacted_text": redacted_text,
            "method": "regex",
        }
