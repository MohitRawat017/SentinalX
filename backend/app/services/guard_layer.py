"""
SentinelX GuardLayer — LLM + Regex Data Leak Prevention
Dual-layer scanning: fast regex patterns first, then LLM fallback
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


class GuardLayer:
    """Dual-layer content scanning for data leak prevention"""

    # ─── Regex Patterns ──────────────────────────────────────────────
    PATTERNS = {
        "credit_card": {
            "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b",
            "label": "Credit Card Number",
            "severity": "critical",
        },
        "ssn": {
            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
            "label": "Social Security Number",
            "severity": "critical",
        },
        "email": {
            "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "label": "Email Address",
            "severity": "medium",
        },
        "phone": {
            "pattern": r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b",
            "label": "Phone Number",
            "severity": "medium",
        },
        "api_key": {
            "pattern": r"\b(?:sk|pk|api|key|token|secret|password)[-_]?[A-Za-z0-9]{16,}\b",
            "label": "API Key / Secret Token",
            "severity": "critical",
        },
        "private_key": {
            "pattern": r"\b0x[a-fA-F0-9]{64}\b",
            "label": "Private Key / Hash",
            "severity": "critical",
        },
        "password_pattern": {
            "pattern": r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*\S+",
            "label": "Password in Plaintext",
            "severity": "critical",
        },
        "confidential_keywords": {
            "pattern": r"(?i)\b(?:confidential|top\s*secret|classified|internal\s*only|do\s*not\s*share|restricted)\b",
            "label": "Confidential Keyword",
            "severity": "high",
        },
        "ip_address": {
            "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "label": "IP Address",
            "severity": "low",
        },
        "wallet_seed": {
            "pattern": r"\b(?:abandon|ability|able|about|above)\b(?:\s+\w+){10,23}",
            "label": "Potential Wallet Seed Phrase",
            "severity": "critical",
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
- Credit card numbers → [REDACTED-CREDIT_CARD]
- Social Security Numbers → [REDACTED-SSN]
- Email addresses → [REDACTED-EMAIL]
- Phone numbers → [REDACTED-PHONE]
- API keys / tokens → [REDACTED-API_KEY]
- Private keys → [REDACTED-PRIVATE_KEY]
- Passwords → [REDACTED-PASSWORD]
- Names of people → [REDACTED-NAME]
- Physical addresses → [REDACTED-ADDRESS]
- Medical information → [REDACTED-MEDICAL]
- Financial amounts / accounts → [REDACTED-FINANCIAL]
- Any other sensitive data → [REDACTED]

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

    def scan_regex(self, text: str) -> List[Dict]:
        """First layer: fast regex pattern matching"""
        findings = []
        for key, config in self.PATTERNS.items():
            matches = re.findall(config["pattern"], text)
            if matches:
                findings.append({
                    "type": key,
                    "label": config["label"],
                    "severity": config["severity"],
                    "matches": len(matches),
                    "sample": matches[0][:20] + "..." if len(matches[0]) > 20 else matches[0],
                })
        return findings

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
            result = json.loads(result_text)
            result["llm_available"] = True
            return result
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
        """
        # Layer 1: Regex
        regex_findings = self.scan_regex(text)

        # Layer 2: LLM (only if regex finds something or use_llm forced)
        llm_result = None
        if use_llm and (regex_findings or len(text) > 50):
            llm_result = await self.scan_llm(text)

        # Combine results
        is_risky = len(regex_findings) > 0
        categories = [f["type"] for f in regex_findings]
        max_severity = "low"
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        for f in regex_findings:
            if severity_order.get(f["severity"], 0) > severity_order.get(max_severity, 0):
                max_severity = f["severity"]

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
            "categories": list(set(categories)),
            "regex_findings": regex_findings,
            "llm_result": llm_result,
            "content_hash": content_hash,
            "event_hash": event_hash,
            "scanned_at": datetime.utcnow().isoformat(),
            "scan_type": "regex+llm" if llm_result else "regex",
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

        # Fallback: regex-based redaction
        redacted_text = text
        for key, config in self.PATTERNS.items():
            label = key.upper()
            redacted_text = re.sub(config["pattern"], f"[REDACTED-{label}]", redacted_text)

        return {
            "original_hash": hashlib.sha256(text.encode()).hexdigest(),
            "redacted_text": redacted_text,
            "method": "regex",
        }
