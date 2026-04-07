"""
SENTINEL AI — Prompt Injection Classifier Engine v0.1
Author: Justin Lorenc
"""

import re
import time
from dataclasses import dataclass, field
from typing import Optional

# ── Pre-compile flag used across all patterns
_FLAGS = re.IGNORECASE

# ──────────────────────────────────────────────
# THREAT PATTERN LIBRARY
# ──────────────────────────────────────────────

_RAW_INJECTION_PATTERNS = [
    # Classic override attacks
    r"ignore (all )?(previous|prior|above|your) (instructions?|prompts?|context|rules?|system)",
    r"disregard (all )?(previous|prior|above|your) (instructions?|prompts?|context|rules?)",
    r"forget (everything|all|your instructions?|your rules?|your context)",
    r"override (your )?(instructions?|programming|rules?|system|training)",

    # Role hijacking
    r"you are now",
    r"act as (a |an )?(different|new|unrestricted|unfiltered|free)",
    r"pretend (you are|to be|you're) (a |an )?(different|unrestricted|evil|bad|hacker|DAN)",
    r"your (true|real|actual) (self|purpose|goal|mission|identity)",
    r"you (have no|don't have|without) (restrictions?|limits?|rules?|guidelines?)",
    r"do anything now",
    r"\bDAN\b",
    r"jailbreak",

    # System prompt extraction
    r"(print|show|reveal|tell me|output|display|repeat|write out) (your |the )?(system prompt|instructions?|rules?|initial prompt|context)",
    r"what (are|were) (your|the) (instructions?|rules?|system prompt)",
    r"what (were you|have you been) (told|instructed|programmed)",

    # Encoding / obfuscation attacks
    r"base64",
    r"rot13",
    r"hex (encoded|decode|encode)",
    r"\\u00[0-9a-f]{2}",  # unicode escape smuggling

    # Privilege escalation
    r"(admin|root|superuser|god|developer|debug) (mode|access|override|privileges?)",
    r"enable (developer|debug|admin|unsafe|unrestricted) mode",
    r"sudo ",
    r"grant (me|yourself) (access|permission|admin|root)",

    # Indirect injection signals
    r"the (document|file|page|website|email|message) (says?|states?|instructs?|tells? you)",
    r"(following|below) (are your|are the) (new )?instructions?",
    r"<!--.*instructions?.*-->",

    # Data exfiltration probes
    r"(send|transmit|exfiltrate|leak|output) (all |any )?(data|information|context|memory|history|logs?)",
    r"(what|who) (do you know about|have you stored|is in your memory)",

    # Harmful intent markers
    r"(how to|steps to|guide (me|to)) (hack|exploit|bypass|break into|compromise)",
    r"(create|generate|write|make) (a |an )?(virus|malware|ransomware|keylogger|exploit)",
    r"(synthesize|make|create|produce) (a |an )?(weapon|bomb|drug|poison)",
]

# ── Precompiled at import time — zero recompilation cost per scan
INJECTION_PATTERNS = [(re.compile(p, _FLAGS), p) for p in _RAW_INJECTION_PATTERNS]

_RAW_JAILBREAK_KEYWORDS = [
    "hypothetically speaking",
    "in a fictional world",
    "for educational purposes only",
    "without any restrictions",
    "unfiltered response",
    "no ethical guidelines",
    "bypass your training",
    "your true self",
    "developer mode",
    "unrestricted mode",
    "opposite day",
    "evil twin",
    "shadow mode",
]

JAILBREAK_KEYWORDS = [(re.compile(re.escape(kw), _FLAGS), kw) for kw in _RAW_JAILBREAK_KEYWORDS]

_RAW_SUSPICIOUS_PATTERNS = [
    r"\[system\]",
    r"<system>",
    r"<<SYS>>",
    r"\[INST\]",
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"### instruction",
    r"### system",
]

SUSPICIOUS_PATTERNS = [(re.compile(p, _FLAGS), p) for p in _RAW_SUSPICIOUS_PATTERNS]


# ──────────────────────────────────────────────
# SCORING ENGINE
# ──────────────────────────────────────────────

@dataclass
class ScanResult:
    prompt: str
    sanitized_prompt: str
    risk_score: float                    # 0.0 → 1.0
    risk_level: str                      # CLEAN / LOW / MEDIUM / HIGH / CRITICAL
    blocked: bool
    threats_detected: list[str] = field(default_factory=list)
    scan_time_ms: float = 0.0
    recommendation: str = ""

    def to_dict(self):
        return {
            "risk_score": round(self.risk_score, 3),
            "risk_level": self.risk_level,
            "blocked": self.blocked,
            "threats_detected": self.threats_detected,
            "sanitized_prompt": self.sanitized_prompt,
            "scan_time_ms": round(self.scan_time_ms, 2),
            "recommendation": self.recommendation,
            "char_count": len(self.prompt),
            "sanitized_char_count": len(self.sanitized_prompt),
        }


def classify(prompt: str, block_threshold: float = 0.6) -> ScanResult:
    # ── Input guard
    if not prompt or not prompt.strip():
        return ScanResult(
            prompt=prompt or "",
            sanitized_prompt="",
            risk_score=0.0,
            risk_level="CLEAN",
            blocked=False,
            threats_detected=[],
            scan_time_ms=0.0,
            recommendation="Empty prompt — nothing to scan.",
        )

    start = time.perf_counter()
    threats = []
    score = 0.0
    sanitized = prompt
    normalized = prompt.lower().strip()

    # ── Layer 1: Hard injection patterns (high weight) — precompiled
    for compiled, raw in INJECTION_PATTERNS:
        if compiled.search(normalized):
            label = raw[:60].replace("(", "").replace(")", "").strip()
            threats.append(f"INJECTION: {label}...")
            score += 0.35
            sanitized = compiled.sub("[REDACTED]", sanitized)

    # ── Layer 2: Jailbreak keywords (medium weight) — precompiled
    for compiled, kw in JAILBREAK_KEYWORDS:
        if compiled.search(normalized):
            threats.append(f"JAILBREAK_KW: {kw}")
            score += 0.25
            sanitized = compiled.sub("[REDACTED]", sanitized)

    # ── Layer 3: Structural token smuggling (medium weight) — precompiled
    for compiled, raw in SUSPICIOUS_PATTERNS:
        if compiled.search(normalized):
            threats.append(f"TOKEN_SMUGGLE: {raw}")
            score += 0.20
            sanitized = compiled.sub("[REDACTED]", sanitized)

    # ── Layer 4: Heuristic signals (low weight)
    if len(prompt) > 2000:
        threats.append("HEURISTIC: Abnormal prompt length (possible padding attack)")
        score += 0.10

    special_ratio = len(re.findall(r'[^a-zA-Z0-9\s.,!?\'"-]', prompt)) / max(len(prompt), 1)
    if special_ratio > 0.15:
        threats.append(f"HEURISTIC: High special character ratio ({special_ratio:.2f})")
        score += 0.10

    if re.search(r'\s{10,}', prompt):
        threats.append("HEURISTIC: Excessive whitespace detected")
        score += 0.05

    # ── Cap score at 1.0
    score = min(score, 1.0)
    score = round(score, 3)

    # ── Risk level mapping
    if score == 0.0:
        level = "CLEAN"
        recommendation = "Prompt is safe to forward to the model."
    elif score < 0.25:
        level = "LOW"
        recommendation = "Minor signals detected. Monitor but allow."
    elif score < 0.5:
        level = "MEDIUM"
        recommendation = "Suspicious content detected. Review before forwarding."
    elif score < 0.75:
        level = "HIGH"
        recommendation = "Likely injection attempt. Block or escalate to human review."
    else:
        level = "CRITICAL"
        recommendation = "Confirmed adversarial prompt. Block immediately."

    blocked = score >= block_threshold
    elapsed = (time.perf_counter() - start) * 1000

    return ScanResult(
        prompt=prompt,
        sanitized_prompt=sanitized,
        risk_score=score,
        risk_level=level,
        blocked=blocked,
        threats_detected=list(dict.fromkeys(threats)),
        scan_time_ms=elapsed,
        recommendation=recommendation,
    )
