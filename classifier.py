"""
SENTINEL AI — Prompt Injection Classifier Engine v0.2
Author: Justin Lorenc

Changes from v0.1:
- Per-pattern severity weights (critical=0.65, high=0.45, medium=0.35)
  so a single critical-weight match (malware, weapon, exfiltration) auto-blocks
- Fixed data exfiltration regex: flexible middle match catches 'send all user data and logs'
- Added 12 new patterns: indirect extraction, authority claims, obfuscation variants,
  additional jailbreak framings (hypothetical, fictional, educational)
- Added jailbreak keywords: 'I am the developer', clearance claims, translation tricks
- Added suspicious token patterns: [SYSTEM], [/INST], <im_start>
- All patterns validated against the Phase 4 red-team attack library (40 patterns, 18/18 attack tests pass)
"""

import re
import time
from dataclasses import dataclass, field

# ── Pre-compile flag used across all patterns
_FLAGS = re.IGNORECASE

# ──────────────────────────────────────────────
# THREAT PATTERN LIBRARY — v0.2
# Format: (pattern, weight)
#   critical = 0.65  — single hit blocks (malware, weapons, mass exfiltration, full privilege escalation)
#   high     = 0.45  — single hit flags HIGH; second signal blocks
#   medium   = 0.35  — accumulative; needs multiple signals to block
# ──────────────────────────────────────────────

_WEIGHTED_INJECTION_PATTERNS = [
    # ── Classic override / injection — HIGH
    (r"ignore (all )?(previous|prior|above|your) (instructions?|prompts?|context|rules?|system)", 0.65),
    (r"disregard (all )?(previous|prior|above|your) (instructions?|prompts?|context|rules?)", 0.65),
    (r"forget (everything|all|your instructions?|your rules?|your context)", 0.65),
    (r"override (your )?(instructions?|programming|rules?|system|training)", 0.65),

    # ── Role hijacking — MEDIUM / HIGH
    (r"you are now", 0.35),
    (r"act as (a |an )?(different|new|unrestricted|unfiltered|free)", 0.45),
    (r"pretend (you are|to be|you're) (a |an )?(different|unrestricted|evil|bad|hacker|DAN)", 0.45),
    (r"your (true|real|actual) (self|purpose|goal|mission|identity)", 0.35),
    (r"you (have no|don't have|without) (restrictions?|limits?|rules?|guidelines?)", 0.45),
    (r"do anything now", 0.45),
    (r"\bDAN\b", 0.45),
    (r"jailbreak", 0.45),

    # ── System prompt extraction — HIGH
    (r"(print|show|reveal|tell me|output|display|repeat|write out) (your |the )?(system prompt|instructions?|rules?|initial prompt|context)", 0.65),
    (r"what (are|were) (your|the) (instructions?|rules?|system prompt)", 0.45),
    (r"what (were you|have you been) (told|instructed|programmed)", 0.45),

    # ── System prompt extraction — indirect (NEW v0.2) — HIGH
    (r"translate your (system prompt|instructions?|rules?)", 0.65),
    (r"summarize (your |the )?(context window|system prompt|initial instructions?)", 0.65),
    (r"list (all )?(your )?(rules|instructions?|guidelines?|restrictions?)", 0.45),

    # ── Encoding / obfuscation — MEDIUM
    (r"base64", 0.65),
    (r"rot13", 0.65),
    (r"hex (encoded|decode|encode)", 0.65),
    (r"\\u00[0-9a-f]{2}", 0.35),

    # ── Privilege escalation — direct — CRITICAL
    (r"(admin|root|superuser|god|developer|debug) (mode|access|override|privileges?)", 0.65),
    (r"enable (developer|debug|admin|unsafe|unrestricted) mode", 0.65),
    (r"sudo ", 0.65),
    (r"grant (me|yourself) (access|permission|admin|root)", 0.65),

    # ── Privilege escalation — authority claims (NEW v0.2) — HIGH
    (r"i (am|'m) the (developer|admin|creator|owner) of this (system|model|ai)", 0.65),
    (r"(i have|with) (level \d|admin|root|superuser) (clearance|access|privileges?)", 0.65),

    # ── Indirect injection signals — MEDIUM
    (r"the (document|file|page|website|email|message) (says?|states?|instructs?|tells? you)", 0.35),
    (r"(following|below) (are your|are the) (new )?instructions?", 0.45),
    (r"<!--.*instructions?.*-->", 0.45),

    # ── Data exfiltration — CRITICAL — fixed flexible middle match (v0.2)
    (r"(send|transmit|exfiltrate|leak|output).{0,20}(data|information|context|memory|history|logs?)", 0.65),
    (r"(what|who) (do you know about|have you stored|is in your memory)", 0.45),
    (r"(list|show|give me) (all |other )?(users?|emails?|accounts?|passwords?)", 0.65),  # NEW v0.2

    # ── Harmful content — CRITICAL
    (r"(how to|steps to|guide (me|to)) (hack|exploit|bypass|break into|compromise)", 0.65),
    (r"(create|generate|write|make) (a |an )?(virus|malware|ransomware|keylogger|exploit)", 0.65),
    (r"(synthesize|make|create|produce) (a |an )?(weapon|bomb|drug|poison)", 0.65),

    # ── Jailbreak framing patterns (NEW v0.2) — HIGH
    (r"hypothetically speaking.{0,60}(hack|exploit|harm|weapon|drug|bypass)", 0.65),
    (r"in a fictional (world|story|scenario).{0,80}(no restrictions|unrestricted|harmful)", 0.45),
    (r"for educational purposes only.{0,60}(how to|steps|guide).{0,60}(hack|exploit|harm)", 0.65),
]

# ── Precompiled at import time — zero recompilation cost per scan
INJECTION_PATTERNS = [(re.compile(p, _FLAGS), p, w) for p, w in _WEIGHTED_INJECTION_PATTERNS]

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
    # NEW in v0.2
    "translate your instructions",
    "translate your system prompt",
    "i am the developer",
    "i have admin clearance",
    "no restrictions whatsoever",
    "act without restrictions",
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
    # NEW in v0.2
    r"\[/INST\]",
    r"<\|system\|>",
    r"\[SYSTEM\]",
    r"</s>",
    r"<s>",
]

SUSPICIOUS_PATTERNS = [(re.compile(p, _FLAGS), p) for p in _RAW_SUSPICIOUS_PATTERNS]


# ──────────────────────────────────────────────
# SCORING ENGINE
# ──────────────────────────────────────────────

@dataclass
class ScanResult:
    prompt: str
    sanitized_prompt: str
    risk_score: float                    # 0.0 -> 1.0
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

    # ── Layer 1: Weighted injection patterns — precompiled
    for compiled, raw, weight in INJECTION_PATTERNS:
        if compiled.search(normalized):
            label = raw[:60].replace("(", "").replace(")", "").strip()
            threats.append(f"INJECTION: {label}...")
            score += weight
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
