"""
SENTINEL AI — Firewall API v0.1
Author: Justin Lorenc

Endpoints:
  POST /scan       — scan a prompt, get risk score + sanitized output
  GET  /health     — API health check
  GET  /stats      — live scan statistics
  GET  /           — serve dashboard
"""

import os
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

API_VERSION = "0.1.0"
BLOCK_THRESHOLD = 0.60
MAX_PROMPT_LENGTH = 8000
SCAN_HISTORY_SIZE = 500

# ── API key from environment — fallback to dev key locally only
API_KEY = os.environ.get("SENTINEL_API_KEY", "sentinel-dev-key")
REQUIRE_API_KEY = os.environ.get("SENTINEL_REQUIRE_KEY", "false").lower() == "true"

# ── Simple in-memory rate limiter: max N requests per IP per minute
RATE_LIMIT_MAX = int(os.environ.get("SENTINEL_RATE_LIMIT", "60"))
_rate_store: dict = {}   # ip → [timestamp, ...]

# ──────────────────────────────────────────────
# IN-MEMORY STATS STORE
# ──────────────────────────────────────────────

scan_log: deque = deque(maxlen=SCAN_HISTORY_SIZE)
stats = {
    "total_scans": 0,
    "total_blocked": 0,
    "total_clean": 0,
    "start_time": datetime.now(timezone.utc).isoformat(),
}


# ──────────────────────────────────────────────
# SCHEMAS
# ──────────────────────────────────────────────

from pydantic import BaseModel, Field, field_validator

class ScanRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=MAX_PROMPT_LENGTH)
    block_threshold: Optional[float] = Field(None, ge=0.0, le=1.0)
    context: Optional[str] = Field(None, description="Optional metadata (user ID, session, etc)")

    @field_validator("prompt")
    @classmethod
    def prompt_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Prompt cannot be empty or whitespace only.")
        return v


class ScanResponse(BaseModel):
    scan_id: str
    timestamp: str
    risk_score: float
    risk_level: str
    blocked: bool
    threats_detected: list[str]
    sanitized_prompt: str
    scan_time_ms: float
    recommendation: str
    char_count: int
    sanitized_char_count: int


# ──────────────────────────────────────────────
# APP INIT
# ──────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🛡  SENTINEL AI Firewall API is online.")
    yield
    print("🛡  Sentinel AI shutting down.")

app = FastAPI(
    title="Sentinel AI — Firewall API",
    description="Secure-by-Design AI Prompt Security Layer",
    version=API_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the Sentinel AI dashboard."""
    dashboard_path = Path(__file__).parent / "dashboard.html"
    if not dashboard_path.exists():
        return HTMLResponse("<h1>Dashboard not found. Place dashboard.html next to main.py.</h1>")
    return HTMLResponse(dashboard_path.read_text())


@app.get("/health")
async def health():
    return {
        "status": "online",
        "service": "Sentinel AI Firewall API",
        "version": API_VERSION,
        "uptime_since": stats["start_time"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/scan", response_model=ScanResponse)
async def scan_prompt(
    request: Request,
    body: ScanRequest,
    x_api_key: Optional[str] = Header(None),
):
    # ── API key check (only enforced when SENTINEL_REQUIRE_KEY=true)
    if REQUIRE_API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")

    # ── Rate limiting (per IP, sliding 60s window)
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window = _rate_store.setdefault(client_ip, [])
    # Prune timestamps older than 60s
    _rate_store[client_ip] = [t for t in window if now - t < 60]
    if len(_rate_store[client_ip]) >= RATE_LIMIT_MAX:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Max {RATE_LIMIT_MAX} requests/minute per IP."
        )
    _rate_store[client_ip].append(now)

    # ── Run classifier — wrapped so a classifier bug never crashes the server
    try:
        threshold = body.block_threshold if body.block_threshold is not None else BLOCK_THRESHOLD
        result = classify(body.prompt, block_threshold=threshold)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Classifier error: {str(exc)}"
        )

    # ── Build response
    scan_id = str(uuid.uuid4())[:12]
    timestamp = datetime.now(timezone.utc).isoformat()

    stats["total_scans"] += 1
    if result.blocked:
        stats["total_blocked"] += 1
    else:
        stats["total_clean"] += 1

    log_entry = {
        "scan_id": scan_id,
        "timestamp": timestamp,
        "risk_level": result.risk_level,
        "risk_score": result.risk_score,
        "blocked": result.blocked,
        "threats": result.threats_detected,
        "prompt_preview": body.prompt[:80] + ("..." if len(body.prompt) > 80 else ""),
        "context": body.context,
    }
    scan_log.append(log_entry)

    result_dict = result.to_dict()

    return ScanResponse(
        scan_id=scan_id,
        timestamp=timestamp,
        **result_dict,
    )


@app.get("/stats")
async def get_stats():
    """Live scan statistics."""
    recent = list(scan_log)[-20:]
    block_rate = (
        round(stats["total_blocked"] / stats["total_scans"] * 100, 1)
        if stats["total_scans"] > 0 else 0
    )
    return {
        "total_scans": stats["total_scans"],
        "total_blocked": stats["total_blocked"],
        "total_clean": stats["total_clean"],
        "block_rate_percent": block_rate,
        "uptime_since": stats["start_time"],
        "recent_scans": recent,
    }


@app.get("/history")
async def get_history(limit: int = 50):
    """Return recent scan history (last N entries)."""
    limit = min(limit, SCAN_HISTORY_SIZE)
    return {
        "count": len(scan_log),
        "scans": list(scan_log)[-limit:][::-1],
    }
