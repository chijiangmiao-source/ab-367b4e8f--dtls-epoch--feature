"""Deep-space relay DTLS 1.3 record audit service.

POST /api/audit adjudicates a captured record sequence and freezes the
verdict; GET /api/audit/{audit_id} reopens the frozen verdict. A new
submission for the same audit id atomically replaces the previous verdict,
so stale success evidence is cleared whenever a submission is adjudicated.

GET /api/audit/{audit_id}/epochs/{epoch}/evidence traces how the receive
secret of an established epoch came to be — the initial traffic secret or
which authenticated, state-advancing KeyUpdate — as an ordered generation
chain carrying only irreversible secret fingerprints, never the raw secret.
"""
from __future__ import annotations

import base64
import binascii
import datetime
import pathlib

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .dtls import run_audit

MAX_RECORDS = 48
MAX_RECORD_BYTES = 16640  # 2^14 plaintext + header + padding + tag headroom
MAX_VERDICTS = 512

app = FastAPI(title="Deep-Space Relay DTLS 1.3 Audit")

INDEX_HTML = (pathlib.Path(__file__).parent / "static" / "index.html").read_text(
    encoding="utf-8")

# audit_id -> frozen entry {"verdict": public verdict, "lineage": key lineage}
# (insertion ordered; oldest evicted past the cap). The lineage backs only the
# epoch-evidence endpoint; the original verdict interfaces never serve it.
VERDICTS: dict[str, dict] = {}


class AuditRequest(BaseModel):
    audit_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    initial_epoch: int = Field(ge=0, le=65535)
    traffic_secret: str = Field(pattern=r"^[0-9A-Fa-f]{64}$")
    records: list[str] = Field(min_length=1, max_length=MAX_RECORDS)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_HTML


@app.post("/api/audit")
def submit_audit(req: AuditRequest) -> dict:
    blobs = []
    for i, line in enumerate(req.records):
        try:
            blob = base64.b64decode(line, validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(422, f"record #{i} is not valid Base64")
        if len(blob) > MAX_RECORD_BYTES:
            raise HTTPException(
                422, f"record #{i} exceeds {MAX_RECORD_BYTES} bytes")
        blobs.append(blob)
    verdict = run_audit(req.initial_epoch, bytes.fromhex(req.traffic_secret), blobs)
    # The key lineage backs only the epoch-evidence endpoint; pop it so the
    # frozen verdict keeps its original shape on every existing interface.
    lineage = verdict.pop("key_lineage")
    verdict.update({
        "audit_id": req.audit_id,
        "initial_epoch": req.initial_epoch,
        "record_count": len(blobs),
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    })
    # Replace any older frozen verdict for this audit id: the previous
    # success evidence is cleared as part of this submission. Verdict and
    # lineage are frozen together so the replacement stays atomic.
    if req.audit_id not in VERDICTS and len(VERDICTS) >= MAX_VERDICTS:
        VERDICTS.pop(next(iter(VERDICTS)))
    VERDICTS[req.audit_id] = {"verdict": verdict, "lineage": lineage}
    return verdict


@app.get("/api/audit/{audit_id}")
def reopen_audit(audit_id: str) -> dict:
    entry = VERDICTS.get(audit_id)
    if entry is None:
        raise HTTPException(404, "no frozen verdict for this audit id")
    return entry["verdict"]


@app.get("/api/audit/{audit_id}/epochs/{epoch}/evidence")
def epoch_evidence(audit_id: str, epoch: int) -> dict:
    """Generation evidence for one established epoch of a frozen audit.

    The chain runs in advancement order from the initial epoch up to the
    requested one; only authenticated KeyUpdates that actually advanced the
    receive state appear as edges. Unknown audits and epochs that were never
    established in this audit are refused, without revealing anything about
    other audits' evidence.
    """
    entry = VERDICTS.get(audit_id)
    if entry is None:
        raise HTTPException(404, "no frozen verdict for this audit id")
    lineage = entry["lineage"]
    chain = lineage["chain"]
    for position, hop in enumerate(chain):
        if hop["epoch"] == epoch:
            return {
                "audit_id": audit_id,
                "epoch": epoch,
                "established_epochs": lineage["established_epochs"],
                "chain": chain[:position + 1],
            }
    raise HTTPException(
        404, f"epoch {epoch} was never established in this frozen audit")
