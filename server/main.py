"""Deep-space relay DTLS 1.3 record audit service.

POST /api/audit adjudicates a captured record sequence and freezes the
verdict; GET /api/audit/{audit_id} reopens the frozen verdict. A new
submission for the same audit id atomically replaces the previous verdict,
so stale success evidence is cleared whenever a submission is adjudicated.
"""
from __future__ import annotations

import base64
import binascii
import datetime
import pathlib

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .dtls import epoch_evidence, run_audit

MAX_RECORDS = 48
MAX_RECORD_BYTES = 16640  # 2^14 plaintext + header + padding + tag headroom
MAX_VERDICTS = 512

app = FastAPI(title="Deep-Space Relay DTLS 1.3 Audit")

INDEX_HTML = (pathlib.Path(__file__).parent / "static" / "index.html").read_text(
    encoding="utf-8")

# audit_id -> frozen verdict (insertion ordered; oldest evicted past the cap)
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
    verdict.update({
        "audit_id": req.audit_id,
        "initial_epoch": req.initial_epoch,
        "record_count": len(blobs),
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    })
    # Replace any older frozen verdict for this audit id: the previous
    # success evidence is cleared as part of this submission.
    if req.audit_id not in VERDICTS and len(VERDICTS) >= MAX_VERDICTS:
        VERDICTS.pop(next(iter(VERDICTS)))
    VERDICTS[req.audit_id] = verdict
    return verdict


@app.get("/api/audit/{audit_id}")
def reopen_audit(audit_id: str) -> dict:
    verdict = VERDICTS.get(audit_id)
    if verdict is None:
        raise HTTPException(404, "no frozen verdict for this audit id")
    return verdict


@app.get("/api/audit/{audit_id}/epoch/{epoch}")
def epoch_generation_evidence(audit_id: str, epoch: int) -> dict:
    """Generation-evidence view for one established epoch of a frozen audit.

    Refuses explicitly when the audit is unknown/frozen elsewhere, or the
    epoch was never established by the initial secret or an authenticated
    KeyUpdate edge. No raw traffic secret is ever returned; generations are
    identified by irreversible fingerprints only.
    """
    verdict = VERDICTS.get(audit_id)
    if verdict is None:
        # Same opaque refusal as the reopen endpoint: no evidence from any
        # other audit is disclosed.
        raise HTTPException(404, "no frozen verdict for this audit id")
    if not 0 <= epoch <= 65535:
        raise HTTPException(
            400,
            detail={
                "error": "epoch_out_of_range",
                "message": "epoch must be in 0..65535",
                "audit_id": audit_id,
                "epoch": epoch,
            },
        )
    lineage = verdict["lineage"]
    established = {lineage["root"]["epoch"]}
    established.update(e["to_epoch"] for e in lineage["edges"])
    if epoch not in established:
        raise HTTPException(
            404,
            detail={
                "error": "epoch_not_established",
                "message": ("epoch was never established by the initial "
                            "traffic secret or an authenticated KeyUpdate"),
                "audit_id": audit_id,
                "epoch": epoch,
                "established_epochs": sorted(established),
            },
        )
    return {
        "audit_id": audit_id,
        "epoch": epoch,
        "evidence": epoch_evidence(lineage, epoch),
        "established_epochs": sorted(established),
        "chain_boundary": verdict["chain_boundary"],
    }
