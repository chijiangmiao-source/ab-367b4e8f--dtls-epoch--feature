#!/usr/bin/env python3
"""Acceptance driver for the DTLS 1.3 audit service.

Runs, in order:
  1. build checks        — byte-compile the app, import it, sanity-check the page
  2. review-rule tests   — the unittest suite (replay window, KeyUpdate, vectors)
  3. HTTP smoke tests    — live API checks of the KeyUpdate ratchet and the
                           replay-window boundary against APP_BASE_URL

Exits 0 when every check passes, 1 otherwise, so `docker compose up
--exit-code-from verify` reports the acceptance result as its status code.
"""
import base64
import compileall
import json
import os
import sys
import unittest
import urllib.error
import urllib.request

APP_BASE = os.environ.get("APP_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
FAILURES: list[str] = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(f"{name}: {detail}")
    return cond


# ---------------------------------------------------------------- build checks
def build_checks():
    print("[verify] build checks")
    check("compileall server", compileall.compile_dir("server", quiet=1))
    check("compileall tests", compileall.compile_dir("tests", quiet=1))
    try:
        import server.main  # noqa: F401
        check("import server.main", True)
    except Exception as exc:  # pragma: no cover
        check("import server.main", False, repr(exc))
    try:
        with open("server/static/index.html", encoding="utf-8") as fh:
            html = fh.read()
        check("page contains audit form",
              all(token in html for token in ("audit_id", "traffic_secret", "records")))
        check("page contains epoch evidence view",
              all(token in html for token in
                  ("epoch-select", "/epoch/", "世代证据", "失败边界")))
    except OSError as exc:
        check("page contains audit form", False, repr(exc))


# ------------------------------------------------------------ review-rule tests
def review_rule_tests():
    print("[verify] review-rule tests")
    suite = unittest.TestLoader().discover("tests")
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    check("review-rule test suite", result.wasSuccessful(),
          f"{len(result.failures)} failure(s), {len(result.errors)} error(s)")


# ---------------------------------------------------------------- HTTP helpers
def http(method, path, payload=None):
    data = headers = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
    req = urllib.request.Request(APP_BASE + path, data=data,
                                 headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, _maybe_json(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, _maybe_json(exc.read())


def _maybe_json(raw: bytes):
    try:
        return json.loads(raw.decode())
    except Exception:
        return raw.decode(errors="replace")


def b64(blob):
    return base64.b64encode(blob).decode()


def post_audit(audit_id, secret_hex, records, initial_epoch=3):
    return http("POST", "/api/audit", {
        "audit_id": audit_id,
        "initial_epoch": initial_epoch,
        "traffic_secret": secret_hex,
        "records": [b64(r) for r in records],
    })


def viol(row):
    return row.get("violation") or {}


# ------------------------------------------------------------------ smoke tests
def smoke_tests():
    from server.crypto import ratchet_secret
    from server.encode import key_update_record, seal_record

    print(f"[verify] HTTP smoke tests against {APP_BASE}")

    status, body = http("GET", "/healthz")
    check("health endpoint", status == 200 and body.get("status") == "ok",
          f"{status} {body}")
    status, _ = http("GET", "/")
    check("audit page served", status == 200, f"status {status}")

    secret3 = bytes(range(32))
    secret4 = ratchet_secret(secret3)
    secret_hex = secret3.hex()

    def app(seq, payload=b"m", secret=secret3, epoch=3, tamper=False):
        rec = bytearray(seal_record(secret, epoch, seq, payload, 23))
        if tamper:
            rec[-1] ^= 1
        return bytes(rec)

    # --- scenario A: legal KeyUpdate ratchets epoch and resets the window ---
    records = [
        app(0, b"ping-0"),
        app(1, b"ping-1"),
        key_update_record(secret3, 3, 2, request_update=0),
        seal_record(secret4, 4, 0, b"post-update", 23),
        app(1, b"ping-1"),  # late replay in the old epoch
    ]
    status, v = post_audit("smoke-keyupdate", secret_hex, records)
    ok = status == 200 and v.get("ok") is True
    check("keyupdate: submission accepted without violations", ok,
          f"{status} {json.dumps(v)[:300]}" if not ok else "")
    if status == 200:
        recs = v["records"]
        check("keyupdate: KeyUpdate processed after authentication",
              recs[2]["key_update"] == "processed" and recs[2]["auth"] == "ok")
        check("keyupdate: ratchet advanced to epoch 4",
              v["final_state"]["current_epoch"] == 4
              and v["final_state"]["ratchets"] == 1)
        check("keyupdate: next-epoch record adjudicated new",
              recs[3]["epoch"] == 4 and recs[3]["replay"] == "new")
        check("keyupdate: old-epoch replay adjudicated duplicate",
              recs[4]["replay"] == "duplicate" and recs[4]["epoch"] == 3)
        check("keyupdate: new epoch window reset then advanced",
              any(e["epoch"] == 4 and e["highest"] == 0
                  and e["bitmap"] == "0000000000000001"
                  for e in v["final_state"]["epochs"]))
    status, v2 = http("GET", "/api/audit/smoke-keyupdate")
    check("keyupdate: frozen verdict reopens",
          status == 200 and v2.get("ok") is True and v2.get("record_count") == 5,
          f"status {status}")

    # --- scenario B: replay-window boundary (64-bit bitmap) ---
    records = [
        app(0),                 # new
        app(0),                 # duplicate
        app(64),                # new, jumps the window
        app(0),                 # offset 64 -> too old
        app(1),                 # offset 63 -> new
        app(2, tamper=True),    # AEAD failure, must not advance the window
        app(2),                 # still new after the failed forgery
    ]
    status, v = post_audit("smoke-replay", secret_hex, records)
    if status != 200:
        check("replay: submission accepted", False, f"status {status}")
    else:
        recs = v["records"]
        check("replay: fresh record is new", recs[0]["replay"] == "new")
        check("replay: exact replay is duplicate", recs[1]["replay"] == "duplicate")
        check("replay: jump to 64 is new", recs[2]["replay"] == "new")
        check("replay: offset 64 is too old", recs[3]["replay"] == "too_old")
        check("replay: offset 63 is new", recs[4]["replay"] == "new")
        check("replay: tampered record fails authentication",
              viol(recs[5]).get("kind") == "authentication")
        check("replay: authentication failure offset points at the tag",
              viol(recs[5]).get("offset") == len(records[5]) - 16)
        check("replay: failed record did not advance the window",
              recs[5]["window_before"] == recs[5]["window_after"])
        check("replay: genuine seq 2 still new after the failure",
              recs[6]["replay"] == "new")
        fv = v.get("first_violation") or {}
        check("replay: first violation reported with raw offset",
              fv.get("record_index") == 5 and fv.get("kind") == "authentication"
              and fv.get("offset") == len(records[5]) - 16)

    # --- scenario C: forged KeyUpdate never ratchets; stale success cleared ---
    status, v = post_audit("smoke-forged-ku", secret_hex, [app(0), app(1)])
    check("forged-ku: clean submission succeeds first",
          status == 200 and v.get("ok") is True,
          f"{status} {json.dumps(v)[:200]}" if not (status == 200 and v.get("ok")) else "")
    forged = bytearray(key_update_record(secret3, 3, 1, request_update=1))
    forged[-1] ^= 0x80  # corrupt the tag: a forged KeyUpdate
    records = [app(0), bytes(forged), seal_record(secret4, 4, 0, b"next", 23)]
    status, v = post_audit("smoke-forged-ku", secret_hex, records)
    if status != 200:
        check("forged-ku: resubmission accepted", False, f"status {status}")
    else:
        recs = v["records"]
        check("forged-ku: verdict reports violations", v.get("ok") is False)
        check("forged-ku: forged KeyUpdate fails authentication",
              viol(recs[1]).get("kind") == "authentication")
        check("forged-ku: secret and window never advance",
              v["final_state"]["current_epoch"] == 3
              and v["final_state"]["ratchets"] == 0)
        check("forged-ku: next-epoch record rejected as state violation",
              viol(recs[2]).get("kind") == "state")
    status, v = http("GET", "/api/audit/smoke-forged-ku")
    check("forged-ku: stale success evidence cleared on resubmission",
          status == 200 and v.get("ok") is False, f"status {status}")

    # --- scenario D: truncation / length violations carry raw offsets ---
    status, v = post_audit("smoke-trunc", secret_hex, [bytes([0x2C, 0x00])])
    fv = (v or {}).get("first_violation") or {}
    check("truncation: kind and raw offset reported",
          status == 200 and fv.get("kind") == "truncation" and fv.get("offset") == 1,
          f"{status} {fv}")

    rec = bytearray(seal_record(secret3, 3, 0, b"xyz", 23))  # S=1,L=1: length @3
    declared = int.from_bytes(rec[3:5], "big")
    rec[3:5] = (declared - 1).to_bytes(2, "big")
    status, v = post_audit("smoke-length", secret_hex, [bytes(rec)])
    fv = (v or {}).get("first_violation") or {}
    check("length: kind and raw offset reported",
          status == 200 and fv.get("kind") == "length" and fv.get("offset") == 3,
          f"{status} {fv}")

    # --- scenario E: epoch generation evidence along a continuous chain ---
    from server.dtls import secret_fingerprint
    secret5 = ratchet_secret(secret4)

    edge0 = key_update_record(secret3, 3, 1, request_update=0)
    edge1 = key_update_record(secret4, 4, 1, request_update=0)
    forged_ku = bytearray(key_update_record(secret3, 3, 5))
    forged_ku[-1] ^= 0x80  # forged KeyUpdate: authentication failure
    # Boundary records must arrive while epoch 3 is still the retained
    # previous epoch (current == 4); after the next ratchet the auditor
    # retains only epoch 4, exactly as DTLS requires.
    records = [
        app(0, b"before"),                       # epoch 3 app data
        edge0,                                   # authenticated KeyUpdate #1: 3 -> 4
        bytes(forged_ku),                        # forged KeyUpdate, auth failure
        edge0,                                   # exact replay of edge #0 -> duplicate
        key_update_record(secret3, 3, 9),        # authenticated, but old epoch
        edge1,                                   # authenticated KeyUpdate #2: 4 -> 5
        seal_record(secret5, 5, 0, b"after-1", 23),
    ]

    status, v = post_audit("smoke-lineage", secret_hex, records)
    ok = status == 200
    check("lineage: chain submission accepted", ok, f"{status} {json.dumps(v)[:200]}")
    if ok:
        lineage = v["lineage"]
        check("lineage: root anchors initial epoch with fingerprint only",
              lineage["root"]["epoch"] == 3
              and lineage["root"]["secret_fingerprint"] == secret_fingerprint(secret3)
              and "secret" not in lineage["root"])
        edges = lineage["edges"]
        check("lineage: exactly two edges in advancement order",
              [(e["edge"], e["from_epoch"], e["to_epoch"], e["record_index"], e["seq"])
               for e in edges]
              == [(0, 3, 4, 1, 1), (1, 4, 5, 5, 1)],
              json.dumps(edges))
        check("lineage: fingerprints are one-way and adjacent",
              edges[0]["from_fingerprint"] == secret_fingerprint(secret3)
              and edges[0]["to_fingerprint"] == secret_fingerprint(secret4)
              and edges[1]["to_fingerprint"] == secret_fingerprint(secret5)
              and secret_hex not in json.dumps(lineage))
        rows = v["records"]
        check("lineage: only the advancing rows carry an edge id",
              rows[1]["lineage_edge"] == 0 and rows[5]["lineage_edge"] == 1
              and all(rows[i].get("lineage_edge") is None
                      for i in (0, 2, 3, 4, 6)))

    # epoch 3: derived straight from the initial traffic secret
    status, e3 = http("GET", "/api/audit/smoke-lineage/epoch/3")
    check("lineage: epoch 3 evidence origin is initial secret",
          status == 200
          and e3["evidence"]["origin"] == "initial_traffic_secret"
          and e3["evidence"]["path_length_edges"] == 0
          and e3["evidence"]["establishing_edge"] is None
          and e3["established_epochs"] == [3, 4, 5],
          f"{status} {json.dumps(e3)[:200]}")

    # epoch 4: one authenticated KeyUpdate edge
    status, e4 = http("GET", "/api/audit/smoke-lineage/epoch/4")
    check("lineage: epoch 4 evidence traces to KeyUpdate record #1 seq 1",
          status == 200
          and e4["evidence"]["origin"] == "authenticated_key_update"
          and e4["evidence"]["path_length_edges"] == 1
          and e4["evidence"]["establishing_record_index"] == 1
          and e4["evidence"]["establishing_record_seq"] == 1
          and e4["evidence"]["edges"][0]["linked"] is True
          and [n["epoch"] for n in e4["evidence"]["nodes"]] == [3, 4],
          f"{status} {json.dumps(e4)[:200]}")

    # epoch 5: continuous two-edge chain; later epochs must not leak into it
    status, e5 = http("GET", "/api/audit/smoke-lineage/epoch/5")
    check("lineage: epoch 5 evidence is a continuous two-edge chain",
          status == 200 and e5["evidence"]["path_length_edges"] == 2
          and [n["epoch"] for n in e5["evidence"]["nodes"]] == [3, 4, 5]
          and all(x["linked"] for x in e5["evidence"]["edges"])
          and e5["evidence"]["establishing_record_index"] == 5,
          f"{status} {json.dumps(e5)[:200]}")

    # failure boundary: forged / replayed / old-epoch records are kept out
    boundary = (e5 or {}).get("chain_boundary", [])
    reasons = {b["record_index"]: b["reason"] for b in boundary}
    check("lineage: failure boundary excludes non-edges with reasons",
          reasons.get(2) == "authentication_failed"
          and reasons.get(3) == "replayed_key_update"
          and reasons.get(4) == "old_epoch_not_advanced"
          and set(reasons).isdisjoint({1, 5}),
          json.dumps(boundary, ensure_ascii=False))

    # refusals: FastAPI wraps error bodies as {"detail": ...}
    status, body = http("GET", "/api/audit/no-such-audit/epoch/3")
    detail = body.get("detail") if isinstance(body, dict) else body
    check("lineage: unknown audit refused like reopen (no other-audit leak)",
          status == 404 and detail == "no frozen verdict for this audit id",
          f"{status} {body}")
    status, body = http("GET", "/api/audit/smoke-lineage/epoch/6")
    detail = body.get("detail") if isinstance(body, dict) else body
    check("lineage: unestablished epoch explicitly refused",
          status == 404 and isinstance(detail, dict)
          and detail.get("error") == "epoch_not_established"
          and detail.get("established_epochs") == [3, 4, 5]
          and detail.get("audit_id") == "smoke-lineage",
          f"{status} {body}")
    status, body = http("GET", "/api/audit/smoke-lineage/epoch/70000")
    detail = body.get("detail") if isinstance(body, dict) else body
    check("lineage: out-of-range epoch refused", status == 400
          and isinstance(detail, dict) and detail.get("error") == "epoch_out_of_range",
          f"{status} {body}")

    # no raw traffic secret anywhere in the evidence responses
    leak = secret_hex in json.dumps(e3) + json.dumps(e4) + json.dumps(e5)
    check("lineage: raw traffic secret absent from evidence responses", not leak)

    # resubmission replaces the lineage: epoch 4 evidence must disappear
    status, _ = post_audit("smoke-lineage", secret_hex, [app(0)])
    status, body = http("GET", "/api/audit/smoke-lineage/epoch/4")
    detail = body.get("detail") if isinstance(body, dict) else body
    check("lineage: old edge evidence cleared on resubmission",
          status == 404 and isinstance(detail, dict)
          and detail.get("error") == "epoch_not_established"
          and detail.get("established_epochs") == [3],
          f"{status} {body}")


def main():
    print(f"[verify] acceptance run, target {APP_BASE}")
    build_checks()
    review_rule_tests()
    smoke_tests()
    if FAILURES:
        print("[verify] failures:")
        for failure in FAILURES:
            print("  -", failure)
    print("[verify] ACCEPTANCE:", "PASS" if not FAILURES else "FAIL")
    sys.exit(0 if not FAILURES else 1)


if __name__ == "__main__":
    main()
