"""Generation-evidence tests: the authenticated KeyUpdate lineage chain,
irreversible secret fingerprints, the failure boundary, and the epoch
evidence endpoint's refusal/isolation semantics."""
import json
import unittest

from fastapi import HTTPException

from server.crypto import ratchet_secret
from server.dtls import (
    chain_boundary,
    epoch_evidence,
    run_audit,
    secret_fingerprint,
)
from server.encode import key_update_record, seal_record
from server.main import (
    MAX_VERDICTS,
    VERDICTS,
    epoch_generation_evidence,
    submit_audit,
)
from server.main import AuditRequest

SECRET3 = bytes(range(32))
SECRET4 = ratchet_secret(SECRET3)
SECRET5 = ratchet_secret(SECRET4)


def appdata(secret, epoch, seq, payload=b"x", **kw):
    return seal_record(secret, epoch, seq, payload, 23, **kw)


def ku(secret, epoch, seq, request_update=0, **kw):
    return key_update_record(secret, epoch, seq, request_update=request_update, **kw)


def tamper(blob):
    rec = bytearray(blob)
    rec[-1] ^= 0x80
    return bytes(rec)


def submit(audit_id, secret, blobs, initial_epoch=3):
    """Drive the POST handler directly (same validation as the HTTP route)."""
    import base64
    req = AuditRequest(
        audit_id=audit_id,
        initial_epoch=initial_epoch,
        traffic_secret=secret.hex(),
        records=[base64.b64encode(b).decode() for b in blobs],
    )
    return submit_audit(req)


class FingerprintTests(unittest.TestCase):
    def test_fingerprint_is_keyed_and_irreversible(self):
        fp = secret_fingerprint(SECRET3)
        self.assertEqual(len(fp), 64)
        self.assertNotIn(SECRET3.hex(), fp)
        # deterministic, and distinct secrets get distinct fingerprints
        self.assertEqual(fp, secret_fingerprint(SECRET3))
        self.assertNotEqual(fp, secret_fingerprint(SECRET4))

    def test_verdict_never_contains_raw_secret(self):
        verdict = run_audit(3, SECRET3, [appdata(SECRET3, 3, 0)])
        blob = json.dumps(verdict, sort_keys=True)
        self.assertNotIn(SECRET3.hex(), blob)
        self.assertNotIn(SECRET3.hex().upper(), blob)
        # every fingerprint field is a 64-hex-char digest, never the secret
        root_fp = verdict["lineage"]["root"]["secret_fingerprint"]
        self.assertEqual(root_fp, secret_fingerprint(SECRET3))


class LineageChainTests(unittest.TestCase):
    def _two_ratchet_capture(self):
        return [
            appdata(SECRET3, 3, 0, b"a"),
            ku(SECRET3, 3, 1),                       # edge #0: 3 -> 4
            appdata(SECRET4, 4, 0, b"b"),
            ku(SECRET4, 4, 1),                       # edge #1: 4 -> 5
            appdata(SECRET5, 5, 0, b"c"),
        ]

    def test_chain_root_and_edges_in_advancement_order(self):
        verdict = run_audit(3, SECRET3, self._two_ratchet_capture())
        lineage = verdict["lineage"]
        self.assertEqual(lineage["initial_epoch"], 3)
        self.assertEqual(lineage["root"], {
            "kind": "initial",
            "epoch": 3,
            "secret_fingerprint": secret_fingerprint(SECRET3),
        })
        edges = lineage["edges"]
        self.assertEqual([(e["edge"], e["from_epoch"], e["to_epoch"]) for e in edges],
                         [(0, 3, 4), (1, 4, 5)])
        # each edge names the exact record that established it
        self.assertEqual([(e["record_index"], e["seq"]) for e in edges],
                         [(1, 1), (3, 1)])
        # irreversible fingerprints link adjacently: root -> e0 -> e1
        self.assertEqual(edges[0]["from_fingerprint"], secret_fingerprint(SECRET3))
        self.assertEqual(edges[0]["to_fingerprint"], secret_fingerprint(SECRET4))
        self.assertEqual(edges[1]["from_fingerprint"], secret_fingerprint(SECRET4))
        self.assertEqual(edges[1]["to_fingerprint"], secret_fingerprint(SECRET5))

    def test_edge_marked_on_processing_row_only(self):
        verdict = run_audit(3, SECRET3, self._two_ratchet_capture())
        rows = verdict["records"]
        self.assertEqual(rows[1]["key_update"], "processed")
        self.assertEqual(rows[1]["lineage_edge"], 0)
        self.assertEqual(rows[3]["lineage_edge"], 1)
        # plain application records are not edges
        for i in (0, 2, 4):
            self.assertIsNone(rows[i]["lineage_edge"])

    def test_initial_epoch_evidence(self):
        verdict = run_audit(3, SECRET3, self._two_ratchet_capture())
        ev = epoch_evidence(verdict["lineage"], 3)
        self.assertEqual(ev["origin"], "initial_traffic_secret")
        self.assertEqual(ev["path_length_edges"], 0)
        self.assertEqual(len(ev["nodes"]), 1)
        self.assertIsNone(ev["establishing_edge"])
        self.assertEqual(ev["nodes"][0]["epoch"], 3)

    def test_successor_epoch_evidence_traces_to_authenticated_key_update(self):
        verdict = run_audit(3, SECRET3, self._two_ratchet_capture())
        ev4 = epoch_evidence(verdict["lineage"], 4)
        self.assertEqual(ev4["origin"], "authenticated_key_update")
        self.assertEqual(ev4["path_length_edges"], 1)
        self.assertEqual(ev4["establishing_edge"], 0)
        self.assertEqual(ev4["establishing_record_index"], 1)
        self.assertEqual(ev4["establishing_record_seq"], 1)
        self.assertTrue(ev4["edges"][0]["linked"])

        ev5 = epoch_evidence(verdict["lineage"], 5)
        self.assertEqual(ev5["path_length_edges"], 2)
        self.assertEqual([n["epoch"] for n in ev5["nodes"]], [3, 4, 5])
        self.assertTrue(all(e["linked"] for e in ev5["edges"]))
        # evidence for epoch 4 must not leak the edge that established epoch 5
        self.assertEqual([e["to_epoch"] for e in ev4["edges"]], [4])

    def test_forged_duplicate_old_and_malformed_records_never_enter_chain(self):
        records = [
            appdata(SECRET3, 3, 0, b"a"),
            tamper(ku(SECRET3, 3, 5)),                  # auth failure: forged
            ku(SECRET3, 3, 1),                          # edge #0 -> epoch 4
            ku(SECRET3, 3, 1),                          # exact replay (duplicate)
            ku(SECRET3, 3, 9),                          # authenticated, old epoch
        ]
        verdict = run_audit(3, SECRET3, records)
        edges = verdict["lineage"]["edges"]
        self.assertEqual(len(edges), 1)
        self.assertEqual((edges[0]["record_index"], edges[0]["from_epoch"],
                          edges[0]["to_epoch"]), (2, 3, 4))
        boundary = verdict["chain_boundary"]
        by_index = {b["record_index"]: b for b in boundary}
        self.assertEqual(by_index[1]["reason"], "authentication_failed")
        self.assertEqual(by_index[3]["reason"], "replayed_key_update")
        self.assertEqual(by_index[3]["replay_of_edge"], 2)
        self.assertEqual(by_index[4]["reason"], "old_epoch_not_advanced")
        # the chain must still terminate cleanly at epoch 4
        self.assertEqual(verdict["final_state"]["current_epoch"], 4)
        self.assertEqual(verdict["final_state"]["ratchets"], 1)

    def test_malformed_authenticated_key_update_is_boundary_not_edge(self):
        from server.encode import handshake_message
        bad_ku = seal_record(
            SECRET3, 3, 0, handshake_message(24, b"\x07"), 22)
        verdict = run_audit(3, SECRET3, [bad_ku])
        self.assertEqual(verdict["lineage"]["edges"], [])
        self.assertEqual(verdict["chain_boundary"][0]["reason"],
                         "authenticated_not_advanced")
        self.assertEqual(verdict["final_state"]["ratchets"], 0)

    def test_all_authentication_failures_are_boundary_entries(self):
        records = [
            tamper(appdata(SECRET3, 3, 0, b"a")),       # forged app data
            appdata(SECRET3, 3, 1, b"b"),
        ]
        verdict = run_audit(3, SECRET3, records)
        # Content never unwraps on tag failure, so every forgery candidate
        # is shown at the boundary — a forged KeyUpdate would look identical.
        self.assertEqual(len(verdict["chain_boundary"]), 1)
        self.assertEqual(verdict["chain_boundary"][0]["reason"],
                         "authentication_failed")
        self.assertEqual(verdict["lineage"]["edges"], [])


class EpochEvidenceEndpointTests(unittest.TestCase):
    def setUp(self):
        VERDICTS.clear()

    def tearDown(self):
        VERDICTS.clear()

    def _chain(self):
        return submit("lineage-a", SECRET3, [
            appdata(SECRET3, 3, 0),
            ku(SECRET3, 3, 1),
            appdata(SECRET4, 4, 0),
        ])

    def test_established_epochs_return_evidence(self):
        self._chain()
        r3 = epoch_generation_evidence("lineage-a", 3)
        self.assertEqual(r3["evidence"]["origin"], "initial_traffic_secret")
        r4 = epoch_generation_evidence("lineage-a", 4)
        self.assertEqual(r4["evidence"]["origin"], "authenticated_key_update")
        self.assertEqual(r4["established_epochs"], [3, 4])

    def test_unknown_audit_refused_without_leaking_others(self):
        self._chain()
        submit("lineage-b", SECRET4, [appdata(SECRET4, 7, 0)], initial_epoch=7)
        with self.assertRaises(HTTPException) as ctx:
            epoch_generation_evidence("lineage-x", 3)
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(ctx.exception.detail,
                         "no frozen verdict for this audit id")

    def test_unestablished_epoch_refused_and_lists_only_this_audit(self):
        self._chain()
        # another audit has epoch 7: it must not make epoch 7 valid here,
        # nor appear in the refusal detail
        submit("lineage-b", SECRET4, [appdata(SECRET4, 7, 0)], initial_epoch=7)
        with self.assertRaises(HTTPException) as ctx:
            epoch_generation_evidence("lineage-a", 7)
        self.assertEqual(ctx.exception.status_code, 404)
        detail = ctx.exception.detail
        self.assertEqual(detail["error"], "epoch_not_established")
        self.assertEqual(detail["established_epochs"], [3, 4])
        self.assertEqual(detail["audit_id"], "lineage-a")
        # audit B is unaffected and still serves only its own epochs
        rb = epoch_generation_evidence("lineage-b", 7)
        self.assertEqual(rb["established_epochs"], [7])
        self.assertEqual(rb["audit_id"], "lineage-b")

    def test_epoch_out_of_range_refused(self):
        self._chain()
        for bad in (-1, 65536):
            with self.assertRaises(HTTPException) as ctx:
                epoch_generation_evidence("lineage-a", bad)
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertEqual(ctx.exception.detail["error"],
                             "epoch_out_of_range")

    def test_resubmission_replaces_old_lineage_evidence(self):
        self._chain()  # establishes 3, 4
        # resubmit with a capture that never ratchets
        submit("lineage-a", SECRET3, [appdata(SECRET3, 3, 0)])
        epoch_generation_evidence("lineage-a", 3)  # still valid
        with self.assertRaises(HTTPException) as ctx:
            epoch_generation_evidence("lineage-a", 4)  # old edge cleared
        self.assertEqual(ctx.exception.detail["error"],
                         "epoch_not_established")
        self.assertEqual(ctx.exception.detail["established_epochs"], [3])

    def test_response_contains_no_raw_secret(self):
        self._chain()
        for epoch in (3, 4):
            payload = json.dumps(
                epoch_generation_evidence("lineage-a", epoch), sort_keys=True)
            self.assertNotIn(SECRET3.hex(), payload)
            self.assertNotIn(SECRET4.hex(), payload)


if __name__ == "__main__":
    unittest.main()
