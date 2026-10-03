import os
import sys
import json
import tempfile
import unittest
import threading
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.repository import Repository
from src.service import Service
from src.domain import ConflictError, DomainError
from src.http_api import build_handler


class ReconcileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.repo = Repository(self.tmp.name)
        self.repo.initialize()
        self.service = Service(self.repo)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def _payload(self, **overrides):
        payload = {
            "source_id": "SRC-1",
            "contaminant": "nitrate",
            "detected_at": "2026-09-27T06:00:00+00:00",
            "concentration": 20,
            "limit": 10,
            "zone_ids": ["Z-1"],
            "population": 5000,
            "complaints": 4,
        }
        payload.update(overrides)
        return payload

    def _advance_to_sampled(self, item, region):
        """Run the response workflow up to the sampled status, returning the item."""
        svc = self.service
        item = svc.act(item["id"], "verify", {"sample_count": 1}, "a", "analyst", item["version"], region=region)
        item = svc.act(item["id"], "advise", {"notice_id": "N-1", "kind": "boil", "message": "煮沸"}, "d", "dispatcher", item["version"], region=region)
        item = svc.act(item["id"], "switch_source", {"alternate_source_id": "ALT-1"}, "c", "coordinator", item["version"], region=region)
        item = svc.act(item["id"], "flush", {"zone_id": "Z-1"}, "f", "field_operator", item["version"], region=region)
        item = svc.act(item["id"], "disinfect", {"zone_id": "Z-1", "completed": True}, "f", "field_operator", item["version"], region=region)
        item = svc.act(item["id"], "sample", {"sample_id": "S-1", "zone_id": "Z-1", "concentration": 2}, "l", "lab", item["version"], region=region)
        return item

    # ----- pairing -----

    def test_pair_merges_two_districts_into_one_event(self):
        item1 = self.service.create_item(self._payload(), "a1", "analyst", region="R-1")
        item2 = self.service.create_item(self._payload(), "a2", "analyst", region="R-2")
        survivor = self.service.pair(item1["id"], item2["id"], "reg", "regulator")
        self.assertEqual(survivor["id"], item1["id"])
        self.assertEqual(survivor["payload"]["regions"], ["R-1", "R-2"])
        # the merged-away record now resolves to the survivor
        resolved = self.service.get_item(item2["id"])
        self.assertEqual(resolved["id"], item1["id"])

    def test_pair_requires_regulator(self):
        item1 = self.service.create_item(self._payload(), "a1", "analyst", region="R-1")
        item2 = self.service.create_item(self._payload(), "a2", "analyst", region="R-2")
        with self.assertRaises(DomainError) as context:
            self.service.pair(item1["id"], item2["id"], "a1", "analyst")
        self.assertEqual(context.exception.code, "forbidden")

    def test_pair_rejects_mismatched_keys(self):
        item1 = self.service.create_item(self._payload(), "a1", "analyst", region="R-1")
        item2 = self.service.create_item(self._payload(source_id="SRC-OTHER"), "a2", "analyst", region="R-2")
        with self.assertRaises(DomainError) as context:
            self.service.pair(item1["id"], item2["id"], "reg", "regulator")
        self.assertEqual(context.exception.code, "stable_key_mismatch")

    def test_notification_dedup_across_districts_after_pairing(self):
        item1 = self.service.create_item(self._payload(), "a1", "analyst", region="R-1")
        item2 = self.service.create_item(self._payload(), "a2", "analyst", region="R-2")
        survivor = self.service.pair(item1["id"], item2["id"], "reg", "regulator")
        item = self.service.get_item(survivor["id"])
        item = self.service.act(item["id"], "verify", {"sample_count": 1}, "a", "analyst", item["version"], region="R-1")
        item = self.service.act(item["id"], "advise", {"notice_id": "N-1", "kind": "boil", "message": "x"}, "d", "dispatcher", item["version"], region="R-1")
        with self.assertRaises(DomainError) as context:
            self.service.act(item["id"], "advise", {"notice_id": "N-1", "kind": "boil", "message": "y"}, "d", "dispatcher", item["version"], region="R-2")
        self.assertEqual(context.exception.code, "duplicate_notification")
        self.assertEqual(len(item["payload"]["notifications"]), 1)

    def test_restore_blocked_when_linked_district_samples_fail(self):
        item1 = self.service.create_item(self._payload(), "a1", "analyst", region="R-1")
        item2 = self.service.create_item(self._payload(zone_ids=["Z-2"]), "a2", "analyst", region="R-2")
        survivor = self.service.pair(item1["id"], item2["id"], "reg", "regulator")
        item = self.service.get_item(survivor["id"])
        item = self._advance_to_sampled(item, "R-1")
        # R-2 contributes a failing re-inspection sample
        item = self.service.act(item["id"], "sample", {"sample_id": "S-2", "zone_id": "Z-2", "concentration": 15}, "l", "lab", item["version"], region="R-2")
        with self.assertRaises(DomainError) as context:
            self.service.act(item["id"], "restore", {"all_zones_cleared": True}, "c", "coordinator", item["version"], region="R-1")
        self.assertEqual(context.exception.code, "quality_not_met")
        self.assertIn("R-2", str(context.exception))

    def test_restore_allowed_when_all_linked_districts_pass(self):
        item1 = self.service.create_item(self._payload(), "a1", "analyst", region="R-1")
        item2 = self.service.create_item(self._payload(zone_ids=["Z-2"]), "a2", "analyst", region="R-2")
        survivor = self.service.pair(item1["id"], item2["id"], "reg", "regulator")
        item = self.service.get_item(survivor["id"])
        item = self._advance_to_sampled(item, "R-1")
        item = self.service.act(item["id"], "sample", {"sample_id": "S-2", "zone_id": "Z-2", "concentration": 1}, "l", "lab", item["version"], region="R-2")
        item = self.service.act(item["id"], "restore", {"all_zones_cleared": True}, "c", "coordinator", item["version"], region="R-1")
        self.assertEqual(item["status"], "restored")

    # ----- region enforcement -----

    def test_ordinary_role_denied_out_of_region(self):
        item = self.service.create_item(self._payload(), "a1", "analyst", region="R-1")
        with self.assertRaises(DomainError) as context:
            self.service.act(item["id"], "verify", {"sample_count": 1}, "a", "analyst", item["version"], region="R-3")
        self.assertEqual(context.exception.code, "region_mismatch")
        self.assertEqual(context.exception.status, 403)

    def test_regulator_can_act_across_regions(self):
        item = self.service.create_item(self._payload(), "a1", "analyst", region="R-1")
        item = self.service.act(item["id"], "verify", {"sample_count": 1}, "a", "analyst", item["version"], region="R-1")
        # regulator based in R-9 can still advise on the R-1 record
        item = self.service.act(item["id"], "advise", {"notice_id": "N-1", "kind": "boil", "message": "x"}, "reg", "regulator", item["version"], region="R-9")
        self.assertEqual(item["status"], "advisory")

    def test_reconcile_rejects_other_region_batch(self):
        batch = {
            "batch_id": "B-X",
            "region": "R-2",
            "items": [],
        }
        with self.assertRaises(DomainError) as context:
            self.service.reconcile(batch, "a", "analyst", region="R-1")
        self.assertEqual(context.exception.code, "region_mismatch")

    # ----- reconcile -----

    def _batch(self, batch_id, region, stable_key, **overrides):
        payload = self._payload(**overrides)
        return {
            "batch_id": batch_id,
            "region": region,
            "items": [{
                "stable_key": stable_key,
                "region": region,
                "status": "detected",
                "version": 1,
                "payload": payload,
            }],
        }

    def test_reconcile_first_filing_creates_item(self):
        stable_key = "water_contamination|SRC-1|nitrate|2026-09-27T06:00:00+00:00"
        result = self.service.reconcile(self._batch("B-1", "R-1", stable_key), "a", "analyst", region="R-1")
        self.assertEqual(len(result["created"]), 1)
        self.assertEqual(result["created"][0]["region"], "R-1")
        item = self.service.get_item(result["created"][0]["item_id"])
        self.assertEqual(item["region"], "R-1")

    def test_reconcile_duplicate_batch_returns_first_result(self):
        stable_key = "water_contamination|SRC-1|nitrate|2026-09-27T06:00:00+00:00"
        batch = self._batch("B-2", "R-1", stable_key)
        first = self.service.reconcile(batch, "a", "analyst", region="R-1")
        second = self.service.reconcile(batch, "a", "analyst", region="R-1")
        self.assertEqual(first, second)

    def test_reconcile_same_event_different_region_merges(self):
        stable_key = "water_contamination|SRC-1|nitrate|2026-09-27T06:00:00+00:00"
        r1 = self.service.reconcile(self._batch("B-3", "R-1", stable_key), "a", "analyst", region="R-1")
        r2 = self.service.reconcile(self._batch("B-4", "R-2", stable_key, zone_ids=["Z-2"]), "a", "analyst", region="R-2")
        self.assertEqual(len(r2["merged"]), 1)
        item = self.service.get_item(r1["created"][0]["item_id"])
        self.assertEqual(item["payload"]["regions"], ["R-1", "R-2"])
        self.assertIn("Z-2", item["payload"]["zone_ids"])

    def test_reconcile_same_region_same_event_is_duplicate(self):
        stable_key = "water_contamination|SRC-1|nitrate|2026-09-27T06:00:00+00:00"
        self.service.reconcile(self._batch("B-5", "R-1", stable_key), "a", "analyst", region="R-1")
        again = self.service.reconcile(self._batch("B-6", "R-1", stable_key), "a", "analyst", region="R-1")
        self.assertEqual(len(again["duplicates"]), 1)
        self.assertEqual(len(again["created"]), 0)

    def test_reconcile_same_region_newer_state_merges(self):
        stable_key = "water_contamination|SRC-1|nitrate|2026-09-27T06:00:00+00:00"
        self.service.reconcile(self._batch("B-5a", "R-1", stable_key), "a", "analyst", region="R-1")
        updated = self._batch("B-5b", "R-1", stable_key)
        updated["items"][0]["version"] = 2
        updated["items"][0]["status"] = "advisory"
        updated["items"][0]["payload"]["notifications"] = [
            {"notice_id": "N-9", "kind": "boil", "message": "更新通知"}
        ]
        result = self.service.reconcile(updated, "a", "analyst", region="R-1")
        self.assertEqual(len(result["merged"]), 1)
        item = self.service.get_item(result["merged"][0]["item_id"])
        self.assertEqual(item["status"], "advisory")
        self.assertEqual([n["notice_id"] for n in item["payload"]["notifications"]], ["N-9"])

    def test_reconcile_version_mismatch_goes_pending(self):
        stable_key = "water_contamination|SRC-1|nitrate|2026-09-27T06:00:00+00:00"
        self.service.reconcile(self._batch("B-7", "R-1", stable_key), "a", "analyst", region="R-1")
        stale = self._batch("B-8", "R-2", stable_key)
        stale["items"][0]["version"] = 99
        result = self.service.reconcile(stale, "a", "analyst", region="R-2")
        self.assertEqual(len(result["pending"]), 1)
        self.assertEqual(result["pending"][0]["reason"], "version_conflict")
        # the original record is unchanged
        item = self.service.get_item(result["pending"][0]["item_id"] if "item_id" in result["pending"][0] else 1)
        self.assertEqual(item["region"], "R-1")

    def test_reconcile_audit_shows_backfilled(self):
        stable_key = "water_contamination|SRC-1|nitrate|2026-09-27T06:00:00+00:00"
        result = self.service.reconcile(self._batch("B-9", "R-1", stable_key), "a", "analyst", region="R-1")
        item = self.service.get_item(result["created"][0]["item_id"])
        events = [(e["event_type"], e["payload"].get("backfilled")) for e in item["audit"]]
        self.assertIn(("backfilled", True), events)

    def test_reconcile_source_dedup_by_region_and_external_id(self):
        stable_key = "water_contamination|SRC-1|nitrate|2026-09-27T06:00:00+00:00"
        batch = self._batch("B-10", "R-1", stable_key)
        batch["sources"] = [{
            "stable_key": stable_key, "source_type": "tap", "external_id": "EXT-1",
            "payload": {"note": "first"}, "observed_at": "2026-09-27T06:00:00+00:00",
        }]
        self.service.reconcile(batch, "a", "analyst", region="R-1")
        again = self.service.reconcile(batch, "a", "analyst", region="R-1")
        item = self.service.get_item(again["sources"][0]["item_id"])
        self.assertEqual(len(item["sources"]), 1)

    def test_pending_resolve_accept_merges_snapshot(self):
        stable_key = "water_contamination|SRC-1|nitrate|2026-09-27T06:00:00+00:00"
        self.service.reconcile(self._batch("B-11", "R-1", stable_key), "a", "analyst", region="R-1")
        stale = self._batch("B-12", "R-2", stable_key, zone_ids=["Z-2"])
        stale["items"][0]["version"] = 99
        self.service.reconcile(stale, "a", "analyst", region="R-2")
        pending = self.service.list_pending()[0]
        result = self.service.resolve_pending(pending["id"], "accept", "reg", "regulator")
        self.assertEqual(result["status"], "accepted")
        item = self.service.get_item(result["item"]["id"])
        self.assertIn("R-2", item["payload"]["regions"])

    def test_pending_resolve_discard(self):
        stable_key = "water_contamination|SRC-1|nitrate|2026-09-27T06:00:00+00:00"
        self.service.reconcile(self._batch("B-13", "R-1", stable_key), "a", "analyst", region="R-1")
        stale = self._batch("B-14", "R-2", stable_key)
        stale["items"][0]["version"] = 99
        self.service.reconcile(stale, "a", "analyst", region="R-2")
        pending = self.service.list_pending()[0]
        result = self.service.resolve_pending(pending["id"], "discard", "reg", "regulator")
        self.assertEqual(result["status"], "discarded")

    def test_pending_requires_regulator(self):
        stable_key = "water_contamination|SRC-1|nitrate|2026-09-27T06:00:00+00:00"
        self.service.reconcile(self._batch("B-15", "R-1", stable_key), "a", "analyst", region="R-1")
        stale = self._batch("B-16", "R-2", stable_key)
        stale["items"][0]["version"] = 99
        self.service.reconcile(stale, "a", "analyst", region="R-2")
        pending = self.service.list_pending()[0]
        with self.assertRaises(DomainError) as context:
            self.service.resolve_pending(pending["id"], "accept", "a", "analyst")
        self.assertEqual(context.exception.code, "forbidden")


class HttpRegionEnforcementTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.repo = Repository(self.tmp.name)
        self.repo.initialize()
        self.service = Service(self.repo)
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(self.service, os.path.join(os.path.dirname(os.path.dirname(__file__)), "static"))
        )
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        os.unlink(self.tmp.name)

    def _request(self, method, path, body=None, headers=None):
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.port, path), method=method)
        if body is not None:
            req.data = json.dumps(body).encode()
            req.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def _payload(self):
        return {
            "source_id": "SRC-1",
            "contaminant": "nitrate",
            "detected_at": "2026-09-27T06:00:00+00:00",
            "concentration": 20,
            "limit": 10,
            "zone_ids": ["Z-1"],
            "population": 5000,
        }

    def test_get_item_out_of_region_denied(self):
        headers = {"X-User-Id": "a", "X-Role": "analyst", "X-Region": "R-1"}
        status, body = self._request("POST", "/api/items", self._payload(), headers)
        self.assertEqual(status, 201)
        item_id = body["id"]
        # analyst from R-3 cannot read R-1's record
        status, body = self._request("GET", "/api/items/%d" % item_id, headers={"X-User-Id": "a", "X-Role": "analyst", "X-Region": "R-3"})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "region_mismatch")
        # regulator can read across regions
        status, body = self._request("GET", "/api/items/%d" % item_id, headers={"X-User-Id": "r", "X-Role": "regulator", "X-Region": "R-9"})
        self.assertEqual(status, 200)

    def test_reconcile_endpoint_merges_across_regions(self):
        headers = {"X-User-Id": "a", "X-Role": "analyst", "X-Region": "R-1"}
        status, body = self._request("POST", "/api/items", self._payload(), headers)
        self.assertEqual(status, 201)
        item_id = body["id"]
        stable_key = body["stable_key"]
        # R-2 pushes a backfill for the same event
        status, body = self._request("POST", "/api/reconcile", {
            "batch_id": "B-HTTP-1",
            "region": "R-2",
            "items": [{
                "stable_key": stable_key,
                "region": "R-2",
                "status": "detected",
                "version": 1,
                "payload": dict(self._payload(), zone_ids=["Z-2"]),
            }],
        }, {"X-User-Id": "a2", "X-Role": "analyst", "X-Region": "R-2"})
        self.assertEqual(status, 200)
        self.assertEqual(len(body["merged"]), 1)
        # the merged record now links both regions
        status, body = self._request("GET", "/api/items/%d" % item_id, headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(body["payload"]["regions"], ["R-1", "R-2"])


if __name__ == "__main__":
    unittest.main()
