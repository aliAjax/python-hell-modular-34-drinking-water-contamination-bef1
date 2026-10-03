import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.repository import Repository
from src.service import Service
from src.domain import ConflictError, DomainError


BASE_PAYLOAD = {
    "source_id": "SRC-X",
    "contaminant": "nitrate",
    "detected_at": "2026-10-01T06:00:00+00:00",
    "concentration": 18,
    "limit": 10,
    "zone_ids": ["Z-1"],
    "population": 3000,
}


def advance(service, item_id, region, actor_prefix, zone_id, version, concentration=2, restore=True):
    """把一条立案推进到（或接近）恢复，通知编号由调用方决定。"""
    version = service.act(item_id, "verify", {"sample_count": 1},
                          "%s-analyst" % actor_prefix, "analyst", version, region)["version"]
    version = service.act(item_id, "advise",
                          {"notice_id": "N-%s" % region, "kind": "boil", "message": "煮沸"},
                          "%s-disp" % actor_prefix, "dispatcher", version, region)["version"]
    version = service.act(item_id, "switch_source", {"alternate_source_id": "ALT-%s" % region},
                          "%s-coord" % actor_prefix, "coordinator", version, region)["version"]
    version = service.act(item_id, "flush", {"zone_id": zone_id},
                          "%s-field" % actor_prefix, "field_operator", version, region)["version"]
    version = service.act(item_id, "disinfect", {"zone_id": zone_id, "completed": True},
                          "%s-field" % actor_prefix, "field_operator", version, region)["version"]
    version = service.act(item_id, "sample",
                          {"sample_id": "S-%s" % region, "zone_id": zone_id, "concentration": concentration},
                          "%s-lab" % actor_prefix, "lab", version, region)["version"]
    if restore:
        version = service.act(item_id, "restore", {"all_zones_cleared": True},
                              "%s-coord" % actor_prefix, "coordinator", version, region)["version"]
    return version


class CrossRegionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.repo = Repository(self.tmp.name)
        self.repo.initialize()
        self.service = Service(self.repo)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_duplicate_filings_in_two_regions_link_as_one_incident(self):
        east = self.service.create_item(dict(BASE_PAYLOAD, region="EAST"), "a1", "analyst", region="EAST")
        west = self.service.create_item(dict(BASE_PAYLOAD, region="WEST"), "a2", "analyst", region="WEST")
        self.assertNotEqual(east["id"], west["id"])

        incident = self.service.link_incident([east["id"], west["id"]], {"reason": "同一起跨界污染"},
                                              "reg-1", "regulator", region="HQ")
        self.assertEqual(sorted(incident["member_ids"]), sorted([east["id"], west["id"]]))

        fetched = self.service.get_item(east["id"], "reg-1", "regulator", "HQ")
        self.assertEqual(fetched["incident"]["group_id"], incident["group_id"])
        # 配对审计在两个区的记录上都能看到。
        types_east = {event["event_type"] for event in fetched["audit"]}
        self.assertIn("incident_linked", types_east)
        fetched_west = self.service.get_item(west["id"], "reg-1", "regulator", "HQ")
        self.assertIn("incident_linked", {event["event_type"] for event in fetched_west["audit"]})

        # 重复配对幂等，不会建第二个事件组。
        again = self.service.link_incident([west["id"], east["id"]], {}, "reg-1", "regulator", region="HQ")
        self.assertEqual(again["group_id"], incident["group_id"])

    def test_notice_id_sent_only_once_across_linked_regions(self):
        east = self.service.create_item(dict(BASE_PAYLOAD, region="EAST"), "a1", "analyst", region="EAST")
        west = self.service.create_item(dict(BASE_PAYLOAD, region="WEST"), "a2", "analyst", region="WEST")
        self.service.link_incident([east["id"], west["id"]], {}, "reg-1", "regulator", region="HQ")

        east = self.service.act(east["id"], "verify", {"sample_count": 1}, "a1", "analyst",
                                east["version"], "EAST")
        west = self.service.act(west["id"], "verify", {"sample_count": 1}, "a2", "analyst",
                                west["version"], "WEST")
        east = self.service.act(east["id"], "advise",
                                {"notice_id": "N-SHARED", "kind": "boil", "message": "煮沸"},
                                "d1", "dispatcher", east["version"], "EAST")
        # 另一个区用同一通知编号再发一次，必须被挡住。
        with self.assertRaises(DomainError) as context:
            self.service.act(west["id"], "advise",
                             {"notice_id": "N-SHARED", "kind": "boil", "message": "煮沸"},
                             "d2", "dispatcher", west["version"], "WEST")
        self.assertEqual(context.exception.code, "duplicate_notification")

    def test_restore_blocked_until_every_linked_region_passes_samples(self):
        east = self.service.create_item(dict(BASE_PAYLOAD, region="EAST"), "a1", "analyst", region="EAST")
        west = self.service.create_item(dict(BASE_PAYLOAD, region="WEST"), "a2", "analyst", region="WEST")
        self.service.link_incident([east["id"], west["id"]], {}, "reg-1", "regulator", region="HQ")

        # 东区全部达标，西区只做到消毒、还没复检：东区也不能恢复。
        advance(self.service, east["id"], "EAST", "e", "Z-1", 1, restore=False)
        v_e = self.repo.get_item(east["id"])["version"]
        v_w = west["version"]
        v_w = self.service.act(west["id"], "verify", {"sample_count": 1}, "a2", "analyst", v_w, "WEST")["version"]
        v_w = self.service.act(west["id"], "advise",
                               {"notice_id": "N-WEST", "kind": "boil", "message": "煮沸"},
                               "d2", "dispatcher", v_w, "WEST")["version"]
        v_w = self.service.act(west["id"], "switch_source", {"alternate_source_id": "ALT-W"},
                               "c2", "coordinator", v_w, "WEST")["version"]
        v_w = self.service.act(west["id"], "flush", {"zone_id": "Z-2"}, "f2", "field_operator", v_w, "WEST")["version"]
        v_w = self.service.act(west["id"], "disinfect", {"zone_id": "Z-2", "completed": True},
                               "f2", "field_operator", v_w, "WEST")["version"]

        with self.assertRaises(DomainError) as context:
            self.service.act(east["id"], "restore", {"all_zones_cleared": True},
                             "c1", "coordinator", v_e, "EAST")
        self.assertEqual(context.exception.code, "linked_regions_not_cleared")
        blocked = context.exception.details["blocked"]
        self.assertEqual([entry["region"] for entry in blocked], ["WEST"])
        self.assertIn("missing_samples", blocked[0]["reasons"])

        # 西区复检超标，仍然挡住并指明哪个区不达标。
        v_w = self.service.act(west["id"], "sample",
                               {"sample_id": "S-W", "zone_id": "Z-2", "concentration": 15},
                               "l2", "lab", v_w, "WEST")["version"]
        with self.assertRaises(DomainError) as context:
            self.service.act(east["id"], "restore", {"all_zones_cleared": True},
                             "c1", "coordinator", v_e, "EAST")
        blocked = context.exception.details["blocked"]
        self.assertEqual([entry["region"] for entry in blocked], ["WEST"])
        self.assertIn("quality_not_met", blocked[0]["reasons"])
        self.assertEqual(context.exception.details["missing_regions"], ["WEST"])

    def test_restore_allowed_once_all_linked_regions_pass(self):
        east = self.service.create_item(dict(BASE_PAYLOAD, region="EAST"), "a1", "analyst", region="EAST")
        west = self.service.create_item(dict(BASE_PAYLOAD, region="WEST"), "a2", "analyst", region="WEST")
        self.service.link_incident([east["id"], west["id"]], {}, "reg-1", "regulator", region="HQ")

        # 两个区都走到采样且全部达标后，恢复才放行。
        v_e = advance(self.service, east["id"], "EAST", "e", "Z-1", 1, restore=False)
        v_w = advance(self.service, west["id"], "WEST", "w", "Z-2", 1, restore=False)
        east_after = self.service.act(east["id"], "restore", {"all_zones_cleared": True},
                                      "c1", "coordinator", v_e, "EAST")
        self.assertEqual(east_after["status"], "restored")
        west_after = self.service.act(west["id"], "restore", {"all_zones_cleared": True},
                                      "c2", "coordinator", v_w, "WEST")
        self.assertEqual(west_after["status"], "restored")

    def test_regulator_cross_region_regular_role_denied(self):
        east = self.service.create_item(dict(BASE_PAYLOAD, region="EAST"), "a1", "analyst", region="EAST")
        west = self.service.create_item(dict(BASE_PAYLOAD, region="WEST"), "a2", "analyst", region="WEST")

        # 普通角色访问本区域以外的记录：权限拒绝。
        with self.assertRaises(DomainError) as context:
            self.service.get_item(west["id"], "a1", "analyst", "EAST")
        self.assertEqual(context.exception.code, "region_access_denied")
        self.assertEqual(context.exception.status, 403)
        with self.assertRaises(DomainError) as context:
            self.service.act(west["id"], "verify", {"sample_count": 1},
                             "a1", "analyst", 1, "EAST")
        self.assertEqual(context.exception.code, "region_access_denied")

        # 列表/总览对普通角色只返回本区域。
        visible = self.service.list_items(None, "a1", "analyst", "EAST")
        self.assertEqual([item["id"] for item in visible], [east["id"]])

        # 普通协调角色不能跨区配对。
        with self.assertRaises(DomainError) as context:
            self.service.link_incident([east["id"], west["id"]], {}, "c1", "coordinator", "EAST")
        self.assertEqual(context.exception.code, "region_access_denied")

        # 监管角色可以跨区读取、配对并跨区下达处置（恢复）。
        linked = self.service.link_incident([east["id"], west["id"]], {}, "reg-1", "regulator", "HQ")
        self.assertEqual(len(linked["member_ids"]), 2)
        advance(self.service, east["id"], "EAST", "e", "Z-1", 1, restore=False)
        advance(self.service, west["id"], "WEST", "w", "Z-2", 1, restore=False)
        east_version = self.repo.get_item(east["id"])["version"]
        restored = self.service.act(east["id"], "restore", {"all_zones_cleared": True},
                                    "reg-1", "regulator", east_version, "HQ")
        self.assertEqual(restored["status"], "restored")


class ReconciliationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.repo = Repository(self.tmp.name)
        self.repo.initialize()
        self.service = Service(self.repo)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def _offline_filed_batch(self, region="EAST"):
        return {
            "region": region,
            "batch_id": "B-1",
            "entries": [
                {"seq": 20, "external_id": "EXT-A2", "op": "create",
                 "payload": dict(BASE_PAYLOAD, source_id="SRC-LATER", region=region)},
                {"seq": 10, "external_id": "EXT-A1", "op": "create",
                 "payload": dict(BASE_PAYLOAD, region=region)},
                {"seq": 30, "external_id": "EXT-S1", "op": "source", "item_ref": "EXT-A1",
                 "payload": {"source_type": "pipe", "external_id": "P-1",
                             "observed_at": "2026-10-01T05:00:00+00:00", "note": "断网期间本地登记"}},
            ],
        }

    def test_offline_entries_merge_in_original_order(self):
        result = self.service.replay_batch(self._offline_filed_batch(), "sync-1", "analyst", "EAST")
        statuses = [(entry["seq"], entry["status"]) for entry in result["entries"]]
        # 按原始 seq 升序补录，而不是网络包顺序。
        self.assertEqual([seq for seq, _ in statuses], [10, 20, 30])
        self.assertEqual(result["applied"], 3)
        self.assertEqual(result["duplicate"], 0)
        self.assertEqual(result["pending"], 0)

        first = result["entries"][0]["result"]
        third = result["entries"][2]["result"]
        self.assertEqual(third["item_id"], first["item_id"])
        # 来源记录确实落在先补录的立案上。
        sources = self.repo.list_sources(first["item_id"])
        self.assertEqual([source["external_id"] for source in sources], ["P-1"])

    def test_region_plus_external_id_applied_once_and_repeated_batch_returns_first_result(self):
        batch = self._offline_filed_batch()
        first = self.service.replay_batch(batch, "sync-1", "analyst", "EAST")
        first_item = first["entries"][0]["result"]["item_id"]

        # 同区域、同外部编号的立案再来一次（哪怕内容不同），只入账一次。
        second_batch = {
            "region": "EAST",
            "batch_id": "B-2",
            "entries": [
                {"seq": 1, "external_id": "EXT-A1", "op": "create",
                 "payload": dict(BASE_PAYLOAD, concentration=99)},
                {"seq": 2, "external_id": "EXT-A1", "op": "create",
                 "payload": dict(BASE_PAYLOAD, concentration=120)},
            ],
        }
        second = self.service.replay_batch(second_batch, "sync-1", "analyst", "EAST")
        self.assertTrue(all(entry["status"] == "duplicate" for entry in second["entries"]))
        self.assertEqual(second["entries"][0]["result"]["item_id"], first_item)
        # 原记录不被重复内容覆盖。
        self.assertEqual(self.repo.get_item(first_item)["payload"]["concentration"], 18)

        # 重复批次（同区域同批次号）拿回第一次的结果。
        repeated = self.service.replay_batch(batch, "sync-1", "analyst", "EAST")
        self.assertTrue(repeated["duplicate_batch"])
        self.assertEqual(repeated["total"], first["total"])
        self.assertEqual([e["status"] for e in repeated["entries"]],
                         [e["status"] for e in first["entries"]])
        # 没有重复建来源。
        self.assertEqual(len(self.repo.list_sources(first_item)), 1)

    def test_backfill_audit_origin_marker(self):
        self.service.replay_batch(self._offline_filed_batch(), "sync-1", "analyst", "EAST")
        entry = self.repo.get_entry("EAST", "EXT-A1")
        item_id = entry["result"]["item_id"]
        created = [event for event in self.repo.audit_trail(item_id) if event["event_type"] == "created"][0]
        self.assertEqual(created["payload"]["_origin"]["kind"], "backfill")
        self.assertEqual(created["payload"]["_origin"]["batch_id"], "B-1")
        self.assertEqual(created["payload"]["_origin"]["external_id"], "EXT-A1")

        # 在线直接创建的记录审计里没有补录标记。
        live = self.service.create_item(dict(BASE_PAYLOAD, source_id="SRC-LIVE", region="EAST"),
                                        "a9", "analyst", "EAST")
        live_created = [event for event in self.repo.audit_trail(live["id"])
                        if event["event_type"] == "created"][0]
        self.assertNotIn("_origin", live_created["payload"])

    def test_version_conflict_backfill_keeps_record_and_goes_pending(self):
        live = self.service.create_item(dict(BASE_PAYLOAD, region="EAST"), "a9", "analyst", "EAST")
        verified = self.service.act(live["id"], "verify", {"sample_count": 1},
                                    "a9", "analyst", live["version"], "EAST")
        current_version = verified["version"]

        # 断网端基于旧版本 1 生成的通知补录：版本对不上。
        batch = {
            "region": "EAST",
            "batch_id": "B-STALE",
            "entries": [
                {"seq": 1, "external_id": "EXT-OLD-ADVISE", "op": "action",
                 "item_ref": live["id"], "action": "advise",
                 "expected_version": 1,
                 "payload": {"notice_id": "N-OFFLINE", "kind": "boil", "message": "断网通知"}},
            ],
        }
        result = self.service.replay_batch(batch, "d1", "dispatcher", "EAST")
        self.assertEqual(result["pending"], 1)
        self.assertEqual(result["entries"][0]["error_code"], "version_conflict")

        # 既有记录保持原样（未被补录推进），原始补录留在待处理里。
        item = self.repo.get_item(live["id"])
        self.assertEqual(item["version"], current_version)
        self.assertEqual(item["status"], "verified")
        pending = self.service.list_pending("d1", "dispatcher", "EAST")["pending"]
        self.assertEqual([row["external_id"] for row in pending], ["EXT-OLD-ADVISE"])
        self.assertEqual(pending[0]["entry"]["payload"]["notice_id"], "N-OFFLINE")

        # 用新版本号重放同一外部编号：待处理记录可以重试并最终入账。
        retry = {
            "region": "EAST",
            "batch_id": "B-RETRY",
            "entries": [
                {"seq": 1, "external_id": "EXT-OLD-ADVISE", "op": "action",
                 "item_ref": live["id"], "action": "advise",
                 "expected_version": current_version,
                 "payload": {"notice_id": "N-OFFLINE", "kind": "boil", "message": "断网通知"}},
            ],
        }
        retried = self.service.replay_batch(retry, "d1", "dispatcher", "EAST")
        self.assertEqual(retried["entries"][0]["status"], "applied")
        self.assertEqual(self.service.list_pending("d1", "dispatcher", "EAST")["pending"], [])

    def test_pending_visibility_respects_region(self):
        for region, batch_id in [("EAST", "B-E"), ("WEST", "B-W")]:
            self.service.replay_batch({
                "region": region,
                "batch_id": batch_id,
                "entries": [
                    {"seq": 1, "external_id": "EXT-BAD-%s" % region, "op": "weird",
                     "payload": {}},
                ],
            }, "sync", "analyst", region)

        east_pending = self.service.list_pending("a", "analyst", "EAST")["pending"]
        self.assertEqual([row["region"] for row in east_pending], ["EAST"])
        all_pending = self.service.list_pending("r", "regulator", "HQ")["pending"]
        self.assertEqual(sorted(row["region"] for row in all_pending), ["EAST", "WEST"])

    def test_backfill_cross_region_notice_and_restore_gate(self):
        east = self.service.create_item(dict(BASE_PAYLOAD, region="EAST"), "a1", "analyst", "EAST")
        west = self.service.create_item(dict(BASE_PAYLOAD, region="WEST"), "a2", "analyst", region="WEST")
        self.service.link_incident([east["id"], west["id"]], {}, "reg-1", "regulator", "HQ")
        east = self.service.act(east["id"], "verify", {"sample_count": 1}, "a1", "analyst",
                                east["version"], "EAST")
        west = self.service.act(west["id"], "verify", {"sample_count": 1}, "a2", "analyst",
                                west["version"], "WEST")

        # 断网期间东区本地发了共享通知，回网补录成功。
        self.service.replay_batch({
            "region": "EAST",
            "batch_id": "B-NOTICE",
            "entries": [
                {"seq": 1, "external_id": "EXT-N1", "op": "action",
                 "item_ref": east["id"], "action": "advise", "expected_version": east["version"],
                 "payload": {"notice_id": "N-JOINT", "kind": "boil", "message": "联合通知"}},
            ],
        }, "d1", "dispatcher", "EAST")

        # 西区在线再用同一通知编号：跨区去重依旧生效。
        with self.assertRaises(DomainError) as context:
            self.service.act(west["id"], "advise",
                             {"notice_id": "N-JOINT", "kind": "boil", "message": "联合通知"},
                             "d2", "dispatcher", west["version"], "WEST")
        self.assertEqual(context.exception.code, "duplicate_notification")

    def test_batch_requires_region_and_identity(self):
        with self.assertRaises(DomainError) as context:
            self.service.replay_batch({"batch_id": "B", "entries": []}, "", "", None)
        self.assertEqual(context.exception.status, 401)
        with self.assertRaises(DomainError) as context:
            self.service.replay_batch({"batch_id": "B", "entries": []}, "a", "analyst")
        self.assertEqual(context.exception.code, "region_required")


if __name__ == "__main__":
    unittest.main()
