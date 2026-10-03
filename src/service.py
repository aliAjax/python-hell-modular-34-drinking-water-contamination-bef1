from . import domain, rules
from .domain import DomainError


class Service:
    def __init__(self, repository):
        self.repository = repository

    def _identity(self, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)

    def _ensure_region_access(self, item, region, role):
        """Ordinary roles may only touch records linked to their own region.

        Regulators can act across regions. Records outside the caller's region
        are rejected with 403.
        """
        if not region or role == "regulator":
            return
        if not rules.ENFORCE_REGION:
            return
        regions = rules.linked_regions(item["payload"])
        if region not in regions:
            raise DomainError("region_mismatch", "不能处理本区域以外的记录", 403)

    def create_item(self, payload, actor, role, region=None):
        self._identity(actor, role)
        if role not in rules.CREATE_ROLES:
            raise DomainError("forbidden", "当前角色不能创建此类业务记录", 403)
        normalized = domain.normalize_create(payload)
        stable_key = normalized.pop("_stable_key")
        normalized["region"] = region or ""
        normalized["regions"] = [region or ""]
        return self.repository.create_item(
            rules.ENTITY_TYPE, stable_key, rules.INITIAL_STATUS, normalized, actor, role, region or ""
        )

    def add_source(self, item_id, payload, actor, role, region=None):
        self._identity(actor, role)
        if role not in rules.SOURCE_ROLES:
            raise DomainError("forbidden", "当前角色不能提交来源记录", 403)
        item = self.repository.get_item(item_id)
        self._ensure_region_access(item, region, role)
        normalized = domain.normalize_source(payload)
        result = self.repository.add_source(
            item_id,
            normalized.pop("source_type"),
            normalized.pop("external_id"),
            normalized,
            normalized.pop("observed_at"),
            actor,
            role,
            region or "",
        )
        return result

    def act(self, item_id, action, payload, actor, role, expected_version=None, region=None):
        self._identity(actor, role)
        item = self.repository.get_item(item_id)
        allowed = rules.ACTION_ROLES.get(action, set())
        if role not in allowed:
            raise DomainError("forbidden", "当前角色不能执行该操作", 403)
        self._ensure_region_access(item, region, role)
        if action in rules.ACTION_REQUIRES_VERSION and expected_version is None:
            raise DomainError("expected_version_required", "该操作需要 expected_version", 400)
        if action == "sample" and region and not payload.get("region"):
            payload["region"] = region
        new_status, new_payload, event_payload = rules.apply_action(
            item, action, payload, actor, role, region
        )
        self.repository.apply_action(
            item_id, action, actor, role, new_status, new_payload, event_payload, expected_version
        )
        return self.get_item(item_id)

    def get_item(self, item_id, actor=None, role=None, region=None):
        if actor is not None or role is not None:
            self._identity(actor, role)
        item = self.repository.get_item(item_id)
        if actor is not None and role is not None:
            self._ensure_region_access(item, region, role)
        item["sources"] = self.repository.list_sources(item_id)
        item["audit"] = self.repository.audit_trail(item_id)
        item["assessment"] = rules.assess(item["payload"])
        return item

    def list_items(self, status=None):
        return self.repository.list_items(status)

    def state(self):
        return self.repository.state_summary()

    # ----- cross-region reconciliation -----

    def pair(self, item_id, other_id, actor, role, region=None):
        """Explicitly merge two records of the same event from different districts."""
        self._identity(actor, role)
        if role != "regulator":
            raise DomainError("forbidden", "只有监管角色可以跨区配对记录", 403)
        item = self.repository.get_item(item_id)
        other = self.repository.get_item(other_id)
        if item["stable_key"] != other["stable_key"]:
            raise DomainError("stable_key_mismatch", "两起事件的关键标识不一致，不能配对", 400)
        if item["id"] == other["id"]:
            return item
        survivor = item if item["id"] < other["id"] else other
        merged = other if survivor is item else item
        return self.repository.pair_items(survivor["id"], merged["id"], actor, role)

    def reconcile(self, payload, actor, role, region=None):
        """Offline-first backfill: push a district's local batch to merge centrally.

        The batch is idempotent (batch_id is the key). Records are replayed in
        their original order. Same (region, external_id) is recorded once.
        Version mismatches keep the original record and go to pending.
        """
        self._identity(actor, role)
        batch = domain.normalize_reconcile(payload)
        batch_id = batch["batch_id"]
        batch_region = batch["region"]
        if region and role != "regulator" and batch_region != region:
            raise DomainError("region_mismatch", "不能补录其他区域的数据", 403)
        existing = self.repository.get_batch(batch_id)
        if existing is not None:
            return existing["result"]
        result = {
            "batch_id": batch_id,
            "region": batch_region,
            "created": [],
            "merged": [],
            "duplicates": [],
            "pending": [],
            "sources": [],
        }
        for snap in batch["items"]:
            self._reconcile_item(snap, actor, role, batch_id, result)
        for source in batch.get("sources", []):
            self._reconcile_source(source, batch_region, actor, role, result)
        self.repository.record_batch(batch_id, batch_region, result)
        return result

    def _reconcile_item(self, snap, actor, role, batch_id, result):
        stable_key = snap["stable_key"]
        snap_region = snap["region"]
        snap_version = snap.get("version")
        existing = self.repository.find_items_by_key(rules.ENTITY_TYPE, stable_key)
        if not existing:
            payload = snap["payload"]
            payload["region"] = snap_region
            payload.setdefault("regions", [snap_region])
            item = self.repository.create_item(
                rules.ENTITY_TYPE,
                stable_key,
                snap.get("status") or rules.INITIAL_STATUS,
                payload,
                actor,
                role,
                snap_region,
            )
            if snap_version is not None:
                self.repository.set_item_version(item["id"], snap_version)
            self.repository.mark_backfilled(
                item["id"], actor, role, {"batch_id": batch_id, "region": snap_region, "backfilled": True}
            )
            result["created"].append(
                {"stable_key": stable_key, "item_id": item["id"], "region": snap_region}
            )
            return
        same_region = [it for it in existing if it["region"] == snap_region]
        if same_region:
            survivor = same_region[0]
            if snap_version is not None and snap_version > survivor["version"]:
                # Same district pushing a newer state: merge the update.
                merged = self.repository.merge_snapshot(survivor["id"], snap, actor, role, batch_id)
                result["merged"].append(
                    {"stable_key": stable_key, "item_id": merged["id"], "region": snap_region}
                )
            else:
                # Same event already filed in this region at this version: idempotent.
                result["duplicates"].append(
                    {"stable_key": stable_key, "item_id": survivor["id"], "region": snap_region}
                )
            return
        survivor = existing[0]
        # Cross-district: only merge when the snapshot is based on the current version.
        if snap_version is not None and snap_version != survivor["version"]:
            # Version mismatch: keep the original record, route to pending.
            pending_id = self.repository.add_pending(
                batch_id, stable_key, snap_region, "version_conflict", snap
            )
            result["pending"].append(
                {
                    "pending_id": pending_id,
                    "stable_key": stable_key,
                    "region": snap_region,
                    "reason": "version_conflict",
                }
            )
            return
        merged = self.repository.merge_snapshot(survivor["id"], snap, actor, role, batch_id)
        result["merged"].append(
            {"stable_key": stable_key, "item_id": merged["id"], "region": snap_region}
        )

    def _reconcile_source(self, source, region, actor, role, result):
        if not isinstance(source, dict):
            return
        stable_key = source.get("stable_key")
        external_id = source.get("external_id")
        source_type = source.get("source_type")
        if not stable_key or not external_id or not source_type:
            return
        existing = self.repository.find_items_by_key(rules.ENTITY_TYPE, stable_key)
        if not existing:
            return
        survivor = existing[0]
        added = self.repository.add_source(
            survivor["id"],
            source_type,
            external_id,
            source.get("payload", {}),
            source.get("observed_at", ""),
            actor,
            role,
            region,
        )
        result["sources"].append(
            {"external_id": external_id, "item_id": survivor["id"], "region": region, "source_id": added["id"]}
        )

    def list_pending(self, status=None, actor=None, role=None):
        if actor is not None or role is not None:
            self._identity(actor, role)
        return self.repository.list_pending(status)

    def resolve_pending(self, pending_id, action, actor, role):
        self._identity(actor, role)
        if role != "regulator":
            raise DomainError("forbidden", "只有监管角色可以处理待补录", 403)
        pending = self.repository.get_pending(pending_id)
        if action == "discard":
            self.repository.resolve_pending(pending_id, "discarded")
            return {"id": pending_id, "status": "discarded"}
        if action != "accept":
            raise DomainError("invalid_action", "不支持的待处理操作", 400)
        snap = pending["snapshot"]
        stable_key = snap["stable_key"]
        snap_region = snap["region"]
        existing = self.repository.find_items_by_key(rules.ENTITY_TYPE, stable_key)
        if existing:
            survivor = existing[0]
            merged = self.repository.merge_snapshot(survivor["id"], snap, actor, role, pending["batch_id"])
            self.repository.resolve_pending(pending_id, "accepted")
            return {"id": pending_id, "status": "accepted", "item": merged}
        payload = snap["payload"]
        payload["region"] = snap_region
        payload.setdefault("regions", [snap_region])
        item = self.repository.create_item(
            rules.ENTITY_TYPE,
            stable_key,
            snap.get("status") or rules.INITIAL_STATUS,
            payload,
            actor,
            role,
            snap_region,
        )
        self.repository.resolve_pending(pending_id, "accepted")
        return {"id": pending_id, "status": "accepted", "item": item}
