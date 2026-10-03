from . import domain, rules
from .domain import DomainError, ConflictError

REPLAY_ORIGIN_KIND = "backfill"


class Service:
    def __init__(self, repository):
        self.repository = repository

    # ---- 权限与管辖 ----

    def _identity(self, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)

    def _deny_outside_region(self, item_region, region, role):
        # 监管角色可以跨区；普通角色访问本区域以外的记录一律权限拒绝。
        if role == rules.REGIONLESS_ROLE:
            return
        if rules.ENFORCE_REGION and region and item_region and item_region != region:
            raise DomainError("region_access_denied", "本区域以外的记录返回权限拒绝", 403)

    def _visible(self, item, actor=None, role=None, region=None):
        if actor is None:
            return True
        if role == rules.REGIONLESS_ROLE or not region:
            return True
        item_region = item["payload"].get("region")
        return not item_region or item_region == region

    # ---- 用例 ----

    def create_item(self, payload, actor, role, region=None, origin=None):
        self._identity(actor, role)
        if role not in rules.CREATE_ROLES:
            raise DomainError("forbidden", "当前角色不能创建此类业务记录", 403)
        normalized = domain.normalize_create(payload)
        self._deny_outside_region(normalized.get("region"), region, role)
        stable_key = normalized.pop("_stable_key")
        return self.repository.create_item(
            rules.ENTITY_TYPE, stable_key, rules.INITIAL_STATUS, normalized, actor, role, origin
        )

    def add_source(self, item_id, payload, actor, role, region=None, origin=None):
        self._identity(actor, role)
        if role not in rules.SOURCE_ROLES:
            raise DomainError("forbidden", "当前角色不能提交来源记录", 403)
        item = self.repository.get_item(item_id)
        self._deny_outside_region(item["payload"].get("region"), region, role)
        normalized = domain.normalize_source(payload)
        result = self.repository.add_source(
            item_id,
            normalized.pop("source_type"),
            normalized.pop("external_id"),
            normalized,
            normalized.pop("observed_at"),
            actor,
            role,
            origin,
        )
        return result

    def act(self, item_id, action, payload, actor, role, expected_version=None, region=None, origin=None):
        self._identity(actor, role)
        item = self.repository.get_item(item_id)
        allowed = rules.ACTION_ROLES.get(action, set())
        if role not in allowed:
            raise DomainError("forbidden", "当前角色不能执行该操作", 403)
        self._deny_outside_region(item["payload"].get("region"), region, role)
        if action in rules.ACTION_REQUIRES_VERSION and expected_version is None:
            raise DomainError("expected_version_required", "该操作需要 expected_version", 400)
        self._apply_guarded(item, action, payload, actor, role, expected_version, origin)
        return self.get_item(item_id)

    def _apply_guarded(self, item, action, payload, actor, role, expected_version, origin):
        item_id = item["id"]
        incident = self.repository.get_incident_for_item(item_id)
        member_items = None
        if incident:
            member_items = [self.repository.get_item(mid) for mid in incident["member_ids"]]

        # 配对以后，同一通知编号在整个联动事件（两个区）里只发一次。
        if action == "advise":
            notice_id = (payload.get("notice_id") or "").strip()
            if notice_id:
                for member in member_items or [item]:
                    if member["id"] == item_id:
                        continue
                    if any(n.get("notice_id") == notice_id for n in member["payload"].get("notifications", [])):
                        raise ConflictError("duplicate_notification", "该通知编号已由联动区发送，不能重复发送")

        # 任一联动区的复检样本没有全部达标，就挡住恢复，并列出缺哪个区。
        if action == "restore" and member_items:
            blocked = self._uncleared_members(member_items)
            if blocked:
                raise DomainError(
                    "linked_regions_not_cleared",
                    "联动区域复检未全部达标，暂不能恢复",
                    409,
                    details={"blocked": blocked, "missing_regions": [entry["region"] for entry in blocked]},
                )

        new_status, new_payload, event_payload = rules.apply_action(item, action, payload, actor, role)
        self.repository.apply_action(
            item_id, action, actor, role, new_status, new_payload, event_payload, expected_version, origin
        )
        return self.repository.get_item(item_id)

    def _uncleared_members(self, member_items):
        blocked = []
        for member in member_items:
            payload = member["payload"]
            limit = max(float(payload.get("limit", 0) or 0), 0.000001)
            results = payload.get("sample_results", [])
            reasons = []
            if not results:
                reasons.append("missing_samples")
            if any(float(result.get("concentration", 0)) > limit for result in results):
                reasons.append("quality_not_met")
            if reasons:
                blocked.append(
                    {
                        "item_id": member["id"],
                        "region": payload.get("region") or ("区域#%d" % member["id"]),
                        "reasons": reasons,
                        "limit": limit,
                        "sample_count": len(results),
                    }
                )
        return blocked

    # ---- 查询 ----

    def get_item(self, item_id, actor=None, role=None, region=None):
        item = self.repository.get_item(item_id)
        if actor is not None:
            self._identity(actor, role)
            self._deny_outside_region(item["payload"].get("region"), region, role)
        item["sources"] = self.repository.list_sources(item_id)
        item["audit"] = self.repository.audit_trail(item_id)
        item["assessment"] = rules.assess(item["payload"])
        item["incident"] = self.repository.get_incident_for_item(item_id)
        return item

    def list_items(self, status=None, actor=None, role=None, region=None):
        items = self.repository.list_items(status)
        if actor is not None:
            self._identity(actor, role)
        return [item for item in items if self._visible(item, actor, role, region)]

    def state(self, actor=None, role=None, region=None):
        summary = self.repository.state_summary()
        if actor is not None:
            self._identity(actor, role)
        items = [item for item in summary["items"] if self._visible(item, actor, role, region)]
        counts = {}
        for item in items:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
        return {"counts": counts, "items": items}

    # ---- 跨区配对：两条立案接成同一件污染事件 ----

    def link_incident(self, item_ids, payload, actor, role, region=None):
        self._identity(actor, role)
        if role not in rules.LINK_ROLES:
            raise DomainError("forbidden", "当前角色不能配对跨区污染事件", 403)
        if not isinstance(item_ids, list) or not item_ids:
            raise DomainError("item_ids_required", "需要提供待配对的记录编号")
        items = [self.repository.get_item(int(item_id)) for item_id in item_ids]
        if role != rules.REGIONLESS_ROLE:
            # 普通协调角色只能在本区域内配对；跨区配对由监管角色下达。
            for item in items:
                self._deny_outside_region(item["payload"].get("region"), region, role)
        reason = ""
        if isinstance(payload, dict):
            reason = str(payload.get("reason", "") or "")
        linked = self.repository.link_items(item_ids, actor, role, reason)
        return self.get_item(linked["member_ids"][0], actor, role, region)["incident"]

    # ---- 跨区对账：断网留存、回网补录 ----

    def replay_batch(self, payload, actor, role, region=None):
        self._identity(actor, role)
        if not isinstance(payload, dict):
            raise DomainError("invalid_batch", "批处理必须是对象")
        batch_id = str(payload.get("batch_id", "") or "").strip()
        if not batch_id:
            raise DomainError("batch_id_required", "补录批次需要 batch_id")
        batch_region = str(payload.get("region", "") or region or "").strip()
        if not batch_region:
            raise DomainError("region_required", "补录批次需要区域编号")
        if role != rules.REGIONLESS_ROLE and region and batch_region != region:
            self._deny_outside_region(batch_region, region, role)

        # 重复批次：整个批次只处理一次，重放拿回第一次的结果。
        cached = self.repository.get_batch(batch_region, batch_id)
        if cached is not None:
            result = dict(cached["result"])
            result["duplicate_batch"] = True
            return result

        entries = payload.get("entries")
        if not isinstance(entries, list) or not entries:
            raise DomainError("entries_required", "补录批次至少包含一条记录")
        ordered = sorted(
            range(len(entries)),
            key=lambda index: self._seq_key(entries[index], index),
        )

        results = []
        for order, index in enumerate(ordered):
            results.append(
                self._replay_entry(batch_region, batch_id, index, order, entries[index], actor, role)
            )

        result = {
            "region": batch_region,
            "batch_id": batch_id,
            "duplicate_batch": False,
            "total": len(results),
            "applied": sum(1 for r in results if r["status"] == "applied"),
            "duplicate": sum(1 for r in results if r["status"] == "duplicate"),
            "pending": sum(1 for r in results if r["status"] == "pending"),
            "entries": results,
        }
        return self.repository.save_batch(batch_region, batch_id, result)

    def _seq_key(self, entry, index):
        if isinstance(entry, dict):
            seq = entry.get("seq", index)
            if isinstance(seq, int) and not isinstance(seq, bool):
                return seq
        return index

    def _replay_entry(self, batch_region, batch_id, index, order, entry, submitter_actor, submitter_role):
        seq = entry.get("seq", index) if isinstance(entry, dict) else index
        if not isinstance(entry, dict):
            return self._quarantine(batch_region, batch_id, seq, "unknown", entry, None, None,
                                   "invalid_entry", "补录条目必须是对象")
        external_id = str(entry.get("external_id", "") or "").strip()
        if not external_id:
            raise DomainError("external_id_required", "补录条目需要外部编号（第 %d 条）" % (index + 1))
        op = str(entry.get("op", "") or "").strip()
        if op not in {"create", "source", "action"}:
            return self._quarantine(batch_region, batch_id, seq, op, entry, external_id, None,
                                   "unknown_op", "不支持的补录操作: %r" % op)

        existing = self.repository.get_entry(batch_region, external_id)
        if existing is not None and existing["status"] in {"applied", "duplicate"}:
            # 区域编号 + 外部编号相同的只入账一次；重放拿回第一次的结果。
            return {
                "seq": seq,
                "order": order,
                "op": op,
                "external_id": external_id,
                "status": "duplicate",
                "result": existing["result"],
            }

        entry_actor = str(entry.get("actor", "") or submitter_actor).strip()
        entry_role = str(entry.get("role", "") or submitter_role).strip()
        origin = {
            "kind": REPLAY_ORIGIN_KIND,
            "region": batch_region,
            "batch_id": batch_id,
            "external_id": external_id,
            "seq": seq,
        }
        try:
            if op == "create":
                result = self._replay_create(batch_region, entry, entry_actor, entry_role, origin)
            elif op == "source":
                result = self._replay_source(batch_region, entry, entry_actor, entry_role, origin)
            else:
                result = self._replay_action(batch_region, entry, entry_actor, entry_role, origin)
        except ConflictError as exc:
            if exc.code == "version_conflict":
                # 版本对不上：保留原记录不动，补录转待处理。
                return self._quarantine(batch_region, batch_id, seq, op, entry, external_id, None,
                                        exc.code, str(exc))
            if exc.code in {"duplicate_item", "duplicate_source", "duplicate_notification"}:
                result = self._duplicate_result(op, exc)
                self.repository.mark_entry(
                    batch_region, external_id, batch_id, seq, op, entry, "duplicate", result
                )
                return self._entry_summary(seq, order, op, external_id, "duplicate", result)
            return self._quarantine(batch_region, batch_id, seq, op, entry, external_id, None,
                                    exc.code, str(exc))
        except DomainError as exc:
            return self._quarantine(batch_region, batch_id, seq, op, entry, external_id, None,
                                    exc.code, str(exc))

        self.repository.mark_entry(
            batch_region, external_id, batch_id, seq, op, entry, "applied", result
        )
        return self._entry_summary(seq, order, op, external_id, "applied", result)

    def _replay_create(self, batch_region, entry, actor, role, origin):
        payload = dict(entry.get("payload") or {})
        payload.setdefault("region", batch_region)
        item = self.create_item(payload, actor, role, batch_region, origin)
        return {"item_id": item["id"], "status": item["status"], "version": item["version"]}

    def _replay_source(self, batch_region, entry, actor, role, origin):
        item_id = self._resolve_ref(batch_region, entry.get("item_ref"))
        payload = dict(entry.get("payload") or {})
        source = self.add_source(item_id, payload, actor, role, batch_region, origin)
        return {"item_id": item_id, "source_id": source["id"], "external_id": source["external_id"]}

    def _replay_action(self, batch_region, entry, actor, role, origin):
        item_id = self._resolve_ref(batch_region, entry.get("item_ref"))
        action = str(entry.get("action", "") or "").strip()
        if not action:
            raise DomainError("action_required", "补录操作缺少 action")
        payload = dict(entry.get("payload") or {})
        expected_version = entry.get("expected_version")
        item = self.repository.get_item(item_id)
        allowed = rules.ACTION_ROLES.get(action, set())
        if role not in allowed:
            raise DomainError("forbidden", "当前角色不能执行该操作")
        if action in rules.ACTION_REQUIRES_VERSION and expected_version is None:
            raise DomainError("expected_version_required", "该操作需要 expected_version")
        updated = self._apply_guarded(item, action, payload, actor, role, expected_version, origin)
        return {"item_id": item_id, "action": action, "status": updated["status"], "version": updated["version"]}

    def _resolve_ref(self, batch_region, ref):
        if ref is None:
            raise DomainError("item_ref_required", "补录条目需要 item_ref 指向立案记录")
        try:
            return int(ref)
        except (TypeError, ValueError):
            pass
        referenced = self.repository.get_entry(batch_region, str(ref))
        if referenced is None or referenced["status"] != "applied" or not referenced.get("result"):
            raise DomainError("unresolved_reference", "引用的立案补录尚未入账: %s" % ref)
        return referenced["result"]["item_id"]

    def _duplicate_result(self, op, exc):
        result = {"deduplicated": True, "reason": exc.code}
        details = getattr(exc, "details", None)
        if details:
            result["details"] = details
        return result

    def _quarantine(self, batch_region, batch_id, seq, op, entry, external_id, result, code, message):
        # 转待处理：原始补录条目完整保留，不改动既有业务记录。
        if external_id:
            self.repository.mark_entry(
                batch_region, external_id, batch_id,
                seq if isinstance(seq, int) else 0, op, entry, "pending", result, code, message
            )
            return {
                "seq": seq,
                "op": op,
                "external_id": external_id,
                "status": "pending",
                "error_code": code,
                "error_message": message,
            }
        return {"seq": seq, "op": op, "status": "pending", "error_code": code, "error_message": message}

    def _entry_summary(self, seq, order, op, external_id, status, result):
        return {
            "seq": seq,
            "order": order,
            "op": op,
            "external_id": external_id,
            "status": status,
            "result": result,
        }

    def list_pending(self, actor, role, region=None):
        self._identity(actor, role)
        scope = None if role == rules.REGIONLESS_ROLE else region
        return {"pending": self.repository.list_pending_entries(scope)}
