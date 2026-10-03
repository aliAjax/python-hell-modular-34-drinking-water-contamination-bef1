from datetime import datetime


class DomainError(Exception):
    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code = code
        self.status = status


class ConflictError(DomainError):
    def __init__(self, code, message):
        super().__init__(code, message, 409)


class NotFoundError(DomainError):
    def __init__(self, code, message):
        super().__init__(code, message, 404)


def require_text(payload, name):
    value = payload.get(name)
    if not isinstance(value, str) or not value.strip():
        raise DomainError("field_required", "%s 不能为空" % name)
    return value.strip()


def number(payload, name, minimum=None):
    value = payload.get(name)
    if isinstance(value, bool):
        raise DomainError("invalid_number", "%s 必须是数字" % name)
    try:
        value = float(value)
    except (TypeError, ValueError):
        raise DomainError("invalid_number", "%s 必须是数字" % name)
    if minimum is not None and value < minimum:
        raise DomainError("invalid_number", "%s 不能小于 %s" % (name, minimum))
    return value


def parse_timestamp(payload, name):
    value = require_text(payload, name)
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise DomainError("invalid_timestamp", "%s 必须是 ISO 时间" % name)
    return value


def normalize_create(payload):
    source_id = require_text(payload, "source_id")
    contaminant = require_text(payload, "contaminant")
    detected_at = parse_timestamp(payload, "detected_at")
    concentration = number(payload, "concentration", 0)
    limit = number(payload, "limit", 0.000001)
    zones = payload.get("zone_ids", [])
    if not isinstance(zones, list) or not zones:
        raise DomainError("zones_required", "至少需要一个受影响区域")
    if any(not isinstance(zone, str) or not zone.strip() for zone in zones):
        raise DomainError("invalid_zones", "区域编号必须是字符串列表")
    population = int(payload.get("population", 0) or 0)
    if population < 0:
        raise DomainError("invalid_population", "受影响人数不能为负数")
    stable_key = "%s|%s|%s" % (source_id, contaminant, detected_at)
    return {
        "source_id": source_id,
        "contaminant": contaminant,
        "detected_at": detected_at,
        "concentration": concentration,
        "limit": limit,
        "zone_ids": [zone.strip() for zone in zones],
        "population": population,
        "complaints": int(payload.get("complaints", 0) or 0),
        "notifications": [],
        "response_actions": [],
        "sample_results": [],
        "_stable_key": stable_key,
    }


def normalize_source(payload):
    source_type = require_text(payload, "source_type")
    external_id = require_text(payload, "external_id")
    observed_at = parse_timestamp(payload, "observed_at")
    result = {
        "source_type": source_type,
        "external_id": external_id,
        "observed_at": observed_at,
        "concentration": number(payload, "concentration", 0) if "concentration" in payload else None,
        "zone_id": payload.get("zone_id"),
        "note": payload.get("note", ""),
    }
    return result


def normalize_reconcile(payload):
    batch_id = require_text(payload, "batch_id")
    region = require_text(payload, "region")
    items = payload.get("items", [])
    if not isinstance(items, list):
        raise DomainError("invalid_batch", "items 必须是列表")
    normalized_items = []
    for snap in items:
        if not isinstance(snap, dict):
            raise DomainError("invalid_batch", "每条补录记录必须是对象")
        stable_key = require_text(snap, "stable_key")
        snap_region = snap.get("region") or region
        version = snap.get("version")
        if version is not None:
            try:
                version = int(version)
            except (TypeError, ValueError):
                raise DomainError("invalid_batch", "version 必须是整数")
        snap_payload = snap.get("payload", {})
        if not isinstance(snap_payload, dict):
            raise DomainError("invalid_batch", "payload 必须是对象")
        normalized_items.append({
            "stable_key": stable_key,
            "region": snap_region,
            "status": snap.get("status"),
            "version": version,
            "payload": snap_payload,
            "created_at": snap.get("created_at"),
        })
    sources = payload.get("sources", [])
    if not isinstance(sources, list):
        raise DomainError("invalid_batch", "sources 必须是列表")
    return {
        "batch_id": batch_id,
        "region": region,
        "items": normalized_items,
        "sources": sources,
    }


def normalize_pair(payload):
    item_id = payload.get("item_id")
    other_id = payload.get("other_item_id")
    if not isinstance(item_id, int) or not isinstance(other_id, int):
        raise DomainError("invalid_pair", "item_id 和 other_item_id 必须是整数")
    return {"item_id": item_id, "other_item_id": other_id}
