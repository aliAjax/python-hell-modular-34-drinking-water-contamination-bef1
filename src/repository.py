import json
import sqlite3
from datetime import datetime, timezone

from .audit import audit_hash, canonical_json
from .domain import ConflictError, NotFoundError, DomainError


def now_iso():
    return datetime.now(timezone.utc).isoformat()


class Repository:
    def __init__(self, path):
        self.path = path

    def connect(self):
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self):
        conn = self.connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    stable_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    payload TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(entity_type, stable_key)
                );
                CREATE TABLE IF NOT EXISTS sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    source_type TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, source_type, external_id),
                    FOREIGN KEY(item_id) REFERENCES items(id)
                );
                CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    role TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(item_id) REFERENCES items(id)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER,
                    event_type TEXT NOT NULL,
                    actor TEXT,
                    role TEXT,
                    payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incident_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reason TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL,
                    created_role TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incident_members (
                    group_id INTEGER NOT NULL,
                    item_id INTEGER NOT NULL,
                    joined_at TEXT NOT NULL,
                    PRIMARY KEY(item_id),
                    FOREIGN KEY(group_id) REFERENCES incident_groups(id),
                    FOREIGN KEY(item_id) REFERENCES items(id)
                );
                CREATE TABLE IF NOT EXISTS reconciliation_batches (
                    region TEXT NOT NULL,
                    batch_id TEXT NOT NULL,
                    result TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(region, batch_id)
                );
                CREATE TABLE IF NOT EXISTS reconciliation_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    region TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    batch_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    op TEXT NOT NULL,
                    entry TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result TEXT,
                    error_code TEXT,
                    error_message TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(region, external_id)
                );
                """
            )
        finally:
            conn.close()

    def _row_to_item(self, row):
        if row is None:
            return None
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result

    def _last_hash(self, conn, item_id):
        row = conn.execute(
            "SELECT event_hash FROM audit_events WHERE item_id IS ? ORDER BY id DESC LIMIT 1",
            (item_id,),
        ).fetchone()
        return row["event_hash"] if row else "GENESIS"

    def append_audit(self, conn, item_id, event_type, actor, role, payload, origin=None):
        previous = self._last_hash(conn, item_id)
        # 补录（断网回传）的事件在审计里带 _origin 标记，
        # 审计链可以直接区分哪些记录来自跨区对账补录。
        if origin:
            payload = dict(payload)
            payload["_origin"] = origin
        event = {
            "item_id": item_id,
            "event_type": event_type,
            "actor": actor,
            "role": role,
            "payload": payload,
            "created_at": now_iso(),
        }
        event_hash = audit_hash(previous, event)
        conn.execute(
            "INSERT INTO audit_events(item_id,event_type,actor,role,payload,previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (item_id, event_type, actor, role, canonical_json(payload), previous, event_hash, event["created_at"]),
        )

    def create_item(self, entity_type, stable_key, initial_status, payload, actor, role, origin=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "INSERT INTO items(entity_type,stable_key,status,version,payload,created_by,created_role,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        entity_type,
                        stable_key,
                        initial_status,
                        1,
                        canonical_json(payload),
                        actor,
                        role,
                        now_iso(),
                        now_iso(),
                    ),
                )
            except sqlite3.IntegrityError:
                raise ConflictError("duplicate_item", "同一业务实体已经存在")
            item_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            self.append_audit(conn, item_id, "created", actor, role, {"stable_key": stable_key}, origin)
            conn.execute("COMMIT")
            return self.get_item(item_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def get_item(self, item_id):
        conn = self.connect()
        try:
            row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            return self._row_to_item(row)
        finally:
            conn.close()

    def item_region(self, item_id):
        conn = self.connect()
        try:
            row = conn.execute("SELECT payload FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            return (json.loads(row["payload"]) or {}).get("region")
        finally:
            conn.close()

    def list_items(self, status=None):
        conn = self.connect()
        try:
            if status:
                rows = conn.execute("SELECT * FROM items WHERE status=? ORDER BY id DESC", (status,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM items ORDER BY id DESC").fetchall()
            return [self._row_to_item(row) for row in rows]
        finally:
            conn.close()

    def add_source(self, item_id, source_type, external_id, payload, observed_at, actor, role, origin=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            item = conn.execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone()
            if item is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            try:
                conn.execute(
                    "INSERT INTO sources(item_id,source_type,external_id,payload,observed_at,created_at) VALUES(?,?,?,?,?,?)",
                    (item_id, source_type, external_id, canonical_json(payload), observed_at, now_iso()),
                )
            except sqlite3.IntegrityError:
                raise ConflictError("duplicate_source", "同一来源记录已经提交")
            source_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            self.append_audit(
                conn,
                item_id,
                "source_recorded",
                actor,
                role,
                {"source_id": source_id, "source_type": source_type, "external_id": external_id},
                origin,
            )
            conn.execute("COMMIT")
            return {"id": source_id, "item_id": item_id, "source_type": source_type, "external_id": external_id, "payload": payload, "observed_at": observed_at}
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def list_sources(self, item_id):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM sources WHERE item_id=? ORDER BY id DESC", (item_id,)).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                result.append(value)
            return result
        finally:
            conn.close()

    def apply_action(self, item_id, action, actor, role, new_status, new_payload, event_payload, expected_version=None, origin=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            if expected_version is not None and int(expected_version) != int(row["version"]):
                raise ConflictError("version_conflict", "记录已被其他操作更新，请重新读取")
            version = int(row["version"]) + 1
            conn.execute(
                "UPDATE items SET status=?,version=?,payload=?,updated_at=? WHERE id=?",
                (new_status, version, canonical_json(new_payload), now_iso(), item_id),
            )
            conn.execute(
                "INSERT INTO actions(item_id,action,actor,role,payload,created_at) VALUES(?,?,?,?,?,?)",
                (item_id, action, actor, role, canonical_json(event_payload), now_iso()),
            )
            self.append_audit(conn, item_id, action, actor, role, event_payload, origin)
            conn.execute("COMMIT")
            return self.get_item(item_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def audit_trail(self, item_id):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM audit_events WHERE item_id=? ORDER BY id", (item_id,)).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                result.append(value)
            return result
        finally:
            conn.close()

    # ---- 跨区配对：把各区独立立案接成同一件污染事件 ----

    def link_items(self, item_ids, actor, role, reason=""):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            ids = []
            for raw in item_ids:
                try:
                    value = int(raw)
                except (TypeError, ValueError):
                    raise DomainError("invalid_item_id", "记录编号必须是整数")
                if value not in ids:
                    ids.append(value)
            if len(ids) < 2:
                raise DomainError("link_requires_two", "至少需要两条记录才能配对")
            rows = conn.execute(
                "SELECT i.id AS item_id, m.group_id AS group_id FROM items i LEFT JOIN incident_members m ON m.item_id=i.id WHERE i.id IN (%s)" % ",".join("?" * len(ids)),
                ids,
            ).fetchall()
            found = {row["item_id"]: row["group_id"] for row in rows}
            missing = [item_id for item_id in ids if item_id not in found]
            if missing:
                raise NotFoundError("item_not_found", "业务实体不存在: %s" % ",".join(str(x) for x in missing))
            existing_groups = {group_id for group_id in found.values() if group_id is not None}
            if len(existing_groups) > 1:
                raise ConflictError("groups_conflict", "这些记录已经分属不同污染事件，不能配对")
            if len(existing_groups) == 1:
                group_id = next(iter(existing_groups))
            else:
                now = now_iso()
                conn.execute(
                    "INSERT INTO incident_groups(reason,created_by,created_role,created_at) VALUES(?,?,?,?)",
                    (reason, actor, role, now),
                )
                group_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            now = now_iso()
            for item_id in ids:
                conn.execute(
                    "INSERT OR IGNORE INTO incident_members(group_id,item_id,joined_at) VALUES(?,?,?)",
                    (group_id, item_id, now),
                )
            member_ids = [
                row["item_id"]
                for row in conn.execute(
                    "SELECT item_id FROM incident_members WHERE group_id=? ORDER BY item_id", (group_id,)
                ).fetchall()
            ]
            for item_id in ids:
                self.append_audit(
                    conn,
                    item_id,
                    "incident_linked",
                    actor,
                    role,
                    {"group_id": group_id, "member_ids": member_ids, "reason": reason},
                )
            conn.execute("COMMIT")
            return {"group_id": group_id, "member_ids": member_ids}
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def get_incident_for_item(self, item_id):
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT group_id FROM incident_members WHERE item_id=?", (item_id,)
            ).fetchone()
            if row is None:
                return None
            group_id = row["group_id"]
            member_ids = [
                r["item_id"]
                for r in conn.execute(
                    "SELECT item_id FROM incident_members WHERE group_id=? ORDER BY item_id", (group_id,)
                ).fetchall()
            ]
            return {"group_id": group_id, "member_ids": member_ids}
        finally:
            conn.close()

    # ---- 跨区对账：断网本地留存，回网后按原始顺序补录 ----

    def get_batch(self, region, batch_id):
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT * FROM reconciliation_batches WHERE region=? AND batch_id=?",
                (region, batch_id),
            ).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["result"] = json.loads(result["result"])
            return result
        finally:
            conn.close()

    def save_batch(self, region, batch_id, result):
        conn = self.connect()
        try:
            conn.execute(
                "INSERT INTO reconciliation_batches(region,batch_id,result,created_at) VALUES(?,?,?,?)",
                (region, batch_id, canonical_json(result), now_iso()),
            )
            return result
        except sqlite3.IntegrityError:
            existing = self.get_batch(region, batch_id)
            return existing["result"] if existing else result
        finally:
            conn.close()

    def get_entry(self, region, external_id):
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT * FROM reconciliation_entries WHERE region=? AND external_id=?",
                (region, external_id),
            ).fetchone()
            if row is None:
                return None
            value = dict(row)
            value["result"] = json.loads(value["result"]) if value["result"] else None
            value["entry"] = json.loads(value["entry"])
            return value
        finally:
            conn.close()

    def _store_entry(self, conn, region, external_id, batch_id, seq, op, entry, status, result, error_code, error_message):
        # 已入账（applied/duplicate）的外部编号不允许覆盖；只有 pending 的记录会被重试更新。
        conn.execute(
            """
            INSERT INTO reconciliation_entries(region,external_id,batch_id,seq,op,entry,status,result,error_code,error_message,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(region, external_id) DO UPDATE SET
                batch_id=excluded.batch_id,
                seq=excluded.seq,
                op=excluded.op,
                entry=excluded.entry,
                status=excluded.status,
                result=excluded.result,
                error_code=excluded.error_code,
                error_message=excluded.error_message,
                updated_at=excluded.updated_at
            WHERE reconciliation_entries.status='pending'
            """,
            (
                region,
                external_id,
                batch_id,
                seq,
                op,
                canonical_json(entry),
                status,
                canonical_json(result) if result is not None else None,
                error_code,
                error_message,
                now_iso(),
                now_iso(),
            ),
        )

    def mark_entry(self, region, external_id, batch_id, seq, op, entry, status, result=None, error_code=None, error_message=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._store_entry(conn, region, external_id, batch_id, seq, op, entry, status, result, error_code, error_message)
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def get_entry_raw(self, region, external_id):
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT entry FROM reconciliation_entries WHERE region=? AND external_id=?",
                (region, external_id),
            ).fetchone()
            return json.loads(row["entry"]) if row else None
        finally:
            conn.close()

    def list_pending_entries(self, region=None):
        conn = self.connect()
        try:
            if region:
                rows = conn.execute(
                    "SELECT * FROM reconciliation_entries WHERE status='pending' AND region=? ORDER BY id",
                    (region,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM reconciliation_entries WHERE status='pending' ORDER BY id"
                ).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["result"] = json.loads(value["result"]) if value["result"] else None
                value["entry"] = json.loads(value["entry"])
                result.append(value)
            return result
        finally:
            conn.close()

    def state_summary(self):
        conn = self.connect()
        try:
            counts = {}
            for row in conn.execute("SELECT status, COUNT(*) AS total FROM items GROUP BY status").fetchall():
                counts[row["status"]] = row["total"]
            return {"counts": counts, "items": self.list_items()}
        finally:
            conn.close()
