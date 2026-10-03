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

    def _column_exists(self, conn, table, column):
        cols = [row[1] for row in conn.execute("PRAGMA table_info(%s)" % table).fetchall()]
        return column in cols

    def _table_exists(self, conn, table):
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        return row is not None

    def initialize(self):
        conn = self.connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            needs_migration = self._table_exists(conn, "items") and not self._column_exists(conn, "items", "region")
            if needs_migration:
                self._migrate(conn)
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    stable_key TEXT NOT NULL,
                    region TEXT NOT NULL DEFAULT '',
                    merged_into INTEGER,
                    status TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    payload TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(entity_type, region, stable_key)
                );
                CREATE TABLE IF NOT EXISTS sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    region TEXT NOT NULL DEFAULT '',
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
                CREATE TABLE IF NOT EXISTS processed_batches (
                    batch_id TEXT PRIMARY KEY,
                    region TEXT NOT NULL,
                    result TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pending_backfills (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id TEXT NOT NULL,
                    item_stable_key TEXT NOT NULL,
                    region TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    snapshot TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL,
                    resolved_at TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_sources_region_external
                    ON sources(region, external_id);
                """
            )
        finally:
            conn.close()

    def _migrate(self, conn):
        # items: add region / merged_into and widen the unique key to include region.
        conn.execute(
            """
            CREATE TABLE items_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_type TEXT NOT NULL,
                stable_key TEXT NOT NULL,
                region TEXT NOT NULL DEFAULT '',
                merged_into INTEGER,
                status TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                payload TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(entity_type, region, stable_key)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO items_new
                (id, entity_type, stable_key, region, merged_into, status, version,
                 payload, created_by, created_role, created_at, updated_at)
            SELECT id, entity_type, stable_key, '', NULL, status, version,
                   payload, created_by, created_role, created_at, updated_at
            FROM items
            """
        )
        conn.execute("DROP TABLE items")
        conn.execute("ALTER TABLE items_new RENAME TO items")
        # sources: add region column (only if the old table exists).
        if self._table_exists(conn, "sources"):
            conn.execute(
                """
                CREATE TABLE sources_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    region TEXT NOT NULL DEFAULT '',
                    source_type TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, source_type, external_id),
                    FOREIGN KEY(item_id) REFERENCES items(id)
                )
                """
            )
            conn.execute(
                """
                INSERT INTO sources_new
                    (id, item_id, region, source_type, external_id, payload, observed_at, created_at)
                SELECT id, item_id, '', source_type, external_id, payload, observed_at, created_at
                FROM sources
                """
            )
            conn.execute("DROP TABLE sources")
            conn.execute("ALTER TABLE sources_new RENAME TO sources")

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

    def append_audit(self, conn, item_id, event_type, actor, role, payload):
        previous = self._last_hash(conn, item_id)
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

    def create_item(self, entity_type, stable_key, initial_status, payload, actor, role, region=""):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "INSERT INTO items(entity_type,stable_key,region,status,version,payload,created_by,created_role,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        entity_type,
                        stable_key,
                        region or "",
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
            self.append_audit(conn, item_id, "created", actor, role, {"stable_key": stable_key, "region": region or ""})
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

    def _resolve_survivor(self, conn, item_id):
        """Follow merged_into to the survivor item id."""
        current = item_id
        seen = set()
        while current and current not in seen:
            seen.add(current)
            row = conn.execute("SELECT id, merged_into FROM items WHERE id=?", (current,)).fetchone()
            if row is None:
                return None
            if not row["merged_into"]:
                return current
            current = row["merged_into"]
        return current

    def _group_ids(self, conn, item_id):
        """Return [survivor_id, ...merged_away_ids] for a paired event."""
        survivor = self._resolve_survivor(conn, item_id)
        if survivor is None:
            return []
        group = [survivor]
        frontier = [survivor]
        while frontier:
            node = frontier.pop()
            rows = conn.execute("SELECT id FROM items WHERE merged_into=?", (node,)).fetchall()
            for row in rows:
                if row["id"] not in group:
                    group.append(row["id"])
                    frontier.append(row["id"])
        return group

    def get_item(self, item_id):
        conn = self.connect()
        try:
            survivor = self._resolve_survivor(conn, item_id)
            if survivor is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            row = conn.execute("SELECT * FROM items WHERE id=?", (survivor,)).fetchone()
            return self._row_to_item(row)
        finally:
            conn.close()

    def find_items_by_key(self, entity_type, stable_key):
        """All items (any region) sharing a stable_key, oldest first."""
        conn = self.connect()
        try:
            rows = conn.execute(
                "SELECT * FROM items WHERE entity_type=? AND stable_key=? ORDER BY id",
                (entity_type, stable_key),
            ).fetchall()
            return [self._row_to_item(row) for row in rows]
        finally:
            conn.close()

    def list_items(self, status=None):
        conn = self.connect()
        try:
            if status:
                rows = conn.execute(
                    "SELECT * FROM items WHERE status=? AND merged_into IS NULL ORDER BY id DESC",
                    (status,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM items WHERE merged_into IS NULL ORDER BY id DESC"
                ).fetchall()
            return [self._row_to_item(row) for row in rows]
        finally:
            conn.close()

    def add_source(self, item_id, source_type, external_id, payload, observed_at, actor, role, region=""):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            survivor = self._resolve_survivor(conn, item_id)
            if survivor is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            # Same (region, external_id) is only ever recorded once.
            existing = conn.execute(
                "SELECT id FROM sources WHERE region=? AND external_id=?",
                (region or "", external_id),
            ).fetchone()
            if existing:
                conn.execute("ROLLBACK")
                row = conn.execute("SELECT * FROM sources WHERE id=?", (existing["id"],)).fetchone()
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                return value
            try:
                conn.execute(
                    "INSERT INTO sources(item_id,region,source_type,external_id,payload,observed_at,created_at) VALUES(?,?,?,?,?,?,?)",
                    (survivor, region or "", source_type, external_id, canonical_json(payload), observed_at, now_iso()),
                )
            except sqlite3.IntegrityError:
                raise ConflictError("duplicate_source", "同一来源记录已经提交")
            source_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            self.append_audit(
                conn,
                survivor,
                "source_recorded",
                actor,
                role,
                {"source_id": source_id, "source_type": source_type, "external_id": external_id, "region": region or ""},
            )
            conn.execute("COMMIT")
            return {
                "id": source_id,
                "item_id": survivor,
                "region": region or "",
                "source_type": source_type,
                "external_id": external_id,
                "payload": payload,
                "observed_at": observed_at,
            }
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
            group = self._group_ids(conn, item_id)
            if not group:
                return []
            placeholders = ",".join("?" for _ in group)
            rows = conn.execute(
                "SELECT * FROM sources WHERE item_id IN (%s) ORDER BY id DESC" % placeholders,
                group,
            ).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                result.append(value)
            return result
        finally:
            conn.close()

    def apply_action(self, item_id, action, actor, role, new_status, new_payload, event_payload, expected_version=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            survivor = self._resolve_survivor(conn, item_id)
            if survivor is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            row = conn.execute("SELECT * FROM items WHERE id=?", (survivor,)).fetchone()
            if expected_version is not None and int(expected_version) != int(row["version"]):
                raise ConflictError("version_conflict", "记录已被其他操作更新，请重新读取")
            version = int(row["version"]) + 1
            conn.execute(
                "UPDATE items SET status=?,version=?,payload=?,updated_at=? WHERE id=?",
                (new_status, version, canonical_json(new_payload), now_iso(), survivor),
            )
            conn.execute(
                "INSERT INTO actions(item_id,action,actor,role,payload,created_at) VALUES(?,?,?,?,?,?)",
                (survivor, action, actor, role, canonical_json(event_payload), now_iso()),
            )
            self.append_audit(conn, survivor, action, actor, role, event_payload)
            conn.execute("COMMIT")
            return self.get_item(survivor)
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
            group = self._group_ids(conn, item_id)
            if not group:
                return []
            placeholders = ",".join("?" for _ in group)
            rows = conn.execute(
                "SELECT * FROM audit_events WHERE item_id IN (%s) ORDER BY id" % placeholders,
                group,
            ).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                result.append(value)
            return result
        finally:
            conn.close()

    # ----- cross-region reconciliation -----

    def get_batch(self, batch_id):
        conn = self.connect()
        try:
            row = conn.execute("SELECT * FROM processed_batches WHERE batch_id=?", (batch_id,)).fetchone()
            if row is None:
                return None
            value = dict(row)
            value["result"] = json.loads(value["result"])
            return value
        finally:
            conn.close()

    def record_batch(self, batch_id, region, result):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT OR IGNORE INTO processed_batches(batch_id,region,result,created_at) VALUES(?,?,?,?)",
                (batch_id, region, canonical_json(result), now_iso()),
            )
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def add_pending(self, batch_id, stable_key, region, reason, snapshot):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO pending_backfills(batch_id,item_stable_key,region,reason,snapshot,status,created_at) VALUES(?,?,?,?,?,?,?)",
                (batch_id, stable_key, region, reason, canonical_json(snapshot), "pending", now_iso()),
            )
            pending_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            conn.execute("COMMIT")
            return pending_id
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def list_pending(self, status=None):
        conn = self.connect()
        try:
            if status:
                rows = conn.execute(
                    "SELECT * FROM pending_backfills WHERE status=? ORDER BY id", (status,)
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM pending_backfills ORDER BY id").fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["snapshot"] = json.loads(value["snapshot"])
                result.append(value)
            return result
        finally:
            conn.close()

    def get_pending(self, pending_id):
        conn = self.connect()
        try:
            row = conn.execute("SELECT * FROM pending_backfills WHERE id=?", (pending_id,)).fetchone()
            if row is None:
                raise NotFoundError("pending_not_found", "待处理补录不存在")
            value = dict(row)
            value["snapshot"] = json.loads(value["snapshot"])
            return value
        finally:
            conn.close()

    def resolve_pending(self, pending_id, status):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE pending_backfills SET status=?, resolved_at=? WHERE id=?",
                (status, now_iso(), pending_id),
            )
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def set_item_version(self, item_id, version):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            survivor = self._resolve_survivor(conn, item_id)
            if survivor is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            conn.execute(
                "UPDATE items SET version=?, updated_at=? WHERE id=?",
                (int(version), now_iso(), survivor),
            )
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def mark_backfilled(self, item_id, actor, role, event_payload):
        """Append an audit event flagging that this state came from a backfill.

        This does NOT advance the optimistic-concurrency version: a backfill is
        a sync operation, not a new state change, so the version token stays
        valid for the next district's snapshot.
        """
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            survivor = self._resolve_survivor(conn, item_id)
            if survivor is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            self.append_audit(conn, survivor, "backfilled", actor, role, event_payload)
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def merge_snapshot(self, item_id, snapshot, actor, role, batch_id):
        """Merge a district's snapshot into an existing (survivor) item.

        The snapshot payload is merged field-by-field with the survivor.
        Notifications are deduped by notice_id keeping the earliest occurrence;
        sample results and response actions are unioned; linked regions are joined.
        """
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            survivor = self._resolve_survivor(conn, item_id)
            if survivor is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            row = conn.execute("SELECT * FROM items WHERE id=?", (survivor,)).fetchone()
            current = json.loads(row["payload"])
            incoming = snapshot.get("payload", {})
            incoming_region = snapshot.get("region", "")

            # link regions
            regions = current.setdefault("regions", [])
            if current.get("region") and current["region"] not in regions:
                regions.insert(0, current["region"])
            if incoming_region and incoming_region not in regions:
                regions.append(incoming_region)

            # union zone ids
            for zone in incoming.get("zone_ids", []):
                if zone not in current.setdefault("zone_ids", []):
                    current["zone_ids"].append(zone)

            # merge notifications: dedup by notice_id, keep earliest (original order)
            existing_notices = current.setdefault("notifications", [])
            seen_notice = {n.get("notice_id") for n in existing_notices}
            for notice in incoming.get("notifications", []):
                if notice.get("notice_id") not in seen_notice:
                    existing_notices.append(notice)
                    seen_notice.add(notice.get("notice_id"))

            # merge response actions (union, preserve order)
            existing_actions = current.setdefault("response_actions", [])
            seen_action = {(a.get("type"), a.get("zone_id")) for a in existing_actions}
            for action in incoming.get("response_actions", []):
                key = (action.get("type"), action.get("zone_id"))
                if key not in seen_action:
                    existing_actions.append(action)
                    seen_action.add(key)

            # merge sample results (union, preserve order), tag with region
            existing_samples = current.setdefault("sample_results", [])
            seen_sample = {
                (s.get("sample_id"), s.get("zone_id")) for s in existing_samples
            }
            for sample in incoming.get("sample_results", []):
                key = (sample.get("sample_id"), sample.get("zone_id"))
                if key not in seen_sample:
                    if incoming_region and not sample.get("region"):
                        sample["region"] = incoming_region
                    existing_samples.append(sample)
                    seen_sample.add(key)

            # scalar fields: only fill when survivor lacks them (first wins)
            for field in ("assessment", "verification", "alternate_source_id", "restoration", "cancellation"):
                if field not in current and field in incoming:
                    current[field] = incoming[field]

            version = int(row["version"]) + 1
            new_status = snapshot.get("status") or row["status"]
            conn.execute(
                "UPDATE items SET status=?,version=?,payload=?,updated_at=? WHERE id=?",
                (new_status, version, canonical_json(current), now_iso(), survivor),
            )
            self.append_audit(
                conn,
                survivor,
                "reconciled",
                actor,
                role,
                {
                    "batch_id": batch_id,
                    "region": incoming_region,
                    "stable_key": snapshot.get("stable_key"),
                    "backfilled": True,
                },
            )
            conn.execute("COMMIT")
            return self.get_item(survivor)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def pair_items(self, survivor_id, merged_id, actor, role):
        """Merge two items (same event, different regions) into one survivor."""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            survivor = self._resolve_survivor(conn, survivor_id)
            merged = self._resolve_survivor(conn, merged_id)
            if survivor == merged:
                conn.execute("ROLLBACK")
                return self.get_item(survivor)
            srow = conn.execute("SELECT * FROM items WHERE id=?", (survivor,)).fetchone()
            mrow = conn.execute("SELECT * FROM items WHERE id=?", (merged,)).fetchone()
            if srow is None or mrow is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            spayload = json.loads(srow["payload"])
            mpayload = json.loads(mrow["payload"])

            sregion = srow["region"]
            mregion = mrow["region"]
            regions = spayload.setdefault("regions", [])
            if sregion and sregion not in regions:
                regions.insert(0, sregion)
            if mregion and mregion not in regions:
                regions.append(mregion)

            for zone in mpayload.get("zone_ids", []):
                if zone not in spayload.setdefault("zone_ids", []):
                    spayload["zone_ids"].append(zone)

            existing_notices = spayload.setdefault("notifications", [])
            seen_notice = {n.get("notice_id") for n in existing_notices}
            for notice in mpayload.get("notifications", []):
                if notice.get("notice_id") not in seen_notice:
                    existing_notices.append(notice)
                    seen_notice.add(notice.get("notice_id"))

            existing_actions = spayload.setdefault("response_actions", [])
            seen_action = {(a.get("type"), a.get("zone_id")) for a in existing_actions}
            for action in mpayload.get("response_actions", []):
                key = (action.get("type"), action.get("zone_id"))
                if key not in seen_action:
                    existing_actions.append(action)
                    seen_action.add(key)

            existing_samples = spayload.setdefault("sample_results", [])
            seen_sample = {(s.get("sample_id"), s.get("zone_id")) for s in existing_samples}
            for sample in mpayload.get("sample_results", []):
                key = (sample.get("sample_id"), sample.get("zone_id"))
                if key not in seen_sample:
                    if mregion and not sample.get("region"):
                        sample["region"] = mregion
                    existing_samples.append(sample)
                    seen_sample.add(key)

            for field in ("assessment", "verification", "alternate_source_id", "restoration", "cancellation"):
                if field not in spayload and field in mpayload:
                    spayload[field] = mpayload[field]

            # re-point sources (dedup by region/external_id)
            m_sources = conn.execute("SELECT * FROM sources WHERE item_id=?", (merged,)).fetchall()
            for src in m_sources:
                dup = conn.execute(
                    "SELECT id FROM sources WHERE region=? AND external_id=?",
                    (src["region"], src["external_id"]),
                ).fetchone()
                if dup:
                    continue
                conn.execute(
                    "UPDATE sources SET item_id=? WHERE id=?",
                    (survivor, src["id"]),
                )

            version = int(srow["version"]) + 1
            conn.execute(
                "UPDATE items SET status=?,version=?,payload=?,updated_at=? WHERE id=?",
                (srow["status"], version, canonical_json(spayload), now_iso(), survivor),
            )
            conn.execute(
                "UPDATE items SET merged_into=? WHERE id=?",
                (survivor, merged),
            )
            self.append_audit(
                conn,
                survivor,
                "paired",
                actor,
                role,
                {"merged_item_id": merged, "region": mregion, "backfilled": True},
            )
            self.append_audit(
                conn,
                merged,
                "merged_into",
                actor,
                role,
                {"survivor_item_id": survivor, "region": sregion, "backfilled": True},
            )
            conn.execute("COMMIT")
            return self.get_item(survivor)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def state_summary(self):
        conn = self.connect()
        try:
            counts = {}
            for row in conn.execute(
                "SELECT status, COUNT(*) AS total FROM items WHERE merged_into IS NULL GROUP BY status"
            ).fetchall():
                counts[row["status"]] = row["total"]
            return {"counts": counts, "items": self.list_items()}
        finally:
            conn.close()
