import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "data" / "gcp_security_releases.db"
DEFAULT_CONFIG_PATH = BASE_DIR / "config" / "products.json"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ReleaseDatabase:
    """SQLite database manager for GCP Security product release notes & crawl snapshots."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS products (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    slug TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    category TEXT DEFAULT 'Security',
                    release_notes_url TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    snapshot_date TEXT NOT NULL DEFAULT '2026-01-01',
                    last_crawled_at TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS crawl_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id INTEGER NOT NULL,
                    baseline_date TEXT NOT NULL,
                    new_snapshot_date TEXT NOT NULL,
                    crawled_at TEXT NOT NULL,
                    scanned_count INTEGER NOT NULL DEFAULT 0,
                    inserted_count INTEGER NOT NULL DEFAULT 0,
                    updated_count INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'SUCCESS',
                    message TEXT DEFAULT '',
                    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS release_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id INTEGER NOT NULL,
                    release_date TEXT NOT NULL,
                    release_date_display TEXT NOT NULL,
                    release_type TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    content_text TEXT NOT NULL,
                    content_html TEXT NOT NULL,
                    links_json TEXT NOT NULL DEFAULT '[]',
                    source_url TEXT NOT NULL,
                    content_hash TEXT NOT NULL UNIQUE,
                    snapshot_id INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
                    FOREIGN KEY (snapshot_id) REFERENCES crawl_snapshots(id) ON DELETE SET NULL
                );

                CREATE INDEX IF NOT EXISTS idx_release_notes_product_date
                    ON release_notes(product_id, release_date DESC);
                CREATE INDEX IF NOT EXISTS idx_release_notes_type
                    ON release_notes(release_type);
                CREATE INDEX IF NOT EXISTS idx_crawl_snapshots_product
                    ON crawl_snapshots(product_id, crawled_at DESC);

                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            self._ensure_default_settings(conn)

    def _ensure_default_settings(self, conn: sqlite3.Connection) -> None:
        now = utc_now_iso()
        defaults = {
            "auto_update_enabled": "true",
            "auto_update_time": "05:00",
            "recent_highlight_days": "7",
            "last_scheduled_run_at": "",
            "last_scheduled_run_date": "",
            "last_scheduled_status": "",
        }
        for k, v in defaults.items():
            conn.execute(
                "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)",
                (k, v, now),
            )
        # Normalize legacy 'Change' -> 'Changed' and 'Fix' -> 'Fixed' in release_notes
        conn.execute(
            "UPDATE release_notes SET release_type = 'Changed' WHERE LOWER(release_type) = 'change'"
        )
        conn.execute(
            "UPDATE release_notes SET release_type = 'Fixed' WHERE LOWER(release_type) = 'fix'"
        )

    def get_admin_settings(self) -> Dict[str, Any]:
        with self._connect() as conn:
            self._ensure_default_settings(conn)
            rows = conn.execute("SELECT key, value FROM app_settings").fetchall()
            raw = {r["key"]: r["value"] for r in rows}

        return {
            "auto_update_enabled": raw.get("auto_update_enabled", "true").lower() == "true",
            "auto_update_time": raw.get("auto_update_time", "05:00") or "05:00",
            "recent_highlight_days": int(raw.get("recent_highlight_days", "7") or "7"),
            "last_scheduled_run_at": raw.get("last_scheduled_run_at", ""),
            "last_scheduled_run_date": raw.get("last_scheduled_run_date", ""),
            "last_scheduled_status": raw.get("last_scheduled_status", ""),
        }

    def update_admin_settings(
        self,
        auto_update_enabled: Optional[bool] = None,
        auto_update_time: Optional[str] = None,
        recent_highlight_days: Optional[int] = None,
        config_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        now = utc_now_iso()
        updates: Dict[str, str] = {}
        if auto_update_enabled is not None:
            updates["auto_update_enabled"] = "true" if auto_update_enabled else "false"
        if auto_update_time is not None:
            updates["auto_update_time"] = auto_update_time.strip()
        if recent_highlight_days is not None:
            updates["recent_highlight_days"] = str(max(1, int(recent_highlight_days)))

        with self._connect() as conn:
            self._ensure_default_settings(conn)
            for k, v in updates.items():
                conn.execute(
                    """
                    INSERT INTO app_settings (key, value, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                    """,
                    (k, v, now),
                )

        settings = self.get_admin_settings()

        # Persist schedule settings to config/products.json as well
        path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                cfg["schedule"] = {
                    "auto_update_enabled": settings["auto_update_enabled"],
                    "auto_update_time": settings["auto_update_time"],
                    "recent_highlight_days": settings["recent_highlight_days"],
                }
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, ensure_ascii=False, indent=2)
                    f.write("\n")
            except Exception:
                pass

        return settings

    def record_scheduled_run(self, run_date: str, status: str = "SUCCESS") -> None:
        now = utc_now_iso()
        with self._connect() as conn:
            for k, v in (
                ("last_scheduled_run_at", now),
                ("last_scheduled_run_date", run_date),
                ("last_scheduled_status", status),
            ):
                conn.execute(
                    """
                    INSERT INTO app_settings (key, value, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                    """,
                    (k, v, now),
                )

    def reset_all_data(self, config_path: Optional[Path] = None) -> int:
        """Clear all release_notes, crawl_snapshots, and products tables, then re-sync from config/products.json."""
        with self._connect() as conn:
            conn.execute("DELETE FROM release_notes;")
            conn.execute("DELETE FROM crawl_snapshots;")
            conn.execute("DELETE FROM products;")
            conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('release_notes', 'crawl_snapshots', 'products');")
        return self.sync_products_from_config(config_path=config_path)

    def sync_products_from_config(self, config_path: Optional[Path] = None) -> int:
        """Load products from config/products.json and insert any missing products into DB."""
        path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
        if not path.exists():
            return 0

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        default_snapshot = data.get("default_initial_snapshot_date", "2026-06-01")
        schedule_cfg = data.get("schedule") or {}
        products = data.get("products", [])
        now = utc_now_iso()
        synced = 0

        with self._connect() as conn:
            self._ensure_default_settings(conn)
            for item in products:
                slug = item["slug"].strip()
                existing_rows = conn.execute(
                    "SELECT id, slug FROM products WHERE LOWER(slug) = LOWER(?) ORDER BY id ASC",
                    (slug,),
                ).fetchall()

                if not existing_rows:
                    conn.execute(
                        """
                        INSERT INTO products (
                            slug, name, category, release_notes_url, description,
                            snapshot_date, enabled, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            slug,
                            item["name"],
                            item.get("category", "Security"),
                            item["release_notes_url"],
                            item.get("description", ""),
                            item.get("initial_snapshot_date", default_snapshot),
                            1 if item.get("enabled", True) else 0,
                            now,
                            now,
                        ),
                    )
                    synced += 1
                else:
                    primary_id = existing_rows[0]["id"]
                    # Remove any duplicate rows that differed only in casing
                    for dup in existing_rows[1:]:
                        conn.execute("DELETE FROM products WHERE id = ?", (dup["id"],))
                    # Update metadata and normalize slug without overwriting active snapshot_date
                    conn.execute(
                        """
                        UPDATE products
                        SET slug = ?, name = ?, category = ?, release_notes_url = ?, description = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            slug,
                            item["name"],
                            item.get("category", "Security"),
                            item["release_notes_url"],
                            item.get("description", ""),
                            now,
                            primary_id,
                        ),
                    )
        return synced

    def upsert_product(
        self,
        slug: str,
        name: str,
        release_notes_url: str,
        category: str = "Security",
        description: str = "",
        snapshot_date: str = "2026-06-01",
        enabled: bool = True,
    ) -> Dict[str, Any]:
        now = utc_now_iso()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT id FROM products WHERE slug = ?", (slug,)
            ).fetchone()
            if existing:
                conn.execute(
                    """
                    UPDATE products
                    SET name = ?, category = ?, release_notes_url = ?, description = ?,
                        snapshot_date = ?, enabled = ?, updated_at = ?
                    WHERE slug = ?
                    """,
                    (
                        name,
                        category,
                        release_notes_url,
                        description,
                        snapshot_date,
                        1 if enabled else 0,
                        now,
                        slug,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO products (
                        slug, name, category, release_notes_url, description,
                        snapshot_date, enabled, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        slug,
                        name,
                        category,
                        release_notes_url,
                        description,
                        snapshot_date,
                        1 if enabled else 0,
                        now,
                        now,
                    ),
                )
        return self.get_product_by_slug(slug)  # type: ignore

    def get_products(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        query = """
            SELECT
                p.*,
                COUNT(r.id) AS total_releases,
                MAX(r.release_date) AS latest_release_date,
                SUM(CASE WHEN r.release_type = 'Feature' THEN 1 ELSE 0 END) AS feature_count
            FROM products p
            LEFT JOIN release_notes r ON p.id = r.product_id
        """
        params: List[Any] = []
        if enabled_only:
            query += " WHERE p.enabled = 1"
        query += " GROUP BY p.id ORDER BY p.enabled DESC, p.id ASC"

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def get_product_by_slug(self, slug: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    p.*,
                    COUNT(r.id) AS total_releases,
                    MAX(r.release_date) AS latest_release_date
                FROM products p
                LEFT JOIN release_notes r ON p.id = r.product_id
                WHERE p.slug = ?
                GROUP BY p.id
                """,
                (slug,),
            ).fetchone()
            return dict(row) if row else None

    def update_product_snapshot(
        self,
        slug: str,
        snapshot_date: str,
        toggle_enabled: Optional[bool] = None,
        clear_after_date: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Update the snapshot baseline date for a product (optionally pruning releases after that date for re-scan testing)."""
        now = utc_now_iso()
        with self._connect() as conn:
            prod = conn.execute(
                "SELECT id FROM products WHERE slug = ?", (slug,)
            ).fetchone()
            if not prod:
                return None

            product_id = prod["id"]
            if clear_after_date:
                conn.execute(
                    "DELETE FROM release_notes WHERE product_id = ? AND release_date > ?",
                    (product_id, snapshot_date),
                )

            if toggle_enabled is not None:
                conn.execute(
                    "UPDATE products SET snapshot_date = ?, enabled = ?, updated_at = ? WHERE id = ?",
                    (snapshot_date, 1 if toggle_enabled else 0, now, product_id),
                )
            else:
                conn.execute(
                    "UPDATE products SET snapshot_date = ?, updated_at = ? WHERE id = ?",
                    (snapshot_date, now, product_id),
                )
        return self.get_product_by_slug(slug)

    def record_crawl_result(
        self,
        product_id: int,
        baseline_date: str,
        new_snapshot_date: str,
        items: List[Dict[str, Any]],
        status: str = "SUCCESS",
        message: str = "",
    ) -> Dict[str, Any]:
        """Store crawl snapshot log, insert/update release notes, and advance product snapshot_date."""
        now = utc_now_iso()
        inserted_count = 0
        updated_count = 0

        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO crawl_snapshots (
                    product_id, baseline_date, new_snapshot_date, crawled_at,
                    scanned_count, inserted_count, updated_count, status, message
                ) VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?)
                """,
                (
                    product_id,
                    baseline_date,
                    new_snapshot_date,
                    now,
                    len(items),
                    status,
                    message,
                ),
            )
            snapshot_id = cursor.lastrowid

            for item in items:
                existing = conn.execute(
                    "SELECT id, content_html, summary FROM release_notes WHERE content_hash = ?",
                    (item["content_hash"],),
                ).fetchone()

                links_str = json.dumps(item.get("links", []), ensure_ascii=False)
                if not existing:
                    conn.execute(
                        """
                        INSERT INTO release_notes (
                            product_id, release_date, release_date_display, release_type,
                            summary, content_text, content_html, links_json,
                            source_url, content_hash, snapshot_id, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            product_id,
                            item["release_date"],
                            item["release_date_display"],
                            item["release_type"],
                            item["summary"],
                            item["content_text"],
                            item["content_html"],
                            links_str,
                            item["source_url"],
                            item["content_hash"],
                            snapshot_id,
                            now,
                            now,
                        ),
                    )
                    inserted_count += 1
                else:
                    if existing["content_html"] != item["content_html"]:
                        conn.execute(
                            """
                            UPDATE release_notes
                            SET summary = ?, content_text = ?, content_html = ?,
                                links_json = ?, snapshot_id = ?, updated_at = ?
                            WHERE id = ?
                            """,
                            (
                                item["summary"],
                                item["content_text"],
                                item["content_html"],
                                links_str,
                                snapshot_id,
                                now,
                                existing["id"],
                            ),
                        )
                        updated_count += 1

            # Update snapshot counts
            conn.execute(
                """
                UPDATE crawl_snapshots
                SET inserted_count = ?, updated_count = ?
                WHERE id = ?
                """,
                (inserted_count, updated_count, snapshot_id),
            )

            # Advance product snapshot_date and last_crawled_at
            conn.execute(
                """
                UPDATE products
                SET snapshot_date = ?, last_crawled_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (new_snapshot_date, now, now, product_id),
            )

            snap_row = conn.execute(
                "SELECT * FROM crawl_snapshots WHERE id = ?", (snapshot_id,)
            ).fetchone()
            return dict(snap_row)

    def get_release_notes(
        self,
        product_slug: Optional[str] = None,
        release_type: Optional[str] = None,
        since_date: Optional[str] = None,
        until_date: Optional[str] = None,
        search_query: Optional[str] = None,
        snapshot_id: Optional[int] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        query = """
            SELECT
                r.*,
                p.slug AS product_slug,
                p.name AS product_name,
                p.category AS product_category,
                s.crawled_at AS snapshot_crawled_at,
                s.baseline_date AS snapshot_baseline_date
            FROM release_notes r
            JOIN products p ON r.product_id = p.id
            LEFT JOIN crawl_snapshots s ON r.snapshot_id = s.id
            WHERE 1=1
        """
        params: List[Any] = []

        if product_slug and product_slug != "all":
            query += " AND p.slug = ?"
            params.append(product_slug)

        if release_type and release_type != "all":
            rt_lower = release_type.strip().lower()
            if rt_lower in ("changed", "change"):
                query += " AND LOWER(r.release_type) IN ('changed', 'change')"
            elif rt_lower in ("fixed", "fix", "issue"):
                query += " AND LOWER(r.release_type) IN ('fixed', 'fix', 'issue')"
            elif rt_lower in ("deprecated", "deprecation"):
                query += " AND LOWER(r.release_type) IN ('deprecated', 'deprecation')"
            else:
                query += " AND LOWER(r.release_type) = ?"
                params.append(rt_lower)

        if since_date:
            query += " AND r.release_date >= ?"
            params.append(since_date)

        if until_date:
            query += " AND r.release_date <= ?"
            params.append(until_date)

        if snapshot_id:
            query += " AND r.snapshot_id = ?"
            params.append(snapshot_id)

        if search_query:
            query += " AND (r.content_text LIKE ? OR r.summary LIKE ? OR p.name LIKE ?)"
            like_q = f"%{search_query}%"
            params.extend([like_q, like_q, like_q])

        query += " ORDER BY r.release_date DESC, r.id ASC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            results = []
            for row in rows:
                d = dict(row)
                try:
                    d["links"] = json.loads(d.get("links_json") or "[]")
                except Exception:
                    d["links"] = []
                results.append(d)
            return results

    def get_snapshots(
        self, product_slug: Optional[str] = None, limit: int = 30
    ) -> List[Dict[str, Any]]:
        query = """
            SELECT
                s.*,
                p.slug AS product_slug,
                p.name AS product_name
            FROM crawl_snapshots s
            JOIN products p ON s.product_id = p.id
            WHERE 1=1
        """
        params: List[Any] = []
        if product_slug and product_slug != "all":
            query += " AND p.slug = ?"
            params.append(product_slug)

        query += " ORDER BY s.id DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]
