import json
import os
import re
import threading
import time
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

try:
    from src.crawler import GCPSecurityReleaseCrawler
    from src.database import DEFAULT_CONFIG_PATH, ReleaseDatabase
except ImportError:
    from crawler import GCPSecurityReleaseCrawler
    from database import DEFAULT_CONFIG_PATH, ReleaseDatabase

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
INDEX_TEMPLATE_PATH = TEMPLATE_DIR / "index.html"
ADMIN_TEMPLATE_PATH = TEMPLATE_DIR / "admin.html"


def compute_next_scheduled_run(update_time_str: str, enabled: bool) -> str:
    if not enabled:
        return ""
    try:
        parts = update_time_str.strip().split(":")
        hour = int(parts[0])
        minute = int(parts[1]) if len(parts) > 1 else 0
        now = datetime.now()
        candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ""


def get_allowed_admins() -> List[str]:
    """Retrieve the list of authorized administrator email addresses from config or environment."""
    emails: List[str] = []
    if DEFAULT_CONFIG_PATH.exists():
        try:
            with open(DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                admin_cfg = cfg.get("admin_emails", [])
                if isinstance(admin_cfg, list):
                    emails = [str(e).strip().lower() for e in admin_cfg if e]
        except Exception:
            pass

    env_admins = os.environ.get("ADMIN_EMAILS", "")
    if env_admins:
        emails.extend([e.strip().lower() for e in env_admins.split(",") if e.strip()])

    if not emails:
        emails = ["dragon@jayseo.altostrat.com"]

    return list(dict.fromkeys(emails))


class AutoUpdateScheduler:
    """Background daemon scheduler that automatically runs release note crawling at the configured daily time."""

    def __init__(self, db: ReleaseDatabase, crawler: GCPSecurityReleaseCrawler):
        self.db = db
        self.crawler = crawler
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._run_loop, name="AutoUpdateScheduler", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                settings = self.db.get_admin_settings()
                if settings.get("auto_update_enabled", True):
                    target_time = settings.get("auto_update_time", "05:00")
                    now = datetime.now()
                    current_hhmm = now.strftime("%H:%M")
                    today_str = now.strftime("%Y-%m-%d")
                    last_run_date = settings.get("last_scheduled_run_date", "")

                    if current_hhmm == target_time and last_run_date != today_str:
                        with self._lock:
                            print(
                                f"\n⏰ [자동 업데이트 스케줄러] 설정된 시각({target_time})이 되어 전체 활성 보안 제품 업데이트를 시작합니다..."
                            )
                            self.db.sync_products_from_config()
                            results = self.crawler.crawl_all_enabled()
                            ok_count = sum(1 for r in results if r.get("status") == "SUCCESS")
                            new_items = sum(int(r.get("inserted_count", 0)) for r in results)
                            status_msg = f"SUCCESS ({ok_count}/{len(results)} products, +{new_items} new)"
                            self.db.record_scheduled_run(run_date=today_str, status=status_msg)
                            print(
                                f"✅ [자동 업데이트 스케줄러] 완료: {status_msg}"
                            )
            except Exception as exc:
                print(f"⚠️ [자동 업데이트 스케줄러] 오류 발생: {exc}")

            self._stop_event.wait(15.0)


class ReleaseTrackerHTTPRequestHandler(BaseHTTPRequestHandler):
    db: ReleaseDatabase = ReleaseDatabase()
    crawler: GCPSecurityReleaseCrawler = GCPSecurityReleaseCrawler(db)
    bootstrap_lock: threading.Lock = threading.Lock()
    bootstrap_done_event: threading.Event = threading.Event()
    is_bootstrapping: bool = False

    def _wait_if_bootstrapping(self, timeout: float = 25.0) -> bool:
        """If an initial empty-DB bootstrap is currently running, wait for it; never trigger a crawl on GET."""
        if self.is_bootstrapping and not self.bootstrap_done_event.is_set():
            self.bootstrap_done_event.wait(timeout=timeout)
        return self.is_bootstrapping

    def _get_current_user(self) -> Dict[str, Any]:
        """Resolve current user identity and permissions from HTTP headers or session cookies."""
        allowed_admins = get_allowed_admins()
        email = ""
        auth_source = "unauthenticated"

        # 1. Google Identity-Aware Proxy (IAP) header
        iap_email = self.headers.get("X-Goog-Authenticated-User-Email", "").strip()
        if iap_email:
            if ":" in iap_email:
                iap_email = iap_email.split(":", 1)[1]
            email = iap_email.strip().lower()
            auth_source = "gcp_identity_platform"

        # 2. Other standard GCP / proxy headers
        if not email:
            goog_user = self.headers.get("X-Goog-User-Email", "").strip()
            if goog_user:
                email = goog_user.lower()
                auth_source = "gcp_identity_platform"

        # 3. Custom auth / admin email headers
        if not email:
            auth_email = (
                self.headers.get("X-Auth-Email", "").strip()
                or self.headers.get("X-Admin-Email", "").strip()
            )
            if auth_email:
                email = auth_email.lower()
                auth_source = "auth_header"

        # 4. Authorization header (Bearer token or Bearer <email>)
        if not email:
            auth_hdr = self.headers.get("Authorization", "").strip()
            if auth_hdr.lower().startswith("bearer "):
                token = auth_hdr[7:].strip()
                admin_token = os.environ.get("ADMIN_TOKEN", "")
                if admin_token and token == admin_token:
                    email = allowed_admins[0] if allowed_admins else "admin"
                    auth_source = "bearer_token"
                elif "@" in token:
                    email = token.lower()
                    auth_source = "bearer_token"

        # 5. Session cookie
        if not email:
            cookie_hdr = self.headers.get("Cookie", "")
            if cookie_hdr:
                try:
                    c = SimpleCookie()
                    c.load(cookie_hdr)
                    for key in ("auth_user", "user_email", "admin_email", "session_user"):
                        if key in c:
                            val = c[key].value.strip()
                            if val:
                                email = val.lower()
                                auth_source = "session_cookie"
                                break
                except Exception:
                    pass

        is_authenticated = bool(email)
        is_admin = is_authenticated and (email in allowed_admins)

        return {
            "email": email,
            "is_authenticated": is_authenticated,
            "is_admin": is_admin,
            "auth_source": auth_source,
            "allowed_admins": allowed_admins,
        }

    def _require_admin(self) -> bool:
        """Verify that caller is authenticated and authorized as an administrator."""
        user = self._get_current_user()
        if not user["is_authenticated"]:
            self._send_json(
                {"error": "Unauthorized", "message": "Authentication required"},
                status=401,
            )
            return False
        if not user["is_admin"]:
            self._send_json(
                {"error": "Forbidden", "message": "Administrator privileges required"},
                status=403,
            )
            return False
        return True

    def _send_json(
        self,
        payload: Dict[str, Any],
        status: int = 200,
        extra_headers: Optional[List[Tuple[str, str]]] = None,
    ) -> None:
        raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Length", str(len(raw)))
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(
        self,
        html_content: str,
        status: int = 200,
        extra_headers: Optional[List[Tuple[str, str]]] = None,
    ) -> None:
        raw = html_content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(raw)))
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        return json.loads(raw) if raw else {}

    def _build_settings_response(self) -> Dict[str, Any]:
        settings = self.db.get_admin_settings()
        now = datetime.now()
        settings["next_scheduled_run_at"] = compute_next_scheduled_run(
            settings["auto_update_time"], settings["auto_update_enabled"]
        )
        settings["server_date"] = now.strftime("%Y-%m-%d")
        settings["server_time"] = now.strftime("%Y-%m-%d %H:%M:%S")
        settings["bootstrapping"] = self.is_bootstrapping
        return settings

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        # 1. Main Dashboard: Publicly accessible without any authentication
        if path in ("/", "/index.html"):
            if INDEX_TEMPLATE_PATH.exists():
                self._send_html(INDEX_TEMPLATE_PATH.read_text(encoding="utf-8"))
            else:
                self._send_html("<h1>Template not found</h1>", status=404)
            return

        # 2. Admin Console: Accessible only by authenticated administrators
        if path in ("/admin", "/admin/"):
            user = self._get_current_user()
            if not user["is_authenticated"]:
                self._send_html(
                    "<!DOCTYPE html><html><head><title>401 Unauthorized</title></head>"
                    "<body style='font-family:sans-serif;padding:2rem;'>"
                    "<h1>401 Unauthorized</h1>"
                    "<p>Authentication required to access the Admin Console.</p>"
                    "<p><a href='/'>Return to Main Dashboard</a></p>"
                    "</body></html>",
                    status=401,
                )
                return
            if not user["is_admin"]:
                self._send_html(
                    "<!DOCTYPE html><html><head><title>403 Forbidden</title></head>"
                    "<body style='font-family:sans-serif;padding:2rem;'>"
                    "<h1>403 Forbidden</h1>"
                    "<p>Access denied. Administrator privileges required.</p>"
                    "<p><a href='/'>Return to Main Dashboard</a></p>"
                    "</body></html>",
                    status=403,
                )
                return

            if ADMIN_TEMPLATE_PATH.exists():
                self._send_html(ADMIN_TEMPLATE_PATH.read_text(encoding="utf-8"))
            else:
                self._send_html("<h1>Admin template not found</h1>", status=404)
            return

        # 3. User metadata endpoint
        if path == "/api/me":
            user = self._get_current_user()
            self._send_json(
                {
                    "email": user["email"],
                    "is_admin": user["is_admin"],
                    "is_viewer": True,
                    "auth_source": user["auth_source"],
                    "allowed_admins": user["allowed_admins"],
                }
            )
            return

        # 4. Settings
        if path == "/api/settings":
            self._send_json({"settings": self._build_settings_response()})
            return

        # 5. Products list (reads directly from DB)
        if path == "/api/products":
            bootstrapping = self._wait_if_bootstrapping()
            enabled_only = qs.get("enabled_only", ["false"])[0].lower() == "true"
            products = self.db.get_products(enabled_only=enabled_only)
            self._send_json({"products": products, "bootstrapping": bootstrapping})
            return

        # 6. Releases list (reads directly from DB)
        if path == "/api/releases":
            bootstrapping = self._wait_if_bootstrapping()
            product_slug = qs.get("product", [None])[0]
            release_type = qs.get("type", [None])[0]
            since_date = qs.get("since", [None])[0]
            until_date = qs.get("until", [None])[0]
            search_query = qs.get("q", [None])[0]
            limit = int(qs.get("limit", ["200"])[0])

            releases = self.db.get_release_notes(
                product_slug=product_slug,
                release_type=release_type,
                since_date=since_date,
                until_date=until_date,
                search_query=search_query,
                limit=limit,
            )
            self._send_json(
                {
                    "count": len(releases),
                    "releases": releases,
                    "bootstrapping": bootstrapping,
                }
            )
            return

        # 7. Snapshots list (reads directly from DB)
        if path == "/api/snapshots":
            bootstrapping = self._wait_if_bootstrapping()
            product_slug = qs.get("product", [None])[0]
            snapshots = self.db.get_snapshots(product_slug=product_slug)
            self._send_json({"snapshots": snapshots, "bootstrapping": bootstrapping})
            return

        # 8. Logout fallback
        if path == "/api/auth/logout":
            clear_cookie = "auth_user=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly"
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", clear_cookie)
            self.end_headers()
            return

        self._send_json({"error": "Not found"}, status=404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        # Login
        if path == "/api/auth/login":
            body = self._read_json_body()
            email = (body.get("email") or "").strip().lower()
            if not email:
                self._send_json({"error": "email is required"}, status=400)
                return
            allowed_admins = get_allowed_admins()
            is_admin = email in allowed_admins
            cookie_val = f"auth_user={email}; Path=/; HttpOnly; SameSite=Lax"
            self._send_json(
                {
                    "message": "로그인되었습니다.",
                    "email": email,
                    "is_admin": is_admin,
                    "auth_source": "session_cookie",
                },
                extra_headers=[("Set-Cookie", cookie_val)],
            )
            return

        # Logout
        if path == "/api/auth/logout":
            clear_cookie = "auth_user=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly"
            self._send_json(
                {"message": "로그아웃되었습니다."},
                extra_headers=[("Set-Cookie", clear_cookie)],
            )
            return

        # DB Reset and Crawl
        if path == "/api/reset-and-crawl":
            if not self._require_admin():
                return
            cls = self.__class__
            with cls.bootstrap_lock:
                cls.is_bootstrapping = True
                cls.bootstrap_done_event.clear()
            try:
                synced = self.db.reset_all_data()
                results = self.crawler.crawl_all_enabled()
                total_inserted = sum(int(r.get("inserted_count", 0)) for r in results)
            finally:
                cls.is_bootstrapping = False
                cls.bootstrap_done_event.set()
            self._send_json(
                {
                    "status": "RESET_AND_CRAWLED",
                    "synced_products": synced,
                    "total_inserted": total_inserted,
                    "results": results,
                }
            )
            return

        # Crawl
        if path == "/api/crawl":
            if not self._require_admin():
                return
            body = self._read_json_body()
            product_slug = body.get("product_slug")
            override_date = body.get("override_baseline_date")
            include_same_day = bool(body.get("include_same_day", False))

            if product_slug:
                result = self.crawler.crawl_product(
                    product_slug=product_slug,
                    override_baseline_date=override_date,
                    include_same_day=include_same_day,
                )
                self._send_json({"results": [result]})
            else:
                results = self.crawler.crawl_all_enabled(
                    override_baseline_date=override_date
                )
                self._send_json({"results": results})
            return

        # Add or update product
        if path == "/api/products":
            if not self._require_admin():
                return
            body = self._read_json_body()
            slug = (body.get("slug") or "").strip().lower()
            name = (body.get("name") or "").strip()
            url = (body.get("release_notes_url") or "").strip()
            category = (body.get("category") or "Security").strip()
            description = (body.get("description") or "").strip()
            snapshot_date = (body.get("snapshot_date") or "2026-06-01").strip()
            enabled = bool(body.get("enabled", True))

            if not slug or not name or not url:
                self._send_json(
                    {"error": "slug, name, release_notes_url은 필수 항목입니다."},
                    status=400,
                )
                return

            product = self.db.upsert_product(
                slug=slug,
                name=name,
                release_notes_url=url,
                category=category,
                description=description,
                snapshot_date=snapshot_date,
                enabled=enabled,
            )
            self._send_json({"product": product}, status=201)
            return

        self._send_json({"error": "Not found"}, status=404)

    def do_PUT(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        # Settings update
        if path == "/api/settings":
            if not self._require_admin():
                return
            body = self._read_json_body()
            auto_update_enabled = body.get("auto_update_enabled")
            auto_update_time = body.get("auto_update_time")
            recent_highlight_days = body.get("recent_highlight_days")

            if auto_update_time is not None:
                auto_update_time = str(auto_update_time).strip()
                if not re.match(r"^([01]\d|2[0-3]):([0-5]\d)$", auto_update_time):
                    self._send_json(
                        {"error": "유효한 시간 형식(HH:MM, 00:00~23:59)을 입력해주세요."},
                        status=400,
                    )
                    return

            self.db.update_admin_settings(
                auto_update_enabled=bool(auto_update_enabled) if auto_update_enabled is not None else None,
                auto_update_time=auto_update_time,
                recent_highlight_days=int(recent_highlight_days) if recent_highlight_days is not None else None,
            )
            self._send_json({"settings": self._build_settings_response()})
            return

        # Snapshot date update
        m = re.match(r"^/api/products/([^/]+)/snapshot$", path)
        if m:
            if not self._require_admin():
                return
            body = self._read_json_body()
            slug = m.group(1)
            snapshot_date = (body.get("snapshot_date") or "").strip()
            clear_after_date = bool(body.get("clear_after_date", False))
            enabled = body.get("enabled")

            if not snapshot_date:
                self._send_json({"error": "snapshot_date is required"}, status=400)
                return

            updated = self.db.update_product_snapshot(
                slug=slug,
                snapshot_date=snapshot_date,
                toggle_enabled=enabled,
                clear_after_date=clear_after_date,
            )
            if not updated:
                self._send_json({"error": "Product not found"}, status=404)
                return
            self._send_json({"product": updated})
            return

        self._send_json({"error": "Not found"}, status=404)

    def log_message(self, format: str, *args: Any) -> None:
        # Keep console output clean
        pass


def run_server(host: str = "127.0.0.1", port: int = 8080, db: Optional[ReleaseDatabase] = None) -> None:
    database = db or ReleaseDatabase()
    database.sync_products_from_config()
    crawler = GCPSecurityReleaseCrawler(database)
    ReleaseTrackerHTTPRequestHandler.db = database
    ReleaseTrackerHTTPRequestHandler.crawler = crawler

    # Serve existing DB records immediately; only run one-time bootstrap if DB is completely empty
    if len(database.get_release_notes(limit=1)) == 0:
        ReleaseTrackerHTTPRequestHandler.is_bootstrapping = True
        ReleaseTrackerHTTPRequestHandler.bootstrap_done_event.clear()

        def _initial_bootstrap() -> None:
            try:
                print("🔄 [초기 부트스트랩] DB가 비어 있어 초기 스캔을 1회 수행합니다...")
                results = crawler.crawl_all_enabled()
                inserted = sum(int(r.get("inserted_count", 0)) for r in results)
                print(f"✅ [초기 부트스트랩] 완료: 총 {len(results)}개 제품 스캔, 신규 {inserted}건 저장")
            except Exception as exc:
                print(f"⚠️ [초기 부트스트랩] 오류: {exc}")
            finally:
                ReleaseTrackerHTTPRequestHandler.is_bootstrapping = False
                ReleaseTrackerHTTPRequestHandler.bootstrap_done_event.set()

        threading.Thread(target=_initial_bootstrap, name="InitialBootstrap", daemon=True).start()
    else:
        ReleaseTrackerHTTPRequestHandler.is_bootstrapping = False
        ReleaseTrackerHTTPRequestHandler.bootstrap_done_event.set()

    scheduler = AutoUpdateScheduler(database, crawler)
    scheduler.start()
    settings = database.get_admin_settings()
    sched_state = (
        f"매일 {settings['auto_update_time']} 자동 실행"
        if settings.get("auto_update_enabled")
        else "비활성"
    )

    server = ThreadingHTTPServer((host, port), ReleaseTrackerHTTPRequestHandler)
    print(f"🚀 GCP Security Release Notes 웹 서버가 시작되었습니다: http://{host}:{port}")
    print(f"⚙️ 관리자 콘솔: http://{host}:{port}/admin")
    print(f"⏰ 자동 업데이트 스케줄러 상태: {sched_state} (최근 강조 기준: {settings.get('recent_highlight_days', 7)}일 이내)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n서버를 종료합니다.")
        scheduler.stop()
        server.server_close()
