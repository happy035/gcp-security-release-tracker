import json
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from src.crawler import GCPSecurityReleaseCrawler
from src.database import DEFAULT_CONFIG_PATH, ReleaseDatabase

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


def get_admin_emails() -> List[str]:
    emails: List[str] = []
    env_admins = os.environ.get("ADMIN_EMAILS", "")
    if env_admins:
        for e in env_admins.split(","):
            cleaned = e.strip().lower()
            if cleaned:
                emails.append(cleaned)
    if DEFAULT_CONFIG_PATH.exists():
        try:
            with open(DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                config_admins = data.get("admin_emails", [])
                if isinstance(config_admins, list):
                    for e in config_admins:
                        cleaned = str(e).strip().lower()
                        if cleaned:
                            emails.append(cleaned)
        except Exception:
            pass
    seen = set()
    result: List[str] = []
    for e in emails:
        if e not in seen:
            seen.add(e)
            result.append(e)
    return result if result else ["dragon@jayseo.altostrat.com"]


_sessions: Dict[str, Dict[str, Any]] = {}
_sessions_lock = threading.Lock()


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

    def _get_cookie(self, name: str) -> Optional[str]:
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        try:
            cookie = SimpleCookie()
            cookie.load(cookie_header)
            if name in cookie:
                return cookie[name].value
        except Exception:
            pass
        return None

    def _authenticate_request(self) -> Tuple[Optional[str], Optional[str]]:
        """Extract authenticated user email and auth source from headers or session cookie.

        Returns (email, auth_source) or (None, None).
        """
        # 1. Google Cloud IAP header
        iap_email = self.headers.get("X-Goog-Authenticated-User-Email")
        if iap_email:
            email = iap_email.strip()
            if ":" in email:
                email = email.split(":")[-1].strip()
            if email:
                return email.lower(), "gcp_iap"

        # 2. Proxy email headers
        for h_name in ("X-User-Email", "X-Auth-Email", "X-Forwarded-Email", "X-Authenticated-User"):
            val = self.headers.get(h_name)
            if val:
                val = val.strip()
                if ":" in val:
                    val = val.split(":")[-1].strip()
                if val:
                    return val.lower(), "header_auth"

        # 3. Session cookie
        cookie_token = self._get_cookie("tracker_session") or self._get_cookie("session")
        if cookie_token:
            with _sessions_lock:
                sess = _sessions.get(cookie_token)
                if sess:
                    if time.time() <= sess.get("expires_at", float("inf")):
                        return sess["email"], sess.get("auth_source", "session")
                    else:
                        _sessions.pop(cookie_token, None)

        # 4. Bearer Token in Authorization header
        auth_header = self.headers.get("Authorization", "").strip()
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            with _sessions_lock:
                sess = _sessions.get(token)
                if sess:
                    if time.time() <= sess.get("expires_at", float("inf")):
                        return sess["email"], sess.get("auth_source", "session")
                    else:
                        _sessions.pop(token, None)

            admin_secret = os.environ.get("ADMIN_API_KEY") or os.environ.get("ADMIN_TOKEN")
            if admin_secret and token == admin_secret:
                admins = get_admin_emails()
                return admins[0], "api_key"

            if token.lower() in [e.lower() for e in get_admin_emails()]:
                return token.lower(), "bearer_auth"

        # 5. API key headers
        api_key = self.headers.get("X-API-Key") or self.headers.get("X-Admin-Token")
        if api_key:
            admin_secret = os.environ.get("ADMIN_API_KEY") or os.environ.get("ADMIN_TOKEN")
            if admin_secret and api_key.strip() == admin_secret:
                admins = get_admin_emails()
                return admins[0], "api_key"

        return None, None

    def _is_admin(self, email: Optional[str]) -> bool:
        if not email:
            return False
        return email.lower() in [e.lower() for e in get_admin_emails()]

    def _require_admin(self) -> bool:
        """Verify the request is from an authorized admin.

        If unauthenticated, sends 401 Unauthorized and returns False.
        If authenticated but not in admin_emails, sends 403 Forbidden and returns False.
        If authorized, returns True.
        """
        email, _ = self._authenticate_request()
        if not email:
            self._send_json(
                {"error": "Unauthorized: Authentication required"},
                status=401,
            )
            return False
        if not self._is_admin(email):
            self._send_json(
                {"error": "Forbidden: Administrator privileges required"},
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

        # 2. Admin Console: Accessible only with admin authentication
        if path in ("/admin", "/admin/"):
            email, auth_source = self._authenticate_request()
            if not email:
                self._send_html(
                    "<h1>401 Unauthorized</h1><p>Authentication required to access the admin console.</p>",
                    status=401,
                )
                return
            if not self._is_admin(email):
                self._send_html(
                    "<h1>403 Forbidden</h1><p>Access denied: Administrator privileges required.</p>",
                    status=403,
                )
                return

            extra_headers: List[Tuple[str, str]] = []
            cookie_token = self._get_cookie("tracker_session") or self._get_cookie("session")
            has_valid_cookie = False
            if cookie_token:
                with _sessions_lock:
                    sess = _sessions.get(cookie_token)
                    if sess and time.time() <= sess.get("expires_at", float("inf")):
                        has_valid_cookie = True

            if not has_valid_cookie:
                session_id = secrets.token_urlsafe(32)
                with _sessions_lock:
                    _sessions[session_id] = {
                        "email": email,
                        "auth_source": auth_source or "session",
                        "created_at": time.time(),
                        "expires_at": time.time() + 86400,
                    }
                extra_headers.append(
                    ("Set-Cookie", f"tracker_session={session_id}; Path=/; HttpOnly; SameSite=Lax")
                )

            if ADMIN_TEMPLATE_PATH.exists():
                self._send_html(
                    ADMIN_TEMPLATE_PATH.read_text(encoding="utf-8"),
                    extra_headers=extra_headers,
                )
            else:
                self._send_html(
                    "<h1>Admin template not found</h1>",
                    status=404,
                    extra_headers=extra_headers,
                )
            return

        # 3. User metadata endpoint
        if path == "/api/me":
            email, auth_source = self._authenticate_request()
            admins = get_admin_emails()
            if email:
                is_admin = self._is_admin(email)
                self._send_json(
                    {
                        "email": email,
                        "is_admin": is_admin,
                        "is_viewer": True,
                        "auth_source": auth_source or "authenticated",
                        "allowed_admins": admins,
                    }
                )
            else:
                self._send_json(
                    {
                        "email": "unauthenticated",
                        "is_admin": False,
                        "is_viewer": True,
                        "auth_source": "none",
                        "allowed_admins": admins,
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
            cookie_token = self._get_cookie("tracker_session") or self._get_cookie("session")
            if cookie_token:
                with _sessions_lock:
                    _sessions.pop(cookie_token, None)
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header(
                "Set-Cookie",
                "tracker_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0",
            )
            self.end_headers()
            return

        self._send_json({"error": "Not found"}, status=404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        # Logout
        if path == "/api/auth/logout":
            cookie_token = self._get_cookie("tracker_session") or self._get_cookie("session")
            if cookie_token:
                with _sessions_lock:
                    _sessions.pop(cookie_token, None)
            self._send_json(
                {"message": "로그아웃되었습니다."},
                extra_headers=[
                    (
                        "Set-Cookie",
                        "tracker_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0",
                    )
                ],
            )
            return

        # Login
        if path == "/api/auth/login":
            email, auth_source = self._authenticate_request()
            body = self._read_json_body()
            req_email = (body.get("email") or "").strip().lower()
            token = (body.get("token") or body.get("password") or "").strip()
            admin_secret = os.environ.get("ADMIN_API_KEY") or os.environ.get("ADMIN_TOKEN") or os.environ.get("ADMIN_PASSWORD")

            if admin_secret and token == admin_secret:
                email = req_email or get_admin_emails()[0]
                auth_source = "password"
            elif not email and req_email and req_email in [e.lower() for e in get_admin_emails()]:
                if token and token.lower() == req_email:
                    email = req_email
                    auth_source = "token"

            if not email:
                self._send_json({"error": "Unauthorized: Invalid credentials"}, status=401)
                return

            if not self._is_admin(email):
                self._send_json({"error": "Forbidden: Administrator privileges required"}, status=403)
                return

            session_id = secrets.token_urlsafe(32)
            with _sessions_lock:
                _sessions[session_id] = {
                    "email": email,
                    "auth_source": auth_source or "login",
                    "created_at": time.time(),
                    "expires_at": time.time() + 86400,
                }
            self._send_json(
                {"message": "로그인되었습니다.", "email": email},
                extra_headers=[
                    ("Set-Cookie", f"tracker_session={session_id}; Path=/; HttpOnly; SameSite=Lax")
                ],
            )
            return

        # DB Reset and Crawl (Admin only)
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

        # Crawl (Admin only)
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

        # Add or update product (Admin only)
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

        # Settings update (Admin only)
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

        # Snapshot date update (Admin only)
        m = re.match(r"^/api/products/([^/]+)/snapshot$", path)
        if m:
            if not self._require_admin():
                return
            slug = m.group(1)
            body = self._read_json_body()
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
