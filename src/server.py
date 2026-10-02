import base64
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

try:
    from src.crawler import GCPSecurityReleaseCrawler, validate_release_notes_url
    from src.database import DEFAULT_CONFIG_PATH, ReleaseDatabase
except ImportError:
    from crawler import GCPSecurityReleaseCrawler, validate_release_notes_url
    from database import DEFAULT_CONFIG_PATH, ReleaseDatabase

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
INDEX_TEMPLATE_PATH = TEMPLATE_DIR / "index.html"
ADMIN_TEMPLATE_PATH = TEMPLATE_DIR / "admin.html"

DEFAULT_ADMIN_EMAILS: List[str] = ["dragon@jayseo.altostrat.com"]


def get_allowed_admins() -> List[str]:
    raw = os.environ.get("ADMIN_EMAILS") or os.environ.get("ADMIN_USERS") or ""
    env_admins = [e.strip().lower() for e in raw.split(",") if e.strip()]
    admins = list(DEFAULT_ADMIN_EMAILS)
    for a in env_admins:
        if a not in admins:
            admins.append(a)
    return admins


def decode_jwt_payload_unverified(token: str) -> Dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload_segment = parts[1]
        padded = payload_segment + "=" * (-len(payload_segment) % 4)
        raw = base64.urlsafe_b64decode(padded)
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}


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
    active_sessions: Dict[str, Dict[str, Any]] = {}
    configured_admin_token: Optional[str] = None

    def _wait_if_bootstrapping(self, timeout: float = 25.0) -> bool:
        """If an initial empty-DB bootstrap is currently running, wait for it; never trigger a crawl on GET."""
        if self.is_bootstrapping and not self.bootstrap_done_event.is_set():
            self.bootstrap_done_event.wait(timeout=timeout)
        return self.is_bootstrapping

    def _get_current_user(self) -> Dict[str, Any]:
        allowed_admins = get_allowed_admins()

        # 1. Identity-Aware Proxy (IAP) headers
        raw_iap_email = (
            self.headers.get("X-Goog-Authenticated-User-Email")
            or self.headers.get("x-goog-authenticated-user-email")
            or ""
        ).strip()
        raw_jwt = (
            self.headers.get("X-Goog-IAP-JWT-Assertion")
            or self.headers.get("x-goog-iap-jwt-assertion")
            or ""
        ).strip()

        jwt_email = ""
        if raw_jwt:
            payload = decode_jwt_payload_unverified(raw_jwt)
            exp = payload.get("exp")
            if exp is None or not isinstance(exp, (int, float)) or time.time() <= exp:
                jwt_email = str(payload.get("email") or "").strip().lower()

        iap_email = ""
        if raw_iap_email:
            if ":" in raw_iap_email:
                iap_email = raw_iap_email.split(":")[-1].strip().lower()
            else:
                iap_email = raw_iap_email.strip().lower()

        if raw_jwt and raw_iap_email and jwt_email and iap_email:
            if jwt_email != iap_email:
                return {
                    "email": "",
                    "is_admin": False,
                    "is_viewer": False,
                    "auth_source": "invalid",
                    "authenticated": False,
                }

        effective_iap_email = iap_email or jwt_email
        if effective_iap_email:
            is_admin = effective_iap_email in allowed_admins
            return {
                "email": effective_iap_email,
                "is_admin": is_admin,
                "is_viewer": True,
                "auth_source": "gcp_iap",
                "authenticated": True,
            }

        # 2. Authorization Header (Bearer token) or API Key headers
        auth_header = (self.headers.get("Authorization") or "").strip()
        admin_token_header = (
            self.headers.get("X-Admin-Token")
            or self.headers.get("X-API-Key")
            or ""
        ).strip()

        token = ""
        if auth_header:
            if auth_header.lower().startswith("bearer "):
                token = auth_header[7:].strip()
            else:
                token = auth_header
        elif admin_token_header:
            token = admin_token_header

        # 3. Cookie
        cookie_header = self.headers.get("Cookie", "")
        if not token and cookie_header:
            cookies = SimpleCookie()
            try:
                cookies.load(cookie_header)
                if "admin_token" in cookies:
                    token = cookies["admin_token"].value
                elif "session_token" in cookies:
                    token = cookies["session_token"].value
            except Exception:
                pass

        # 4. Query Parameter fallback
        if not token:
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            token_candidates = (
                qs.get("admin_token", [])
                + qs.get("token", [])
                + qs.get("api_key", [])
            )
            if token_candidates:
                token = token_candidates[0].strip()

        configured_token = (
            os.environ.get("ADMIN_TOKEN")
            or os.environ.get("ADMIN_API_KEY")
            or self.configured_admin_token
        )
        if configured_token:
            configured_token = configured_token.strip()

        if token and configured_token and token == configured_token:
            admin_email = os.environ.get(
                "ADMIN_EMAIL", allowed_admins[0] if allowed_admins else "admin@domain.com"
            )
            return {
                "email": admin_email,
                "is_admin": True,
                "is_viewer": True,
                "auth_source": "token",
                "authenticated": True,
            }

        cls = self.__class__
        if token and hasattr(cls, "active_sessions") and token in cls.active_sessions:
            sess = cls.active_sessions[token]
            return {
                "email": sess.get("email", allowed_admins[0]),
                "is_admin": sess.get("is_admin", True),
                "is_viewer": True,
                "auth_source": "session",
                "authenticated": True,
            }

        return {
            "email": "",
            "is_admin": False,
            "is_viewer": True,
            "auth_source": "none",
            "authenticated": False,
        }

    def _require_admin(self) -> Optional[Dict[str, Any]]:
        """Verify caller has admin privileges. If not, send error response and return None."""
        user = self._get_current_user()
        if not user.get("authenticated", False):
            self._send_json(
                {"error": "Unauthorized: Authentication required for this operation."},
                status=401,
                extra_headers=[("WWW-Authenticate", 'Bearer realm="GCP Security Release Tracker"')],
            )
            return None
        if not user.get("is_admin", False):
            self._send_json(
                {"error": "Forbidden: Administrative privileges required."},
                status=403,
            )
            return None
        return user

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
            user = self._get_current_user()
            if not user.get("authenticated", False):
                self._send_html(
                    "<!DOCTYPE html><html><head><title>401 Unauthorized</title></head>"
                    "<body style='font-family:sans-serif;padding:40px;text-align:center;'>"
                    "<h1>401 Unauthorized</h1><p>Admin authentication required to access the Admin Console.</p>"
                    "<p><a href='/'>Return to Main Dashboard</a></p></body></html>",
                    status=401,
                    extra_headers=[("WWW-Authenticate", 'Bearer realm="GCP Security Release Tracker"')],
                )
                return
            if not user.get("is_admin", False):
                self._send_html(
                    "<!DOCTYPE html><html><head><title>403 Forbidden</title></head>"
                    "<body style='font-family:sans-serif;padding:40px;text-align:center;'>"
                    "<h1>403 Forbidden</h1><p>Access denied. Administrative privileges required.</p>"
                    "<p><a href='/'>Return to Main Dashboard</a></p></body></html>",
                    status=403,
                )
                return

            if ADMIN_TEMPLATE_PATH.exists():
                extra_headers = []
                token_param = (
                    qs.get("admin_token", [None])[0]
                    or qs.get("token", [None])[0]
                    or qs.get("api_key", [None])[0]
                )
                if token_param:
                    extra_headers.append(
                        ("Set-Cookie", f"admin_token={token_param}; Path=/; HttpOnly; SameSite=Lax")
                    )
                self._send_html(
                    ADMIN_TEMPLATE_PATH.read_text(encoding="utf-8"),
                    extra_headers=extra_headers if extra_headers else None,
                )
            else:
                self._send_html("<h1>Admin template not found</h1>", status=404)
            return

        # 3. User metadata endpoint
        if path == "/api/me":
            user = self._get_current_user()
            self._send_json(
                {
                    "email": user.get("email", ""),
                    "is_admin": user.get("is_admin", False),
                    "is_viewer": user.get("is_viewer", True),
                    "auth_source": user.get("auth_source", "none"),
                    "allowed_admins": get_allowed_admins(),
                }
            )
            return

        # 4. Settings (read-only for dashboard)
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
            cookie_header = self.headers.get("Cookie", "")
            if cookie_header:
                cookies = SimpleCookie()
                try:
                    cookies.load(cookie_header)
                    if "session_token" in cookies:
                        self.__class__.active_sessions.pop(cookies["session_token"].value, None)
                except Exception:
                    pass
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header(
                "Set-Cookie",
                "session_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax",
            )
            self.send_header(
                "Set-Cookie",
                "admin_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax",
            )
            self.end_headers()
            return

        self._send_json({"error": "Not found"}, status=404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        # Logout
        if path == "/api/auth/logout":
            cookie_header = self.headers.get("Cookie", "")
            if cookie_header:
                cookies = SimpleCookie()
                try:
                    cookies.load(cookie_header)
                    if "session_token" in cookies:
                        self.__class__.active_sessions.pop(cookies["session_token"].value, None)
                except Exception:
                    pass
            extra_headers = [
                ("Set-Cookie", "session_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax"),
                ("Set-Cookie", "admin_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax"),
            ]
            self._send_json({"message": "로그아웃되었습니다."}, extra_headers=extra_headers)
            return

        # Login
        if path == "/api/auth/login":
            body = self._read_json_body()
            token = (body.get("token") or body.get("api_key") or "").strip()
            configured_token = (
                os.environ.get("ADMIN_TOKEN")
                or os.environ.get("ADMIN_API_KEY")
                or self.configured_admin_token
            )
            if configured_token and token == configured_token.strip():
                session_id = secrets.token_hex(24)
                cls = self.__class__
                allowed = get_allowed_admins()
                admin_email = os.environ.get("ADMIN_EMAIL", allowed[0] if allowed else "admin@domain.com")
                cls.active_sessions[session_id] = {
                    "email": admin_email,
                    "is_admin": True,
                    "auth_source": "session",
                }
                extra_headers = [
                    ("Set-Cookie", f"session_token={session_id}; Path=/; HttpOnly; SameSite=Lax")
                ]
                self._send_json(
                    {"status": "OK", "session_token": session_id, "email": admin_email},
                    extra_headers=extra_headers,
                )
                return
            self._send_json({"error": "Invalid credentials"}, status=401)
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

        body = self._read_json_body()

        # Crawl
        if path == "/api/crawl":
            if not self._require_admin():
                return
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

            try:
                validate_release_notes_url(url)
            except ValueError as exc:
                self._send_json(
                    {"error": f"유효하지 않거나 허용되지 않은 release_notes_url입니다: {exc}"},
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
