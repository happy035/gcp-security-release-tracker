import json
import os
import sqlite3
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
from pathlib import Path

from server import ReleaseTrackerHTTPRequestHandler
from database import ReleaseDatabase


class TestServerAuthentication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        db_path = Path(cls.temp_dir.name) / "test.db"
        cls.db = ReleaseDatabase(db_path=db_path)
        ReleaseTrackerHTTPRequestHandler.db = cls.db
        ReleaseTrackerHTTPRequestHandler.is_bootstrapping = False
        ReleaseTrackerHTTPRequestHandler.bootstrap_done_event.set()

        # Set configured admin token for token tests
        ReleaseTrackerHTTPRequestHandler.configured_admin_token = "test-secret-token"

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ReleaseTrackerHTTPRequestHandler)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.temp_dir.cleanup()

    def _request(self, path, method="GET", payload=None, headers=None):
        url = f"{self.base_url}{path}"
        req_headers = dict(headers or {})
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            req_headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode("utf-8")
                return resp.status, json.loads(body) if resp.headers.get_content_type() == "application/json" else body
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = body
            return e.code, parsed

    # 1. Unauthenticated tests
    def test_unauthenticated_api_me(self):
        status, body = self._request("/api/me")
        self.assertEqual(status, 200)
        self.assertFalse(body.get("is_admin"))
        self.assertEqual(body.get("auth_source"), "none")
        self.assertEqual(body.get("email"), "")

    def test_unauthenticated_admin_page(self):
        status, body = self._request("/admin")
        self.assertEqual(status, 401)

    def test_unauthenticated_reset_and_crawl(self):
        status, body = self._request("/api/reset-and-crawl", method="POST")
        self.assertEqual(status, 401)

    def test_unauthenticated_settings_put(self):
        status, body = self._request("/api/settings", method="PUT", payload={"auto_update_time": "04:00"})
        self.assertEqual(status, 401)

    def test_unauthenticated_products_post(self):
        status, body = self._request("/api/products", method="POST", payload={"slug": "test", "name": "Test", "release_notes_url": "https://cloud.google.com/armor/docs/release-notes"})
        self.assertEqual(status, 401)

    def test_unauthenticated_crawl_post(self):
        status, body = self._request("/api/crawl", method="POST", payload={})
        self.assertEqual(status, 401)

    def test_unauthenticated_product_snapshot_put(self):
        status, body = self._request("/api/products/test/snapshot", method="PUT", payload={"snapshot_date": "2026-01-01"})
        self.assertEqual(status, 401)

    # 2. Public endpoints work without auth
    def test_public_dashboard_get(self):
        status, body = self._request("/")
        self.assertEqual(status, 200)

    def test_public_products_get(self):
        status, body = self._request("/api/products")
        self.assertEqual(status, 200)
        self.assertIn("products", body)

    def test_public_settings_get(self):
        status, body = self._request("/api/settings")
        self.assertEqual(status, 200)
        self.assertIn("settings", body)

    def test_public_logout_post(self):
        status, body = self._request("/api/auth/logout", method="POST")
        self.assertEqual(status, 200)

    # 3. Non-admin user tests (Forbidden)
    def test_non_admin_forbidden_on_admin_operations(self):
        headers = {"X-Goog-Authenticated-User-Email": "viewer@example.com"}
        status, body = self._request("/api/me", headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(body.get("email"), "viewer@example.com")
        self.assertFalse(body.get("is_admin"))

        status, _ = self._request("/admin", headers=headers)
        self.assertEqual(status, 403)

        status, _ = self._request("/api/reset-and-crawl", method="POST", headers=headers)
        self.assertEqual(status, 403)

        status, _ = self._request("/api/settings", method="PUT", payload={"auto_update_time": "04:00"}, headers=headers)
        self.assertEqual(status, 403)

    # 4. Admin user via GCP IAP header
    def test_admin_iap_user(self):
        headers = {"X-Goog-Authenticated-User-Email": "accounts.google.com:dragon@jayseo.altostrat.com"}
        status, body = self._request("/api/me", headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(body.get("email"), "dragon@jayseo.altostrat.com")
        self.assertTrue(body.get("is_admin"))
        self.assertEqual(body.get("auth_source"), "gcp_iap")

        # Admin page access
        status, body = self._request("/admin", headers=headers)
        self.assertEqual(status, 200)

        # Admin settings PUT
        status, body = self._request("/api/settings", method="PUT", payload={"auto_update_time": "06:30"}, headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(body.get("settings", {}).get("auto_update_time"), "06:30")

    # 5. Bearer token auth
    def test_admin_bearer_token(self):
        headers = {"Authorization": "Bearer test-secret-token"}
        status, body = self._request("/api/me", headers=headers)
        self.assertEqual(status, 200)
        self.assertTrue(body.get("is_admin"))
        self.assertEqual(body.get("auth_source"), "token")

        # Admin settings PUT with bearer token
        status, body = self._request("/api/settings", method="PUT", payload={"auto_update_time": "07:15"}, headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(body.get("settings", {}).get("auto_update_time"), "07:15")

    def test_invalid_bearer_token(self):
        headers = {"Authorization": "Bearer wrong-token"}
        status, body = self._request("/api/reset-and-crawl", method="POST", headers=headers)
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
