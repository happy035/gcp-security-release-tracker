import hashlib
import html
import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NameResolutionError, NewConnectionError
from urllib3.poolmanager import PoolManager
from urllib3.util.connection import _DEFAULT_TIMEOUT, _set_socket_options

try:
    from src.database import ReleaseDatabase
except ImportError:
    from database import ReleaseDatabase

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)

ALLOWED_SCHEMES = {"https"}
ALLOWED_DOMAINS = {
    "cloud.google.com",
    "docs.cloud.google.com",
    "cloud.google",
    "docs.cloud.google",
}


def is_safe_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check that the IP address does not belong to private, loopback, link-local, or reserved ranges."""
    if (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    ):
        return False
    return True


def validate_release_notes_url(url: str) -> List[str]:
    """
    Validate that release_notes_url uses HTTPS, targets an allowed Google Cloud domain,
    and resolves to safe, public IP addresses to protect against SSRF.
    Returns the list of validated safe IP addresses.
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")

    parsed = urlparse(url.strip())
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError(f"Invalid URL scheme '{parsed.scheme}'. Only HTTPS is allowed.")

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise ValueError("URL must include a valid hostname")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing authentication credentials are not allowed")

    if parsed.port and parsed.port != 443:
        raise ValueError(f"Port {parsed.port} is not allowed. Only HTTPS port 443 is permitted.")

    if hostname not in ALLOWED_DOMAINS:
        raise ValueError(
            f"Disallowed domain '{hostname}'. Only Google Cloud documentation domains are permitted."
        )

    try:
        addr_info = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve host '{hostname}': {e}")

    if not addr_info:
        raise ValueError(f"Could not resolve host '{hostname}'")

    safe_ips: List[str] = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise ValueError(f"Invalid IP address resolved: {ip_str}")

        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped

        if not is_safe_ip(ip_obj):
            raise ValueError(f"Access to private/internal IP address '{ip_str}' is blocked")
        if ip_str not in safe_ips:
            safe_ips.append(ip_str)

    return safe_ips

DATE_FORMATS = [
    "%B %d, %Y",   # September 16, 2026
    "%b %d, %Y",   # Sep 16, 2026
    "%Y-%m-%d",    # 2026-09-16
    "%d %B %Y",    # 16 September 2026
]


def parse_release_date(raw_date_str: str) -> Optional[str]:
    """Parse human-readable date string like 'September 16, 2026' into 'YYYY-MM-DD'."""
    cleaned = re.sub(r"\s+", " ", html.unescape(raw_date_str)).strip()
    for fmt in DATE_FORMATS:
        try:
            dt = datetime.strptime(cleaned, fmt)
            return dt.strftime("%Y-%m-%d")
        except ValueError:
            continue
    return None


class _HTMLTextAndLinkExtractor(HTMLParser):
    """Extracts plain text and anchor links from a release note HTML snippet."""

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.text_parts: List[str] = []
        self.links: List[Dict[str, str]] = []
        self._current_href: Optional[str] = None
        self._current_link_text: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr_dict = dict(attrs)
        if tag in ("p", "li", "br", "ul", "ol", "div", "h3", "h4"):
            self.text_parts.append(" ")
        if tag == "li":
            self.text_parts.append("• ")
        if tag == "a":
            href = attr_dict.get("href")
            if href:
                self._current_href = urljoin(self.base_url, href)
                self._current_link_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag in ("p", "li", "div", "h3", "h4"):
            self.text_parts.append("\n")
        if tag == "a" and self._current_href:
            link_title = re.sub(r"\s+", " ", "".join(self._current_link_text)).strip()
            if link_title and not any(
                l["url"] == self._current_href and l["title"] == link_title
                for l in self.links
            ):
                self.links.append({"title": link_title, "url": self._current_href})
            self._current_href = None
            self._current_link_text = []

    def handle_data(self, data: str) -> None:
        normalized = re.sub(r"\s+", " ", data)
        self.text_parts.append(normalized)
        if self._current_href is not None:
            self._current_link_text.append(normalized)

    def get_clean_text(self) -> str:
        raw = "".join(self.text_parts)
        lines = [re.sub(r"[ \t]+", " ", line).strip() for line in raw.splitlines()]
        non_empty = [line for line in lines if line]
        return "\n".join(non_empty)


def normalize_html_links(html_fragment: str, base_url: str) -> str:
    """Convert relative href/src attributes in HTML snippet to absolute URLs with target='_blank'."""

    def _replace_href(match: re.Match) -> str:
        quote = match.group(1)
        url = match.group(2)
        abs_url = urljoin(base_url, url)
        return f'href={quote}{abs_url}{quote} target="_blank" rel="noopener noreferrer"'

    return re.sub(r'href=(["\'])([^"\']+)\1', _replace_href, html_fragment)


def extract_summary(content_text: str) -> str:
    """Create a concise headline/summary from the first sentence or line of a release note."""
    first_line = content_text.split("\n")[0].strip().lstrip("•").strip()
    # Split at the first period followed by a space, unless it's a version number like 1.2.0
    sentence_match = re.match(r"^(.{20,180}?\.)(?:\s|$)", first_line)
    if sentence_match:
        return sentence_match.group(1).strip()
    if len(first_line) > 160:
        return first_line[:157].rstrip() + "..."
    return first_line or "Release update"


def parse_gcp_release_notes_html(
    raw_html: str, product_slug: str, page_url: str
) -> List[Dict[str, Any]]:
    """
    Parse Google Cloud release notes HTML page (<section class="releases">)
    into structured release note dictionaries sorted by release_date DESC.
    """
    # Isolate <section class="releases"> if present
    section_match = re.search(
        r'<section[^>]*class=["\'][^"\']*\breleases\b[^"\']*["\'][^>]*>(.*?)</section>',
        raw_html,
         flags=re.DOTALL | re.IGNORECASE,
    )
    releases_body = section_match.group(1) if section_match else raw_html

    # Find all <h2 ...> date headings and their positions
    h2_pattern = re.compile(
        r'<h2(?P<attrs>[^>]*)>(?P<inner>.*?)</h2>',
        flags=re.DOTALL | re.IGNORECASE,
    )
    h2_matches = list(h2_pattern.finditer(releases_body))

    parsed_items: List[Dict[str, Any]] = []

    for idx, h2_match in enumerate(h2_matches):
        attrs_str = h2_match.group("attrs")
        inner_html = h2_match.group("inner")

        # Extract date text from data-text or inner HTML stripped of tags
        data_text_match = re.search(r'data-text=["\']([^"\']+)["\']', attrs_str)
        raw_date_display = (
            data_text_match.group(1).strip()
            if data_text_match
            else re.sub(r"<[^>]+>", "", inner_html).strip()
        )

        release_date = parse_release_date(raw_date_display)
        if not release_date:
            continue

        id_match = re.search(r'id=["\']([^"\']+)["\']', attrs_str)
        anchor_id = id_match.group(1).strip() if id_match else ""
        source_url = f"{page_url}#{anchor_id}" if anchor_id else page_url

        # Slice the HTML chunk between this <h2> and the next <h2>
        chunk_start = h2_match.end()
        chunk_end = (
            h2_matches[idx + 1].start()
            if idx + 1 < len(h2_matches)
            else len(releases_body)
        )
        date_chunk = releases_body[chunk_start:chunk_end]

        # Split by <div class="devsite-release-note"> blocks
        note_starts = [
            m.start()
            for m in re.finditer(
                r'<div[^>]*class=["\'][^"\']*\bdevsite-release-note\b[^"\']*["\'][^>]*>',
                date_chunk,
                flags=re.IGNORECASE,
            )
        ]

        for n_idx, n_start in enumerate(note_starts):
            n_end = (
                note_starts[n_idx + 1]
                if n_idx + 1 < len(note_starts)
                else len(date_chunk)
            )
            note_block = date_chunk[n_start:n_end].strip()

            # Extract release_type label from <span class="devsite-label ...">
            label_match = re.search(
                r'<span[^>]*class=["\'][^"\']*\bdevsite-label\b[^"\']*["\'][^>]*>(.*?)</span>',
                note_block,
                flags=re.DOTALL | re.IGNORECASE,
            )
            raw_label = (
                re.sub(r"<[^>]+>", "", label_match.group(1)).strip().title()
                if label_match
                else "Update"
            )
            label_map = {
                "Change": "Changed",
                "Changed": "Changed",
                "Fix": "Fixed",
                "Fixed": "Fixed",
                "Feature": "Feature",
                "Deprecated": "Deprecated",
                "Deprecation": "Deprecated",
                "Announcement": "Announcement",
                "Issue": "Issue",
                "Security": "Security",
            }
            release_type = label_map.get(raw_label, raw_label)

            # Remove outer <div class="devsite-release-note"> wrapper and the label <span>
            inner_note = re.sub(
                r'^<div[^>]*class=["\'][^"\']*\bdevsite-release-note\b[^"\']*["\'][^>]*>',
                "",
                note_block,
                count=1,
                flags=re.IGNORECASE,
            )
            if label_match:
                inner_note = inner_note.replace(label_match.group(0), "", 1)

            # Strip trailing closing </div> from the outer wrapper
            inner_note = re.sub(r"</div>\s*$", "", inner_note.strip(), count=1).strip()
            # Also unwrap a single outer <div>...</div> if present
            if inner_note.startswith("<div>") and inner_note.endswith("</div>"):
                inner_note = inner_note[5:-6].strip()

            normalized_html = normalize_html_links(inner_note, page_url)

            extractor = _HTMLTextAndLinkExtractor(page_url)
            extractor.feed(inner_note)
            content_text = extractor.get_clean_text()
            if not content_text:
                continue

            summary = extract_summary(content_text)

            # Web Security Scanner's URL redirects to Security Command Center release notes.
            # Filter only items related to Web Security Scanner to prevent duplicating general SCC notes.
            if product_slug == "web-security-scanner":
                lower_text = content_text.lower()
                if "web security scanner" not in lower_text and "security scanner" not in lower_text:
                    continue

            normalized_key = re.sub(r"\s+", " ", summary).strip().lower()
            content_hash = hashlib.sha256(
                f"{product_slug}|{release_date}|{release_type.lower()}|{normalized_key}".encode(
                    "utf-8"
                )
            ).hexdigest()

            item_dict = {
                "release_date": release_date,
                "release_date_display": raw_date_display,
                "release_type": release_type,
                "summary": summary,
                "content_text": content_text,
                "content_html": normalized_html,
                "links": extractor.links,
                "source_url": source_url,
                "content_hash": content_hash,
            }

            # If an item with the same content_hash (same product, date, type, and headline summary)
            # was already seen on the page, keep the one with longer content_text.
            existing_idx = next(
                (i for i, x in enumerate(parsed_items) if x["content_hash"] == content_hash),
                None,
            )
            if existing_idx is not None:
                if len(content_text) > len(parsed_items[existing_idx]["content_text"]):
                    parsed_items[existing_idx] = item_dict
            else:
                parsed_items.append(item_dict)

    return parsed_items


def _connect_to_ip(
    ip_str: str,
    port: int,
    timeout: Any,
    source_address: Optional[Tuple[str, int]] = None,
    socket_options: Any = None,
) -> socket.socket:
    cleaned_ip = ip_str.strip("[]")
    ip_obj = ipaddress.ip_address(cleaned_ip)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped
    if not is_safe_ip(ip_obj):
        raise ValueError(f"Access to private/internal IP address '{cleaned_ip}' is blocked")

    af = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
    sock = socket.socket(af, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    try:
        _set_socket_options(sock, socket_options)
        if timeout is not None and timeout != _DEFAULT_TIMEOUT:
            if isinstance(timeout, (int, float)):
                sock.settimeout(timeout)
            elif hasattr(timeout, "connect_timeout") and isinstance(timeout.connect_timeout, (int, float)):
                sock.settimeout(timeout.connect_timeout)
        if source_address:
            sock.bind(source_address)
        sa = (cleaned_ip, port, 0, 0) if ip_obj.version == 6 else (cleaned_ip, port)
        sock.connect(sa)
        return sock
    except Exception:
        sock.close()
        raise


class SSRFProtectedPoolManager(PoolManager):
    def __init__(self, *args, pinned_ips: Optional[Dict[str, str]] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.pinned_ips = pinned_ips if pinned_ips is not None else {}
        self.pool_classes_by_scheme["https"] = self._create_pool_class()

    def _create_pool_class(self):
        pool_manager = self

        class SSRFProtectedHTTPSConnection(HTTPSConnection):
            def _new_conn(self) -> socket.socket:
                host = self._dns_host
                port = self.port or 443
                pinned_ip = pool_manager.pinned_ips.get(host)
                if not pinned_ip:
                    addr_info = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
                    if not addr_info:
                        raise ValueError(f"Could not resolve host '{host}'")
                    for entry in addr_info:
                        ip_str = entry[4][0]
                        ip_obj = ipaddress.ip_address(ip_str.strip("[]"))
                        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
                            ip_obj = ip_obj.ipv4_mapped
                        if not is_safe_ip(ip_obj):
                            raise ValueError(f"Access to private/internal IP address '{ip_str}' is blocked")
                    pinned_ip = addr_info[0][4][0]

                try:
                    sock = _connect_to_ip(
                        pinned_ip,
                        port,
                        timeout=self.timeout,
                        source_address=self.source_address,
                        socket_options=self.socket_options,
                    )
                except socket.gaierror as e:
                    raise NameResolutionError(self.host, self, e) from e
                except socket.timeout as e:
                    raise ConnectTimeoutError(
                        self,
                        f"Connection to {self.host} timed out. (connect timeout={self.timeout})",
                    ) from e
                except OSError as e:
                    raise NewConnectionError(
                        self, f"Failed to establish a new connection: {e}"
                    ) from e

                return sock

        class SSRFProtectedHTTPSConnectionPool(HTTPSConnectionPool):
            ConnectionCls = SSRFProtectedHTTPSConnection

        return SSRFProtectedHTTPSConnectionPool


class SSRFProtectedHTTPAdapter(HTTPAdapter):
    def __init__(self, pinned_ips: Optional[Dict[str, str]] = None, **kwargs):
        self.pinned_ips = pinned_ips if pinned_ips is not None else {}
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self.poolmanager = SSRFProtectedPoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            pinned_ips=self.pinned_ips,
            **pool_kwargs,
        )


class GCPSecurityReleaseCrawler:
    """Fetches GCP Security product release notes and scans updates after the snapshot date."""

    def __init__(self, db: Optional[ReleaseDatabase] = None):
        self.db = db or ReleaseDatabase()

    def fetch_html(self, url: str, timeout: int = 25) -> str:
        current_url = url
        max_redirects = 5
        pinned_ips: Dict[str, str] = {}
        adapter = SSRFProtectedHTTPAdapter(pinned_ips=pinned_ips)
        with requests.Session() as session:
            session.mount("https://", adapter)
            for _ in range(max_redirects):
                safe_ips = validate_release_notes_url(current_url)
                parsed = urlparse(current_url.strip())
                hostname = (parsed.hostname or "").strip().lower()
                if safe_ips:
                    pinned_ips[hostname] = safe_ips[0]

                resp = session.get(
                    current_url,
                    headers={"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"},
                    timeout=timeout,
                    allow_redirects=False,
                )
                if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location")
                    if not location:
                        raise ValueError(f"Redirect response missing Location header from {current_url}")
                    current_url = urljoin(current_url, location)
                    continue
                resp.raise_for_status()
                return resp.text
        raise ValueError(f"Too many redirects from {url}")

    def crawl_product(
        self,
        product_slug: str,
        override_baseline_date: Optional[str] = None,
        include_same_day: bool = False,
    ) -> Dict[str, Any]:
        """
        Crawl a single product's release notes page:
        1. Uses `override_baseline_date` if given, else `product['snapshot_date']`.
        2. Filters items published after (`>`) the snapshot date (or `>=` if `include_same_day=True`).
        3. Updates the database and advances `snapshot_date` to the latest release date found.
        """
        product = self.db.get_product_by_slug(product_slug)
        if not product:
            raise ValueError(f"등록되지 않은 제품입니다: {product_slug}")

        baseline_date = (override_baseline_date or product["snapshot_date"]).strip()
        url = product["release_notes_url"]

        try:
            raw_html = self.fetch_html(url)
            all_items = parse_gcp_release_notes_html(raw_html, product_slug, url)

            if include_same_day:
                filtered_items = [
                    item for item in all_items if item["release_date"] >= baseline_date
                ]
            else:
                filtered_items = [
                    item for item in all_items if item["release_date"] > baseline_date
                ]

            # Sort ascending by release_date so older items get lower IDs and newest date is clear
            filtered_items.sort(key=lambda x: x["release_date"])

            if filtered_items:
                latest_date = max(item["release_date"] for item in filtered_items)
                new_snapshot_date = max(baseline_date, latest_date)
            else:
                new_snapshot_date = baseline_date

            msg = (
                f"총 {len(all_items)}건의 전체 릴리즈 노트 중 스냅샷 기준일({baseline_date}) "
                f"이후 {len(filtered_items)}건을 스캔했습니다."
            )
            snapshot_record = self.db.record_crawl_result(
                product_id=product["id"],
                baseline_date=baseline_date,
                new_snapshot_date=new_snapshot_date,
                items=filtered_items,
                status="SUCCESS",
                message=msg,
            )
            return {
                "product_slug": product_slug,
                "product_name": product["name"],
                "url": url,
                "total_page_items": len(all_items),
                "baseline_date": baseline_date,
                "new_snapshot_date": new_snapshot_date,
                "scanned_count": snapshot_record["scanned_count"],
                "inserted_count": snapshot_record["inserted_count"],
                "updated_count": snapshot_record["updated_count"],
                "status": "SUCCESS",
                "message": msg,
                "snapshot_id": snapshot_record["id"],
            }
        except Exception as exc:
            err_msg = f"크롤링 실패 ({url}): {exc}"
            self.db.record_crawl_result(
                product_id=product["id"],
                baseline_date=baseline_date,
                new_snapshot_date=baseline_date,
                items=[],
                status="FAILED",
                message=err_msg,
            )
            return {
                "product_slug": product_slug,
                "product_name": product["name"],
                "url": url,
                "baseline_date": baseline_date,
                "new_snapshot_date": baseline_date,
                "scanned_count": 0,
                "inserted_count": 0,
                "updated_count": 0,
                "status": "FAILED",
                "message": err_msg,
            }

    def crawl_all_enabled(
        self, override_baseline_date: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        products = self.db.get_products(enabled_only=True)
        if not products:
            return []

        max_workers = min(8, len(products))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(
                    self.crawl_product,
                    prod["slug"],
                    override_baseline_date=override_baseline_date,
                )
                for prod in products
            ]
            return [fut.result() for fut in futures]
