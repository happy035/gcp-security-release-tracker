import hashlib
import html
import ipaddress
import re
import socket
from datetime import datetime
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

from src.database import ReleaseDatabase

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)

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


ALLOWED_RELEASE_NOTE_DOMAINS = {
    "cloud.google.com",
    "docs.cloud.google.com",
}


def is_allowed_domain(hostname: str) -> bool:
    """Check if the given hostname is an allowed Google Cloud documentation domain."""
    hostname = hostname.lower().strip()
    return hostname in ALLOWED_RELEASE_NOTE_DOMAINS or hostname.endswith(".cloud.google.com")


def validate_release_notes_url(url: str) -> None:
    """
    Validate that release_notes_url points to an authorized Google Cloud documentation endpoint.
    Prevents Server-Side Request Forgery (SSRF) and access to internal/private resources.
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL이 비어 있습니다.")

    url = url.strip()
    try:
        parsed = urlparse(url)
    except Exception:
        raise ValueError("유효하지 않은 URL 형식입니다.")

    if parsed.scheme.lower() != "https":
        raise ValueError("HTTPS 프로토콜만 허용됩니다.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("호스트명이 유효하지 않습니다.")

    hostname = hostname.lower().strip()

    if parsed.username or parsed.password:
        raise ValueError("사용자 인증 정보가 포함된 URL은 허용되지 않습니다.")

    if parsed.port is not None and parsed.port != 443:
        raise ValueError("표준 HTTPS 포트(443)만 허용됩니다.")

    # Reject IP address literals directly
    try:
        ipaddress.ip_address(hostname)
        raise ValueError("IP 주소 직접 접근은 허용되지 않습니다.")
    except ValueError as val_err:
        if "IP 주소 직접 접근" in str(val_err):
            raise

    # Hostname whitelist
    if not is_allowed_domain(hostname):
        raise ValueError(
            "허용되지 않은 도메인입니다. Google Cloud 공식 문서 도메인만 지원됩니다."
        )

    # Check DNS resolution for internal/private/link-local IP addresses
    try:
        addr_info = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
        for entry in addr_info:
            sockaddr = entry[4]
            ip_str = sockaddr[0]
            try:
                ip = ipaddress.ip_address(ip_str)
                if (
                    ip.is_loopback
                    or ip.is_private
                    or ip.is_link_local
                    or ip.is_multicast
                    or ip.is_reserved
                    or ip.is_unspecified
                ):
                    raise ValueError("내부 또는 비공개 IP 주소는 허용되지 않습니다.")
            except ValueError as ip_err:
                if "내부 또는 비공개 IP" in str(ip_err):
                    raise
    except socket.gaierror:
        # If DNS cannot be resolved (e.g. offline environment/isolated test sandbox),
        # the domain has already been strictly validated against allowed Google Cloud domains.
        pass


class SSRFSafeSession(requests.Session):
    """Requests Session that validates destination URL on every request and redirect."""

    def send(self, request, **kwargs):
        validate_release_notes_url(request.url)
        return super().send(request, **kwargs)


class GCPSecurityReleaseCrawler:
    """Fetches GCP Security product release notes and scans updates after the snapshot date."""

    def __init__(self, db: Optional[ReleaseDatabase] = None):
        self.db = db or ReleaseDatabase()

    def fetch_html(self, url: str, timeout: int = 25) -> str:
        validate_release_notes_url(url)
        with SSRFSafeSession() as session:
            resp = session.get(
                url,
                headers={"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"},
                timeout=timeout,
            )
            resp.raise_for_status()
            return resp.text

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
            if isinstance(exc, ValueError):
                err_msg = f"크롤링 실패 ({url}): {exc}"
            elif isinstance(exc, requests.Timeout):
                err_msg = f"크롤링 실패 ({url}): 요청 시간이 초과되었습니다."
            elif isinstance(exc, requests.HTTPError):
                code = exc.response.status_code if exc.response is not None else ""
                err_msg = f"크롤링 실패 ({url}): 원격 서버 HTTP 오류 ({code})"
            elif isinstance(exc, requests.RequestException):
                err_msg = f"크롤링 실패 ({url}): 원격 서버에 연결할 수 없습니다."
            else:
                err_msg = f"크롤링 실패 ({url}): 데이터 처리 중 오류가 발생했습니다."
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
        results = []
        for prod in products:
            res = self.crawl_product(
                prod["slug"], override_baseline_date=override_baseline_date
            )
            results.append(res)
        return results
