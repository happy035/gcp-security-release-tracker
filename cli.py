#!/usr/bin/env python3
"""
GCP Security Release Notes Tracker CLI & Server Runner
"""
import argparse
import sys
from pathlib import Path

from src.crawler import GCPSecurityReleaseCrawler
from src.database import ReleaseDatabase
from src.server import run_server


def cmd_init(db: ReleaseDatabase) -> None:
    synced = db.sync_products_from_config()
    products = db.get_products()
    print(f"✅ 데이터베이스 초기화 및 config/products.json 동기화 완료 (신규 추가: {synced}건, 총 제품: {len(products)}개)")
    for p in products:
        state = "활성(Enabled)" if p["enabled"] else "비활성(Disabled)"
        print(
            f"  - [{p['slug']}] {p['name']} ({state}) | 스냅샷 기준일: {p['snapshot_date']} | URL: {p['release_notes_url']}"
        )


def cmd_crawl(
    db: ReleaseDatabase,
    product_slug: str | None,
    since_date: str | None,
    reset_after_since: bool,
) -> None:
    db.sync_products_from_config()
    crawler = GCPSecurityReleaseCrawler(db)

    if product_slug:
        if since_date and reset_after_since:
            db.update_product_snapshot(
                slug=product_slug,
                snapshot_date=since_date,
                clear_after_date=True,
                toggle_enabled=True,
            )
            print(f"🔄 [{product_slug}] 스냅샷 기준일을 {since_date}로 초기화하고 이후 데이터를 정리했습니다.")

        res = crawler.crawl_product(
            product_slug=product_slug,
            override_baseline_date=since_date,
        )
        _print_crawl_result(res)
    else:
        if since_date and reset_after_since:
            for prod in db.get_products(enabled_only=True):
                db.update_product_snapshot(
                    slug=prod["slug"],
                    snapshot_date=since_date,
                    clear_after_date=True,
                )
        results = crawler.crawl_all_enabled(override_baseline_date=since_date)
        for res in results:
            _print_crawl_result(res)


def _print_crawl_result(res: dict) -> None:
    if res["status"] == "SUCCESS":
        print(
            f"✅ [{res['product_name']}] 크롤링 성공\n"
            f"   - 원본 페이지 전체 항목 수 : {res.get('total_page_items', 0)}건\n"
            f"   - 스캔 기준 스냅샷 날짜    : {res['baseline_date']}\n"
            f"   - 기준일 이후 스캔된 항목  : {res['scanned_count']}건 (DB 신규 추가: +{res['inserted_count']}건, 업데이트: {res['updated_count']}건)\n"
            f"   - 갱신된 스냅샷 날짜       : {res['new_snapshot_date']}"
        )
    else:
        print(f"❌ [{res['product_name']}] 크롤링 실패: {res['message']}")


def cmd_status(db: ReleaseDatabase) -> None:
    db.sync_products_from_config()
    products = db.get_products()
    print("\n=== 📊 GCP 보안 제품 스냅샷 & 수집 현황 ===")
    for p in products:
        state = "🟢 ON " if p["enabled"] else "⚪ OFF"
        print(
            f"{state} | {p['name']} ({p['slug']})\n"
            f"       현재 스냅샷 기준일: {p['snapshot_date']} | 수집된 릴리즈 노트: {p['total_releases']}건 (Feature: {p['feature_count'] or 0}건)\n"
            f"       최근 크롤링 시각  : {p['last_crawled_at'] or '-'}"
        )

    snapshots = db.get_snapshots(limit=5)
    if snapshots:
        print("\n=== 🕒 최근 크롤링 스냅샷 이력 (최근 5건) ===")
        for s in snapshots:
            print(
                f"  #{s['id']} [{s['product_name']}] {s['baseline_date']} -> {s['new_snapshot_date']} "
                f"| 스캔 {s['scanned_count']}건 (신규 +{s['inserted_count']} / 갱신 {s['updated_count']}) | {s['crawled_at']}"
            )


def cmd_list(
    db: ReleaseDatabase,
    product_slug: str | None,
    release_type: str | None,
    since_date: str | None,
    limit: int,
) -> None:
    items = db.get_release_notes(
        product_slug=product_slug,
        release_type=release_type,
        since_date=since_date,
        limit=limit,
    )
    print(f"\n=== 📋 수집된 릴리즈 노트 목록 (조회 결과: {len(items)}건) ===")
    for item in items:
        print(
            f"[{item['release_date']}] ({item['release_type']}) {item['product_name']}\n"
            f"  요약: {item['summary']}\n"
            f"  원문: {item['source_url']}"
        )
        if item.get("links"):
            links_preview = ", ".join(f"{l['title']}" for l in item["links"][:3])
            print(f"  관련 문서: {links_preview}")
        print("-" * 76)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="GCP Security Release Notes Snapshot Crawler & Web Server"
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init", help="DB 스키마 초기화 및 config/products.json 동기화")

    crawl_p = sub.add_parser("crawl", help="스냅샷 기준일 이후 신규 릴리즈 노트 스캔 및 DB 저장")
    crawl_p.add_argument("--product", "-p", help="특정 제품 slug (예: security-command-center)")
    crawl_p.add_argument(
        "--since",
        "-s",
        help="스냅샷 기준 날짜 지정 (YYYY-MM-DD, 지정한 날짜 이후의 릴리즈 노트를 스캔)",
    )
    crawl_p.add_argument(
        "--reset",
        action="store_true",
        help="--since 날짜 이후의 기존 DB 데이터를 지우고 재스캔 테스트 수행",
    )

    sub.add_parser("status", help="등록된 제품별 스냅샷 기준일 및 DB 수집 통계 출력")

    list_p = sub.add_parser("list", help="DB에 저장된 릴리즈 노트 조회")
    list_p.add_argument("--product", "-p", default="security-command-center")
    list_p.add_argument("--type", "-t", default="all", help="Feature, Deprecated, Changed 등")
    list_p.add_argument("--since", "-s", help="특정 날짜(YYYY-MM-DD) 이후만 표시")
    list_p.add_argument("--limit", "-n", type=int, default=15)

    import os
    serve_p = sub.add_parser("serve", help="제품별 릴리즈 노트 조회 웹 서버 실행")
    serve_p.add_argument("--host", default="127.0.0.1")
    serve_p.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))

    args = parser.parse_args()
    db = ReleaseDatabase()

    if args.command == "init":
        cmd_init(db)
    elif args.command == "crawl":
        cmd_crawl(db, args.product, args.since, args.reset)
    elif args.command == "status":
        cmd_status(db)
    elif args.command == "list":
        cmd_list(db, args.product, args.type, args.since, args.limit)
    elif args.command == "serve":
        run_server(host=args.host, port=args.port, db=db)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
