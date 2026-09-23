# GCP Security Release Notes Tracker (Google Cloud Run)

Google Cloud 보안 제품의 공식 Release Notes 페이지를 자동으로 수집·정규화하여 **일반 사용자용 공개 대시보드(`/`)**와 **`dragon@jayseo.altostrat.com` 전용 관리자 콘솔(`/admin`)**로 분리 제공하는 Cloud Run 기반 릴리즈 트래킹 서비스입니다.

---

## 🌐 운영 서비스 접속 주소 (Google Cloud Run)

* **GCP 프로젝트 / 리전**: `security-demo-319501` / `asia-northeast3` (서울)
* **Cloud Run 서비스명**: `gcp-security-release-tracker`
* **일반 사용자 메인 대시보드 (`/`)**:
  * URL: `https://gcp-security-release-tracker-896350673864.asia-northeast3.run.app`
  * 별도의 로그인이나 인증 절차 없이 즉시 열람 가능한 공개 릴리즈 대시보드입니다. 브라우저 언어 설정에 따라 영문/한글 자동 인식 및 상단 `EN | KO` 전환을 지원합니다.
* **관리자 전용 콘솔 (`/admin`)**:
  * URL: `https://gcp-security-release-tracker-896350673864.asia-northeast3.run.app/admin`
  * 보안 제품 목록 활성화/비활성화, 스냅샷 기준일 설정, 일일 스케줄러 시각 변경 및 수동 즉시 크롤링을 수행할 수 있는 관리 콘솔입니다.

---

## 📁 프로젝트 구조

```text
GCP-Security-release-update/
├── Dockerfile                 # Google Cloud Run 컨테이너 이미지 빌드 설정
├── requirements.txt           # Python 의존성 목록 (requests, beautifulsoup4)
├── config/
│   └── products.json          # 추적 대상 9개 GCP 보안 제품, 일일 자동 스캔 설정(05:00), 관리자 계정(dragon@jayseo.altostrat.com)
├── data/
│   └── gcp_security_releases.db # SQLite 데이터베이스 (제품, 릴리즈 노트, 스냅샷 이력, 관리자 설정)
├── src/
│   ├── database.py            # SQLite 스키마 관리, 대소문자 무관 제품 동기화(sync_products_from_config), CRUD 레이어
│   ├── crawler.py             # GCP Release Notes HTML 파서, 카테고리 정규화(Change→Changed, Fix→Fixed), 증분 크롤러
│   ├── server.py              # Cloud Run HTTP 서버, 일일 자동 업데이트 스케줄러(AutoUpdateScheduler), /admin 인증 게이트
│   └── templates/
│       ├── index.html         # 일반 사용자 대시보드 (읽기 전용, 제품별/유형별 필터, 개별 항목 강조 배너, 최종 업데이트 일 표시)
│       └── admin.html         # 관리자 전용 콘솔 (/admin, 5대 핵심 관리 메뉴 및 로그아웃 지원)
└── cli.py                     # 컨테이너 기동 엔트리포인트 및 관리용 CLI 도구
```

---

## 🛡️ 추적 중인 GCP 보안 제품 (총 9개)

`config/products.json`에 정의된 9개 Google Cloud 보안 제품의 공식 Release Notes를 매일 자동 스캔합니다.
*(참고: `web-security-scanner`는 `security-command-center` URL로 리다이렉트되어 중복 데이터가 생성되므로 수집 대상에서 제거되었습니다.)*

| Slug | 제품명 | 공식 Release Notes URL |
| :--- | :--- | :--- |
| `security-command-center` | Security Command Center | `https://docs.cloud.google.com/security-command-center/docs/release-notes` |
| `Model-Armor` | Model Armor | `https://docs.cloud.google.com/model-armor/release-notes` |
| `cloud-kms` | Cloud Key Management Service | `https://docs.cloud.google.com/kms/docs/release-notes` |
| `Google-secops` | Google Security Operations (SecOps) | `https://docs.cloud.google.com/chronicle/docs/secops/secops-release-notes` |
| `secret-manager` | Secret Manager | `https://docs.cloud.google.com/secret-manager/docs/release-notes` |
| `sensitive-data-protection` | Sensitive Data Protection (Cloud DLP) | `https://docs.cloud.google.com/sensitive-data-protection/docs/release-notes` |
| `identity-aware-proxy` | Identity-Aware Proxy (IAP) | `https://docs.cloud.google.com/iap/docs/release-notes` |
| `certificate-manager` | Certificate Manager | `https://docs.cloud.google.com/certificate-manager/docs/release-notes` |
| `binary-authorization` | Binary Authorization | `https://docs.cloud.google.com/binary-authorization/docs/release-notes` |

---

## ✨ 핵심 기능 및 화면 구성

### 1. 일반 사용자 대시보드 (`/`) 및 다국어(EN / KO) 자동 지원
* **다국어(EN / KO) 지원 및 브라우저 언어 자동 인식**:
  * 기본 UI를 영문(`EN`) 기반으로 제공하며, 상단 네비게이션 바의 **`EN | KO`** 토글 버튼으로 영문/한글을 즉시 전환할 수 있습니다.
  * 최초 접속 시 브라우저 언어 설정(`navigator.language`)을 자동으로 감지하여 한국어(`ko*`) 환경에서는 `KO`, 그 외 언어 환경에서는 `EN` 화면을 자동으로 표시합니다 (`?lang=en` 또는 `?lang=ko` 파라미터 및 `localStorage` 연동).
* **읽기 전용 인터페이스**: 좌측 사이드바에는 **GCP 보안 제품 목록**만 표시되며, 관리 제어 메뉴는 노출되지 않습니다.
* **`Last Updated` (`최종 업데이트 일`) 표시**: 상단 4번째 요약 카드에 선택된 제품(또는 전체 제품)의 **마지막 스캔 날짜(`last_crawled_at`)**를 표시합니다.
* **개별 항목 헤더(`[유형 + Product_Name]`) 강조 디자인**:
  * 날짜 그룹 헤더는 중립 색상으로 유지하여 같은 날짜의 일반 항목까지 강조되는 부작용을 방지합니다.
  * **`DEPRECATED` 항목**: 아티클 상단 `[DEPRECATED + Product_Name]` 바를 **Navy(`#0b1f44`)** 배경과 Amber 경고 배지로 강조합니다.
  * **최근 1주일(`recent_highlight_days: 7`) 이내 항목**: 아티클 상단 `[FEATURE/CHANGED + Product_Name]` 바를 **Rose-Amber 그라데이션**으로 강조합니다.

### 2. 관리자 콘솔 (`/admin`)
* **관리자 기능**: 별도의 복잡한 로그인 절차 없이 관리자 콘솔(`/admin`)에 바로 접근하여 수집 대상 제품 및 스케줄러 설정을 제어할 수 있습니다.
* **5대 관리 기능**:
  1. **스케줄러 설정**: 일일 자동 업데이트 활성화, 매일 자동 실행 시각(기본 `05:00`), 최근 강조 표시 기간(기본 `7`일) 설정
  2. **제품 관리**: 신규 GCP 보안 제품 URL 등록 및 수집 활성화/비활성화 토글
  3. **스냅샷 이후 신규 스캔**: 제품별/전체 즉시 스캔 실행 및 전체 DB 초기화 후 재스캔(`POST /api/reset-and-crawl`)
  4. **스냅샷 기준일 제어**: 제품별 기준일(`YYYY-MM-DD`) 변경 및 재스캔
  5. **최근 스냅샷 실행 이력**: 크롤링 실행 로그 및 신규/갱신 건수 조회

---

## 🗄️ 데이터베이스 구조 (`data/gcp_security_releases.db`)

1. **`products` 테이블**: 추적 대상 제품 메타데이터, 스냅샷 기준일(`snapshot_date`), 마지막 스캔 시각(`last_crawled_at`)
2. **`release_notes` 테이블**: 제품별 릴리즈 날짜(`release_date`), 정규화된 카테고리(`Feature`, `Deprecated`, `Changed`, `Fixed`, `Announcement`, `Security`), 요약(`summary`), 정제된 HTML 본문, 원문 링크(`links_json`), 중복 방지 해시(`content_hash`)
3. **`crawl_snapshots` 테이블**: 스캔 실행 시점별 `baseline_date` → `new_snapshot_date` 및 수집 통계
4. **`admin_settings` 테이블**: 자동 업데이트 스케줄(`05:00`), 최근 강조 기간(`7`일), 마지막 자동 스캔 실행 이력

---

## 🚀 Cloud Run 배포 및 접속

```bash
# 1) Google Cloud Run 배포 (security-demo-319501 프로젝트)
gcloud run deploy gcp-security-release-tracker \
  --source . \
  --project security-demo-319501 \
  --region asia-northeast3 \
  --no-iap \
  --allow-unauthenticated \
  --quiet

# 2) DB 초기화 및 최신 릴리즈 수집 동기화
curl -X POST https://gcp-security-release-tracker-896350673864.asia-northeast3.run.app/api/reset-and-crawl
```

---

## 🌐 서비스 접속 및 기능 안내

* **대시보드 메인**: [https://gcp-security-release-tracker-896350673864.asia-northeast3.run.app/](https://gcp-security-release-tracker-896350673864.asia-northeast3.run.app/)
  * 별도의 로그인이나 인증 절차 없이 즉시 대시보드 열람이 가능합니다.
  * 브라우저 언어 설정에 따른 자동 언어(KO/EN) 선택 및 상단 KO/EN 토글 지원.
  * 제품군 필터, 카테고리 필터, 검색, 신규 릴리즈 하이라이트 기능 제공.
* **제품 및 스케줄러 관리 콘솔**: [https://gcp-security-release-tracker-896350673864.asia-northeast3.run.app/admin](https://gcp-security-release-tracker-896350673864.asia-northeast3.run.app/admin)
  * 별도의 인증 없이 9개 보안 제품 활성화/비활성화, 스냅샷 날짜 조정, 즉시 크롤링 및 수집 스케줄 설정을 관리할 수 있습니다.