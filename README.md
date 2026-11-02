# 🛡️ Shadow API 및 비관리 API 공격 탐지·대응 프로젝트

본 프로젝트는 **기존 경계 방화벽(WAF/IPS)을 우회하는 Shadow API(미관리 API) 접근 및 IDOR(BOLA, 권한 우회) 공격을 API 스캐닝 기반 Wazuh 커스텀 룰로 실시간 탐지하고, SBOM 생성·Shuffle(SOAR) 자동 차단·Grafana 모니터링까지 연동하는 보안관제 시스템** 구축 프로젝트입니다.

---

## 📁 프로젝트 디렉터리 구조

GitHub 협업 및 재현성을 위해 가상머신 전체 이미지 대신 **인프라 설정 코드(IaC), 소스코드, 탐지/대응 파이프라인, 문서** 중심으로 구성되어 있습니다.

```text
.
├── 📜 README.md                                  # [루트 가이드] 프로젝트 개요, 구조 및 빠른 시작 가이드 (본 문서)
├── 📜 .gitignore                                 # VMware 가상머신, 대용량 로그 및 캐시 제외 설정
│
├── 📂 docs/                                      # [프로젝트 문서 통합 관리]
│   ├── planning/                                 # 프로젝트 계획서, 네트워크 아키텍처, 로그 수집 명세서
│   │   ├── 계획서.md
│   │   ├── 인프라_구축_실행가이드_및_작업로그.md
│   │   └── Wazuh_통합_수집대상_로그명세서.md
│   └── troubleshooting/                          # 단계별 장애 분석 및 트러블슈팅 리포트
│       ├── 01_웹서버_Wazuh_로그연동_및_권한_장애해결.md
│       ├── 02_폐쇄망_DMZ웹서버_Docker빌드_외부통신제한_해결.md
│       └── 03_웹서버_Apache_로그포맷_밀리초_변경.md
│
├── 📂 infra/                                     # [인프라 설정 및 배포 스크립트] (VMware 환경 재현용)
│   ├── fortigate/                                # 방화벽 설정 백업 및 라우팅/VIP 명세
│   ├── web_dmz/                                  # DMZ 웹서버 docker-compose.yml, Dockerfile, 웹서버 설정
│   └── wazuh/                                    # Wazuh 매니저/에이전트 수집 설정(ossec.conf), 구축 리포트
│
├── 📂 web/                                       # [취약한 웹 애플리케이션 소스코드]
│   └── src/                                      # Apache + PHP + MySQL 쇼핑몰 소스코드
│
└── 📂 detection/                                 # [Shadow API 탐지 룰 · SBOM · 대시보드 · SOAR 연동]
    └── shadow_api/
        ├── gen_shadow_rules.py                   # 알려진 API 목록 기반 Wazuh 탐지 룰 생성기
        ├── shadow_api_allowlist.yaml             # 정상 예외 API 목록
        ├── shadow_api_rules.xml                  # Wazuh 배포용 커스텀 탐지 룰
        └── grafana/                              # Grafana 대시보드 생성기 및 JSON
```

---

## 🌐 인프라 및 네트워크 아키텍처

```text
[공격자: PentAGI / ARTEX] 192.168.80.135
       │
       ▼ (외부 인입 트래픽)
┌─────────────────────────────────────────────────────────────┐
│ 1. 경계 방화벽: pfSense CE (+Suricata) / FortiGate-VM        │
│   • WAN (외부 접근): 192.168.0.141 / 192.168.80.x           │
│   • 포트포워딩(VIP):                                          │
│       - 2222 ➔ DMZ 웹서버 SSH (22)                           │
│       - 8822 ➔ Wazuh 관제서버 SSH (22)                       │
│       - 8000 ➔ DMZ 웹서버 HTTP (80)                          │
└──────────────┬──────────────────────────────┬───────────────┘
               │ (DMZ 망: 192.168.20.0/24)    │ (LAN 망: 192.168.10.0/24)
               ▼                              ▼
┌──────────────────────────────┐ ┌──────────────────────────────┐
│ 2. DMZ 웹서버                │ │ 3. Wazuh 관제 서버 (+Grafana)│
│   • IP: 192.168.20.10        │ │   • IP: 192.168.10.30        │
│   • 컨테이너: shop-web-web-1 │ │   • 프로토콜: 1514 (Agent)   │
│   • SSH: ubuntu / ****       │ │   • SSH: dongyoung / ****    │
│   • Wazuh Agent ID: 004      │ │   • Web UI: admin/********** │
└──────────────────────────────┘ └──────────────────────────────┘
```

---

## 📋 핵심 문서 및 모듈 가이드

| 분류 | 문서 / 모듈 경로 | 주요 내용 및 역할 |
| :--- | :--- | :--- |
| **기획 & 설계** | [docs/planning/계획서.md](file:///d:/Project/team_one/docs/planning/계획서.md) | 연구 배경, Shadow API 탐지 필요성, 탐지 룰 및 대시보드 설계 전반 |
| **인프라 명세** | [docs/planning/인프라_구축_실행가이드_및_작업로그.md](file:///d:/Project/team_one/docs/planning/인프라_구축_실행가이드_및_작업로그.md) | 방화벽 인터페이스 IP, VIP 매핑, 라우팅 테이블, 서버 설치 명령어 히스토리 |
| **로그 수집** | [docs/planning/Wazuh_통합_수집대상_로그명세서.md](file:///d:/Project/team_one/docs/planning/Wazuh_통합_수집대상_로그명세서.md) | 웹서버 로그, DB 로그 수집 경로, 포맷 및 잡음 차단 정책 |
| **트러블슈팅** | [docs/troubleshooting/01_웹서버_Wazuh_로그연동_및_권한_장애해결.md](file:///d:/Project/team_one/docs/troubleshooting/01_웹서버_Wazuh_로그연동_및_권한_장애해결.md) | Docker 볼륨 권한 거부 해결, Apache 호스트 실측 경로 매핑, 잡음 제거 |
| **트러블슈팅** | [docs/troubleshooting/02_폐쇄망_DMZ웹서버_Docker빌드_외부통신제한_해결.md](file:///d:/Project/team_one/docs/troubleshooting/02_폐쇄망_DMZ웹서버_Docker빌드_외부통신제한_해결.md) | 방화벽 Outbound 차단 환경에서 Docker 오프라인 빌드/마운트 우회 해결 |
| **탐지 & 대시보드** | [detection/shadow_api/README.md](file:///d:/Project/team_one/detection/shadow_api/README.md) | 알려진 API 기반 Wazuh 커스텀 룰 생성 및 Grafana 대시보드 구성 |

---

## 🤝 팀 협업 및 작업 수칙

1. **대용량 파일 커밋 금지:**
   - VMware 디스크(`.vmdk`, `.vmx`), 100MB 이상의 원천 로그 데이터, 가상머신 스냅샷은 Git에 업로드하지 않습니다. (`.gitignore` 확인)
2. **로그 수집 무결성 유지:**
   - 웹서버는 Docker Compose 환경이므로 Apache 로그는 호스트의 `/home/ubuntu/sesac_shop_web_php/logs/apache/` 경로를 준수합니다.
   - 불필요한 시스템 잡음 로그(`journald`, `df -P`, `dpkg.log` 등)는 비활성화 상태를 유지합니다.
3. **새로운 장애/설정 변경 시:**
   - 신규 이슈나 트러블슈팅 발생 시 `docs/troubleshooting/` 폴더에 일련번호(`03_...`, `04_...`) 형태로 문서를 추가하고 본 README의 테이블을 최신화합니다.
