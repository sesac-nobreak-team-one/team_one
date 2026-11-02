# 📊 Wazuh 통합 수집 대상 로그 명세서 (WAF · WEB · DB 수집 및 탐지·관제 연계)

본 문서는 프로젝트 인프라(경계 방화벽, DMZ 웹방화벽·웹서버, LAN 데이터베이스, 관제 서버) 전반에서 **어떤 로그를, 왜, 어떤 방식으로 수집하는지**를 체계적으로 정리한 공식 기술 명세서입니다. 추후 최종 보고서 작성 및 발표 시 그대로 인용할 수 있도록 작성되었습니다.

---

## 1. 전체 로그 수집 아키텍처 흐름도

```text
[외부 트래픽 (정상 사용자 / ARTEX 공격)]
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. 경계 방화벽                                              │
│   • 역할: L3/L4 네트워크 경계 방어선 (포트포워딩 및 망분리) │
│   • 🚫 Wazuh L4 트래픽 로그 수집 제외: URL/응답코드 부재 및 │
│     불필요한 세션 노이즈 방지를 위해 관제 수집 대상에서 배제│
└──────────────────────────────┬──────────────────────────────┘
                               │ (정상 패킷으로 위장된 로직 공격 트래픽 100% 통과)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. DMZ 웹방화벽(WAF) 및 웹서버(WEB) [★ 핵심 수집처]         │
│   • 수집 방식: Wazuh Agent (중앙 배포: agent.conf)          │
│   • 수집 로그:                                              │
│     ① WAF 감사/차단 로그 (modsec_audit.log 등)              │
│     ② 쇼핑몰 비즈니스 로직 로그 (app.log)                   │
│     ③ 웹 접근 및 에러 로그 (access.log, error.log)          │
│     ④ 도커 내부 PHP 런타임 예외 (*-json.log)                │
│     ⑤ 시스템 인증 및 쉘 감사 (auth.log, audit.log)          │
└──────────────────────────────┬──────────────────────────────┘
                               │ (DB 쿼리 요청: 3306)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. LAN 데이터베이스 (MariaDB / MySQL)                        │
│   • 수집 방식: Wazuh Agent (로컬 ossec.conf)                 │
│   • 수집 로그: General Query Log, Slow Log, Error Log       │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Wazuh 중앙 보안관제 서버 (LAN)                           │
│   • 저장 위치: /var/ossec/logs/archives/archives.json       │
│   • 대시보드 인덱스: wazuh-alerts-*, wazuh-archives-*       │
│   • 🚫 자체 잡음 차단: journald, df -P, last, SCA 점검 배제 │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Shadow API 커스텀 탐지 룰 · Shuffle(SOAR) · Grafana      │
│   • 스캔된 API 목록 기반 비관리(Shadow) API 실시간 탐지     │
│   • 반복 접근 시 Shuffle 연동 자동 차단 & Grafana 감시      │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. 인프라 계층별 세부 수집 로그 명세표

### ① [DMZ] 웹방화벽(WAF) 및 웹서버(WEB) 로그 (핵심 탐지 소스 ⭐⭐⭐)
> **Wazuh 서버 배포 위치:** `/var/ossec/etc/shared/default/agent.conf` 및 웹서버 `/var/ossec/etc/ossec.conf`  
> **수집 주체:** 웹서버에 설치된 Wazuh Agent (`web-server`)  
> **컨테이너 볼륨 연동:** Docker Compose에서 호스트 `./logs` 디렉터리가 컨테이너 내부(`/var/log/apache2`, `/var/www/html/logs`)로 마운트되어 실시간 동기화 수집됨

| 로그 종류 | 호스트 실 수집 경로 | 포맷 | 수집 목적 및 탐지·관제 연계 |
| :--- | :--- | :---: | :--- |
| **WAF 감사/차단 로그** | `/var/log/apache2/modsec_audit.log` (또는 WAF 로그 경로) | Audit / JSON | **시그니처 공격 차단 및 로직 공격 우회 입증:**<br>• SQLi, XSS 등 고전적 공격 차단(403) 확인<br>• 구버전 Shadow API(`GET /api/v1/users/{id}`) 공격이 WAF를 정상 통과함을 입증. |
| **쇼핑몰 비즈니스 로그** | `/home/ubuntu/sesac_shop_web_php/logs/app.log` | JSON | **Shadow API 탐지 및 API 호출 감시 (1차 소스):**<br>• 요청 시각(`timestamp`), 클라이언트 IP(`client_ip`), HTTP 메서드(`method`), API 경로(`path`), 응답상태(`status`), 사용자 ID(`user_id`), 처리시간(`duration_ms`), 응답 바이트(`response_bytes`), User-Agent<br>• 스캔된 알려진 API 목록과 대조하여 미관리 API 접근(L1/L2/L3/F1/F2) 판정 및 Grafana API 호출 통계 집계. |
| **웹 표준 접근 로그** | `/home/ubuntu/sesac_shop_web_php/logs/apache/shop_access.log` | Apache (Combined) | **보조 탐지 소스:**<br>• Apache 접근 제한이나 WAF 단계에서 차단되어 PHP(`app.log`)까지 도달하지 못한 요청을 교차 확인. |
| **웹 서버 에러 로그** | `/home/ubuntu/sesac_shop_web_php/logs/apache/shop_error.log` | Apache Error | **웹서버 내부 비정상 에러 감시:**<br>• 잘못된 HTTP 요청 헤더, 존재하지 않는 모듈/스크립트 호출 에러 포착. |
| **도커/PHP 런타임 로그** | `/var/lib/docker/containers/*/*-json.log` | Docker JSON | **취약점 유발 파라미터 주입 감시:**<br>• 컨테이너 stdout/stderr 표준 출력 로그 실시간 수집. |
| **호스트 시스템 인증** | `/var/log/auth.log` | Syslog | **권한 상승 및 SSH 침투 감시:**<br>• sudo 명령어 실행, SSH brute-force 시도 이력 감시. |

---

### ② [LAN] 데이터베이스(DB) 로그 (침해 결과 팩트 검증용)
> **설정 위치:** DB 서버 MariaDB/MySQL 설정 및 로컬 Agent  
> **수집 주체:** DB 서버에 설치된 Wazuh Agent

| 로그 종류 | 상세 경로 (DB VM 내부) | 포맷 | 수집 목적 및 보안 분석 역할 |
| :--- | :--- | :---: | :--- |
| **일반 쿼리 로그 (General Log)** | `/var/log/mysql/general.log` | Syslog / Text | **비정상 데이터 유출 최종 팩트 검증:**<br>• Shadow API(`GET /api/v1/users/{id}`) IDOR 공격 성공 시 단시간 내에 서로 다른 회원의 개인정보가 수십~수만 건씩 `SELECT`되는 쿼리 내역 추적<br>• "웹서버가 뚫려 실제 DB 조회가 발생했음"을 입증하는 결정적 증거. |
| **DB 에러 로그** | `/var/log/mysql/error.log` | Text | **비정상 SQL 구문 유발 확인:**<br>• SQL 인젝션 공격 시도 시 발생하는 DB 구문 오류(Syntax Error) 집계. |

---

### ③ [경계] 경계 방화벽 L4 트래픽 로그 — 【수집 제외 확정 및 기술적 의사결정 사유 🚫】
> **결정 상태:** **L4 트래픽 로그는 수집 대상에서 영구 제외 (IDS/IPS 경보만 비교용 확인)**  
> **검토 결론:** L4 세션 로그는 API 경로 및 상태 코드가 없어 Shadow API 탐지에 사용할 수 없으며, SIEM 저장 공간에 대규모 노이즈(Noise)만 유발하므로 배제하고 **WEB · WAF · DB 로그만 수집**함.

| 핵심 검토 항목 | 세부 기술적 제외 사유 |
| :--- | :--- |
| **1. L7 애플리케이션 필드 부재** | • 방화벽 트래픽 로그(L3/L4)는 출발지/도착지 IP, 포트, TCP 세션 정보, 전송 바이트 수만 기록함.<br>• API 명세 대조 및 모니터링에 필수적인 **HTTP 메서드(`method`), 세부 URL 경로(`path`), HTTP 상태코드(`status`)** 정보가 존재하지 않음. |
| **2. 인덱스 노이즈 방지** | • 방화벽 트래픽 Syslog를 활성화할 경우 단순 TCP 핸드셰이크(SYN/ACK), 킵얼라이브(Keep-Alive) 등의 방대한 세션 로그가 초당 수십~수백 건씩 쏟아짐. |
| **3. Wazuh SIEM 리소스 최적화** | • 무의미한 L4 네트워크 연결/종료 로그의 인덱싱 부하를 원천 차단하여, 실제 핵심 분석 대상인 **WAF, 웹서버(`shop_access.log`, `app.log`) 및 DB 쿼리 로그의 실시간 탐지·검색 지연 시간을 최소화**함. |

---

### ④ [관제] Wazuh 서버 자체 잡음 로그 (100% 수집 제외 / 차단 완료 🚫)
> **조치 현황:** `ossec.conf` 내 로컬 수집 블록 영구 삭제 완료

| 제외 대상 항목 | 차단 이유 |
| :--- | :--- |
| **`df -P`, `last -n 20`, `netstat`** | 6분마다 서버 디스크 용량, 로그인 목록, 포트를 점검하는 명령어로 불필요한 이벤트 노이즈를 유발함 (제외 완료) |
| **`journald`, `syslog`, `dpkg.log`** | DNS 쿼리, systemd 데몬 동작, 패키지 설치 등 웹 공격과 무관한 리눅스 OS 잡음 (제외 완료) |
| **CIS 벤치마크 점검 (`<sca>`)** | 수천 건씩 쌓이는 리눅스 취약점 진단 로그로 실제 공격 트래픽을 밀어내는 현상 원천 차단 (비활성화 완료) |
| *(남겨둔 로그)* | `/var/ossec/logs/active-responses.log` (Shuffle 및 Active Response를 통한 공격자 IP 자동 차단 기록용으로 보존) |

---

## 3. Wazuh 대시보드 / Grafana 조회 필터 예시

Wazuh 서버 자체 잡음 및 방화벽 L4 로그가 배제되었으므로, 웹/API 로그 및 Shadow API 경보를 조회할 때는 아래 쿼리를 사용합니다:

```text
# 1. 웹서버 원천 API/접근 로그 조회 (wazuh-archives-*)
agent.name: "web-server" and (location: "*access.log*" or location: "*app.log*")

# 2. Shadow API 탐지 경보 조회 (wazuh-alerts-*)
rule.groups: "shadow_api"
```
