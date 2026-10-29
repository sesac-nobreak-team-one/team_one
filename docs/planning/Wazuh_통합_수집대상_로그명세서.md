# 📊 Wazuh 통합 수집 대상 로그 명세서 (WAF · WEB · DB 수집 및 머신러닝 연계)

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
│   • 🚫 Wazuh Syslog 수집 제외: L4 정보의 머신러닝 무용성 및 │
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
│   • 대시보드 인덱스: wazuh-archives-*                        │
│   • 🚫 자체 잡음 차단: journald, df -P, last, SCA 점검 배제 │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. 머신러닝 (Random Forest) 탐지 모델                       │
│   • 30초 시간 창(Window) 단위 9대 행동 특징값(Feature) 학습   │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. 인프라 계층별 세부 수집 로그 명세표

### ① [DMZ] 웹방화벽(WAF) 및 웹서버(WEB) 로그 (Machine Learning 핵심 학습 소스 ⭐⭐⭐)
> **Wazuh 서버 배포 위치:** `/var/ossec/etc/shared/default/agent.conf` 및 웹서버 `/var/ossec/etc/ossec.conf`  
> **수집 주체:** 웹서버에 설치된 Wazuh Agent (`web-server`)  
> **컨테이너 볼륨 연동:** Docker Compose에서 호스트 `./logs` 디렉터리가 컨테이너 내부(`/var/log/apache2`, `/var/www/html/logs`)로 마운트되어 실시간 동기화 수집됨

| 로그 종류 | 호스트 실 수집 경로 | 포맷 | 수집 목적 및 머신러닝(ML) 피처 연계 |
| :--- | :--- | :---: | :--- |
| **WAF 감사/차단 로그** | `/var/log/apache2/modsec_audit.log` (또는 WAF 로그 경로) | Audit / JSON | **시그니처 공격 차단 및 로직 공격 우회 입증:**<br>• SQLi, XSS 등 고전적 공격 차단(403) 확인<br>• 구버전 Shadow API(`GET /api/v1/users/{id}`) 공격이 WAF를 정상 통과함을 입증. |
| **쇼핑몰 비즈니스 로그** | `/home/ubuntu/sesac_shop_web_php/logs/app.log` | JSON | **Shadow API 및 IDOR/BOLA 권한 우회 탐지:**<br>• 요청 시각(`timestamp`), 클라이언트 IP, HTTP 메서드, API 경로(`/api/v1/users/{id}`, `/api/v2/*`), 응답상태, 처리시간(`duration_ms`), 응답 바이트(`response_bytes`), User-Agent<br>• 타인 계정 ID 순차 탐색 및 개인정보(PII) 무단 조회 행위 정밀 추적. |
| **웹 표준 접근 로그** | `/home/ubuntu/sesac_shop_web_php/logs/apache/shop_access.log` | Apache (Combined) | **기계적 탐색 리듬 통계 (9대 피처 추출):**<br>• 요청 시각(`timestamp`), 클라이언트 IP, HTTP 메서드, 응답 상태코드, User-Agent, 전송 바이트<br>• 요청 수(`req_count`), 간격 평균/표준편차(`interval_mean`, `interval_std`), 에러율(`error_404_ratio`, `error_abnormal_ratio`), 고유 URL/UA 수(`unique_url_count`, `unique_ua_count`), POST 비율(`ratio_post`), 평균 응답 크기(`bytes_mean`) 산출. |
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

### ③ [경계] 경계 방화벽 로그 — 【수집 제외 확정 및 기술적 의사결정 사유 🚫】
> **결정 상태:** **수집 대상에서 영구 제외 (Excluded from SIEM / ML Pipeline)**  
> **검토 결론:** 머신러닝 학습 모델에 기여도가 0%이며, SIEM 저장 공간 및 전처리 파이프라인에 대규모 노이즈(Noise)만 유발하므로 관제 수집 대상에서 완전히 배제하고 **WEB · WAF · DB 로그만 수집**함.

| 핵심 검토 항목 | 세부 기술적 제외 사유 |
| :--- | :--- |
| **1. L7 애플리케이션 피처 부재<br>(머신러닝 기여도 0% ⭐⭐⭐)** | • 방화벽 트래픽 로그(L3/L4)는 출발지/도착지 IP, 포트, TCP 세션 정보, 전송 바이트 수만 기록함.<br>• 모델의 9대 행동 특징값 산출에 필요한 **세부 URL 경로(`path`), HTTP 상태코드(200, 404), User-Agent 변조 횟수, POST 메서드 비율** 정보가 일체 존재하지 않음.<br>• 즉, AI 모델의 공격 패턴 학습에 활용할 수 있는 피처가 전무함. |
| **2. 데이터셋 오염(Noise) 방지** | • 방화벽 Syslog를 활성화할 경우 단순 TCP 핸드셰이크(SYN/ACK), 킵얼라이브(Keep-Alive) 등의 방대한 세션 로그가 초당 수십~수백 건씩 쏟아짐.<br>• 이는 30초 슬라이딩 윈도우 집계 시 데이터 편향(Skew)을 일으키고, 실제 웹/API 공격 원천 로그를 밀어내는 심각한 데이터 오염을 유발함. |
| **3. Wazuh SIEM 리소스 최적화** | • 무의미한 L4 네트워크 연결/종료 로그의 인덱싱 부하를 원천 차단하여, 실제 핵심 분석 대상인 **WAF, 웹서버(`shop_access.log`, `app.log`) 및 DB 쿼리 로그의 실시간 색인/검색 지연 시간을 0초대로 유지**함. |

---

### ④ [관제] Wazuh 서버 자체 잡음 로그 (100% 수집 제외 / 차단 완료 🚫)
> **조치 현황:** `ossec.conf` 내 로컬 수집 블록 영구 삭제 완료

| 제외 대상 항목 | 차단 이유 |
| :--- | :--- |
| **`df -P`, `last -n 20`, `netstat`** | 6분마다 서버 디스크 용량, 로그인 목록, 포트를 점검하는 명령어로 머신러닝 학습 데이터를 심각하게 오염시킴 (제외 완료) |
| **`journald`, `syslog`, `dpkg.log`** | DNS 쿼리, systemd 데몬 동작, 패키지 설치 등 웹 공격과 무관한 리눅스 OS 잡음 (제외 완료) |
| **CIS 벤치마크 점검 (`<sca>`)** | 수천 건씩 쌓이는 리눅스 취약점 진단 로그로 실제 공격 트래픽을 밀어내는 현상 원천 차단 (비활성화 완료) |
| *(남겨둔 로그)* | `/var/ossec/logs/active-responses.log` (공격자 IP 자동 차단 기록용으로만 유일하게 보존) |

---

## 3. 머신러닝 학습 피처(Feature)와의 매핑 관계도 (`01_preprocess.py` 9종 기준)

수집된 원천 로그는 **IP별 30초 시간 창(Window)**으로 묶여 아래 9대 핵심 피처로 변환됩니다:

```text
[원천 로그 수집 (WEB / app.log)]          [30초 창 통계 피처 변환 (9종)]
• 요청 타임스탬프 건수                ➔  1. req_count (30초 창 내 요청 빈도)
• 연속 요청 간 시간 차이 평균         ➔  2. interval_mean (요청 간격 평균)
• 연속 요청 간 시간 차이 표준편차     ➔  3. interval_std (요청 간격 표준편차 - 기계적 규칙성)
• HTTP Status == 404 비율             ➔  4. error_404_ratio (숨은 API 탐색 404 에러율)
• HTTP Status >= 400 비율             ➔  5. error_abnormal_ratio (4xx/5xx 비정상 응답률)
• 요청 URI(path) 고유값 수            ➔  6. unique_url_count (30초간 찌른 고유 경로 수)
• User-Agent 고유값 수                ➔  7. unique_ua_count (도구 체이닝 및 User-Agent 전환 수)
• HTTP Method == POST 비율            ➔  8. ratio_post (데이터 변조/주입 POST 요청 비율)
• 응답 크기(response_bytes) 평균      ➔  9. bytes_mean (응답 페이로드 크기 평균)
```

---

## 4. Wazuh 대시보드(Discover) 클린 CSV 추출 공식 쿼리

Wazuh 서버 자체 잡음 및 방화벽 로그가 배제되었으므로, 머신러닝 학습용 데이터를 뽑으실 때는 대시보드 검색창에 아래 쿼리만 넣으시면 순수한 학습용 데이터만 추출됩니다:

```text
agent.name: "web-server" and (location: "*access.log*" or location: "*app.log*")
```
