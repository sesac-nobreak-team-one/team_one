# Shadow API 모니터링 — ELK 도입

> **목표**: 쿠버네티스 없는 VM 환경(웹은 Docker Apache)에서 ① Shadow/Zombie API 탐지 ② 새 모니터링 대시보드 구축

**작성일**: 2026-10-29 · **기준 토폴로지**: 조원6 토폴로지 — [topology/wazuh_network_diagram.drawio](topology/wazuh_network_diagram.drawio) (draw.io로 열기, 계정 정보 제외)

## 결론 요약

- **Prometheus가 아니라 로그 기반(ELK: Filebeat → Elasticsearch → Kibana)으로 간다.**
  - Prometheus는 *등록된 대상*의 숫자만 본다 → "모르는 API"를 구조적으로 못 본다.
  - 액세스 로그는 *길목을 지나간 모든 요청*을 남긴다 → 명세와 대조하면 Shadow API가 나온다.
- 외부 트래픽의 길목은 **DMZ WEB(192.168.20.10)의 Docker Apache** → 호스트 마운트 로그 `/home/ubuntu/sesac_shop_web_php/logs/apache/shop_access.log`를 수집한다.
- 탐지 원리: `관측된 엔드포인트 − 명세(OpenAPI) 엔드포인트 = Shadow`, `명세상 deprecated ∩ 관측 = Zombie`

## 수집 경로 3가지 버전

| 버전 | 수집 경로 | 방화벽 작업 | 상태 |
|---|---|---|---|
| **A. 현버전 (FortiGate)** | WEB Filebeat → ELK | DMZ→LAN 9200 정책 + Kibana VIP | 정책 수 한도로 현재 불가 |
| **B. pfSense** | WEB Filebeat → ELK | DMZ 규칙 + 포트포워딩 | pfSense 전환 후 (최종 목표) |
| **C. 현버전 우회** | WEB → (기존 Wazuh Agent) → Wazuh `archives.json` → Filebeat → ELK | **없음** | **지금 바로 가능** |

권장: **C로 시작 → pfSense 전환 후 B로 이전.** ELK 설치·명세 대조·대시보드는 세 버전 공통이라 그대로 재사용한다.

## 문서

| 문서 | 내용 |
|---|---|
| [docs/01_Prometheus_vs_Kibana_비교.md](docs/01_Prometheus_vs_Kibana_비교.md) | 두 도구의 수집 위치·방식 차이, Shadow API 탐지 적합성, 선택 근거 |
| [docs/02_ELK_구축_가이드라인.md](docs/02_ELK_구축_가이드라인.md) | 공통 구축 절차 + 버전별(A/B/C) 수집 설정 |
| [tools/openapi_to_inventory.py](tools/openapi_to_inventory.py) | OpenAPI 명세 → Elasticsearch `api-inventory` 적재용 NDJSON 변환 |

## 확인 필요 (구축 전에 채울 것)

- [x] WEB 웹서버 종류 → Docker 컨테이너 Apache(php:7.4-apache), combined 포맷 (팀 문서 troubleshooting/01·02)
- [x] FortiGate WAN 주소 → `192.168.0.141` (화이트보드의 `.41`은 판독 오류)
- [ ] 외부 포트포워딩 `:8080`(WEB), `:8082`(Wazuh 대시보드, 판독 추정) 실제 값
- [ ] ELK 서버로 쓸 VM과 IP (가이드에서는 **예시로 `192.168.10.40`** 사용), 호스트 PC 메모리 여유
- [ ] Apache 로그의 클라이언트 IP가 실제 IP인지 Docker 브리지 IP인지
- [ ] 쇼핑몰 API(`/api/v1/...`)의 OpenAPI(Swagger) 명세 보유 여부
- [ ] pfSense 전환 일정 및 인터페이스 주소 (B 버전)
