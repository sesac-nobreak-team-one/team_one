# Shadow API 모니터링 — 비(非)컨테이너 환경

> **목표**: 도커·쿠버네티스 없이 일반 서버 환경에서 ① Shadow/Zombie API 탐지 ② 새 모니터링 대시보드 구축

**작성일**: 2026-10-29 · **기준 토폴로지**: 조원6 토폴로지 — [topology/wazuh_network_diagram.drawio](topology/wazuh_network_diagram.drawio) (draw.io로 열기, 계정 정보 제외)

## 결론 요약

- **Prometheus가 아니라 로그 기반(ELK: Filebeat → Elasticsearch → Kibana)으로 간다.**
  - Prometheus는 *등록된 대상*의 숫자만 본다 → "모르는 API"를 구조적으로 못 본다.
  - 액세스 로그는 *길목을 지나간 모든 요청*을 남긴다 → 명세와 대조하면 Shadow API가 나온다.
- 우리 토폴로지에서 외부 트래픽의 길목은 **DMZ의 WEB 서버(192.168.20.10)** → 여기 액세스 로그를 수집한다.
- 탐지 원리: `관측된 엔드포인트 − 명세(OpenAPI) 엔드포인트 = Shadow`, `명세상 deprecated ∩ 관측 = Zombie`

## 문서

| 문서 | 내용 |
|---|---|
| [docs/01_Prometheus_vs_Kibana_비교.md](docs/01_Prometheus_vs_Kibana_비교.md) | 두 도구의 수집 위치·방식 차이, Shadow API 탐지 적합성, 선택 근거 |
| [docs/02_ELK_구축_가이드라인.md](docs/02_ELK_구축_가이드라인.md) | 우리 토폴로지 기준 단계별 구축 절차 (설치 → 수집 → 정규화 → 명세 대조 → 대시보드) |
| [tools/openapi_to_inventory.py](tools/openapi_to_inventory.py) | OpenAPI 명세 → Elasticsearch `api-inventory` 적재용 NDJSON 변환 |

## 확인 필요 (구축 전에 채울 것)

- [ ] WEB 서버 OS 및 웹서버 종류 (Nginx / Apache / Tomcat / IIS) → 로그 경로·포맷이 달라짐
- [ ] 외부 접속 `192.168.0.41:8080` → WEB 서버 내부 포트 매핑
- [ ] Wazuh 접속 포트 `192.168.0.41:8082` (화이트보드 판독 추정값)
- [ ] ELK 서버로 쓸 VM과 IP (가이드에서는 **예시로 `192.168.10.40`** 사용)
- [ ] WEB 서버에서 운영 중인 API의 OpenAPI(Swagger) 명세 보유 여부
