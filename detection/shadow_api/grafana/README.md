# Shadow API 탐지 Grafana 대시보드

통합 계획서 7장 구현입니다. `shadow_api_dashboard.json`을 Grafana에 Import하면 패널 6개가 한 번에 만들어집니다.

## 준비: 경보용 데이터 소스

Connections → Data sources → Add new data source → OpenSearch

| 항목 | 값 |
| :--- | :--- |
| Name | `Wazuh-Alerts` |
| URL, Auth, Skip TLS Verify | 기존 `wazuh-archives-*` 데이터 소스와 같게 |
| Index name | `wazuh-alerts-*` |
| Time field name | `timestamp` |

Save & test가 초록색이면 됩니다. 버전 칸이 있으면 **Get Version and Save**를 먼저 누릅니다.

## 대시보드 넣기

1. Dashboards → New → **Import**
2. `shadow_api_dashboard.json` 파일을 올리거나 내용을 붙여넣고 **Load**
3. "Wazuh 경보 (wazuh-alerts-*)" 칸에서 `Wazuh-Alerts` 선택 → **Import**

같은 대시보드가 이미 있으면 덮어쓸지 묻습니다 (uid `shadow-api-detect`).

## 패널 구성

| 패널 | 내용 |
| :--- | :--- |
| 기간 내 단계별 경보 수 | L1, L2, L3, L3-E, F1, F2 건수 타일 |
| 단계별 경보 추이 | 단계별 색으로 쌓은 막대 그래프 |
| 위험 IP 순위 | IP별 경보 수, 최고 도달 단계 (레벨 순 정렬) |
| 명세 밖 엔드포인트 순위 | 많이 호출된 명세 밖 메서드 + 경로 (Shadow API 후보) |
| 기존 보안 장비와 비교 | 같은 시간대 Suricata, ModSecurity, Wazuh 기본 웹 룰 경보 수 vs 명세 대조 룰 |
| 최근 경보 | 원본 경보 표 (시각, 레벨, IP, 메서드, 경로, 상태, user_id 등) |

- 위쪽 **IP 필터** 칸에 IP를 넣으면 비교 패널을 뺀 모든 패널이 그 IP만 보여줍니다. `*`는 전체입니다.
- 10초마다 새로고침되고, 기본 시간 범위는 최근 1시간입니다.
- 단계는 룰 ID가 아니라 그룹 이름(`shadow_api_recon` 등)으로 거릅니다. 룰 ID 시작 번호를 바꿔도 대시보드는 그대로 씁니다.

## Import 후 확인할 것

이 JSON은 Grafana에 직접 올려보지 않고 만들었습니다. 다음은 화면에서 확인하고, 다르면 패널 편집에서 고쳐 주세요.

- **기존 장비 비교 패널의 그룹 이름:** `suricata`, `modsecurity`, `web`은 짐작한 값입니다. Wazuh 대시보드에서 실제 Suricata/WAF 경보를 하나 열어 `rule.groups` 값을 보고 쿼리를 맞추세요.
- **표의 열 이름:** 위험 IP 순위의 "최고 단계" 열이 `Max rule.level` 그대로 보이면, 패널 편집 → Transformations → Organize fields에서 이름을 바꾸면 됩니다.
- **패널이 비어 있을 때:** 패널 편집에서 Lucene query를 `*`로 바꿔 데이터가 나오면 데이터 소스는 정상이고, 해당 시간대에 경보가 없는 것입니다.

## 알림 규칙 (계획서 7.3)

알림은 웹 화면에서 만듭니다.

### 1. 알림 채널 (Contact point)

Alerting → Contact points → **Add contact point**

- Discord: 채널 설정 → 연동 → 웹후크 만들기 → URL 복사 → Integration `Discord`에 붙여넣기
- 저장 전 **Test**를 눌러 메시지가 오는지 확인

### 2. 알림 규칙

Alerting → Alert rules → **New alert rule**

| 항목 | Shadow API 악용 | 대량 유출 | 자동화 정찰 |
| :--- | :--- | :--- | :--- |
| 데이터 소스 | `Wazuh-Alerts` | 같음 | 같음 |
| Lucene query | `rule.groups:shadow_api_exploit OR rule.groups:shadow_api_error` | `rule.groups:shadow_api_mass_exfil` | `rule.groups:shadow_api_recon_burst` |
| Metric / Group by | Count / Date Histogram `timestamp` | 같음 | 같음 |
| 조회 범위 | 최근 2분 (`now-2m` ~ `now`) | 같음 | 최근 5분 |
| 조건 | Reduce: **Sum** → Threshold: **IS ABOVE 0** | 같음 | 같음 |
| 평가 주기 | 10초 | 10초 | 1분 |
| Pending period | 0s (바로 알림) | 0s | 0s |
| Contact point | 위에서 만든 채널 | 같음 | 같음 |

- 조회 범위를 평가 주기보다 넉넉하게(2분) 잡는 이유: Wazuh가 경보를 Indexer에 넣기까지 몇 초 걸려서, 1분으로 잡으면 경계에 걸린 경보를 놓칠 수 있습니다.
- 알림 메시지에 IP를 넣으려면 Group by에 `Terms: data.client_ip`를 먼저 넣고 그다음 Date Histogram을 넣습니다. 그러면 IP마다 알림이 따로 갑니다.
- 공격이 끝나고 2분 동안 경보가 없으면 "해결됨(Resolved)" 알림이 한 번 더 옵니다.

## 대시보드를 고쳤을 때

화면에서 고친 내용은 대시보드 설정 → JSON Model 또는 Export → **Export for sharing externally**로 내보내 이 폴더의 `shadow_api_dashboard.json`을 바꿔 두세요. 저장소에 남아 있어야 Grafana를 다시 설치해도 그대로 복원됩니다. `build_dashboard.py`로 처음부터 다시 만들 수도 있습니다.
