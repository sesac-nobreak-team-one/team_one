# Shadow API 탐지 룰 생성기

`openapi.yaml`을 허용 목록으로 삼아, `app.log`의 `/api` 요청 중 **명세에 없는 메서드 + 경로**를 Wazuh 경보로 만드는 룰을 자동 생성합니다. 통합 계획서 6장의 구현입니다.

## 파일

| 파일 | 설명 |
| :--- | :--- |
| `gen_shadow_rules.py` | 생성기 (build / test / replay / logtest) |
| `shadow_api_allowlist.yaml` | 명세 밖이지만 정상인 API 예외 목록 (현재 비어 있음, 사유 필수) |
| `shadow_api_rules.xml` | **생성 결과.** Wazuh에 배포하는 룰 파일 (직접 고치지 말 것) |
| `rules_meta.json` | 생성 정보 (명세 해시, 룰 ID, 임계값). test, replay, logtest가 읽음 |
| `testcases.jsonl` | 생성된 테스트 케이스 34개 |

필요 패키지: Python 3.8 이상, PyYAML (`sudo apt install python3-yaml`)

## 룰 구조

| 룰 ID | 레벨 | 내용 |
| :--- | :---: | :--- |
| 100200 | 0 | 기반: app.log JSON 중 경로가 `/api`로 시작하는 요청 (`//api` 포함). 명세 안 요청은 여기서 끝남 |
| 100201 | 6 | 명세에 아예 없는 메서드 (PUT, HEAD, OPTIONS 등) |
| 100202~100205 | 6 | 메서드별(DELETE, GET, PATCH, POST)로 명세 경로 어디에도 맞지 않는 요청 |
| 100210 | 5 | **L1 정찰**: 명세 밖 + 404/405 |
| 100211 | 8 | **L2 발견**: 명세 밖 + 401/403 |
| 100212 | 12 | **L3 악용**: 명세 밖 + 2xx (MITRE T1190) |
| 100213 | 10 | **L3-E 서버 오류**: 명세 밖 + 5xx |
| 100220 | 10 | **F1 자동화 정찰**: 같은 `client_ip`가 30초 안에 L1 20회 (T1595.003) |
| 100221 | 14 | **F2 대량 유출**: 같은 `client_ip`가 60초 안에 L3 10회 (T1119) |

- 명세 밖 판정 룰(100201~100205)은 응답 코드가 400, 422, 3xx처럼 단계에 해당하지 않을 때만 레벨 6으로 남습니다.
- 경로 비교는 서버 라우터(`Router.php`, `Request.php`)와 같은 규칙입니다. 경로 파라미터는 `[^/?]+`, 끝 슬래시와 쿼리스트링은 무시합니다.
- 모든 경보에 `shadow_api` 그룹이 붙습니다. Grafana에서는 `rule.groups:shadow_api`로 거르면 됩니다.

## 사용법

### 1. 룰 만들기

```bash
# 파일에서 읽기 (Wazuh 서버에서는 이 방법을 씁니다)
python3 gen_shadow_rules.py build --spec openapi.yaml --base-id 100500

# 웹서버가 공개한 명세를 주소로 읽기 (웹서버에 HTTP로 접근할 수 있는 PC에서만)
python3 gen_shadow_rules.py build --spec http://192.168.80.128:8000/docs/openapi.yaml --base-id 100500
```

- Wazuh 서버(LAN)에서 웹서버(DMZ)로 가는 HTTP는 방화벽 정책에 없어서 주소로 읽으면 시간 초과가 납니다. PC에서 `scp`로 `openapi.yaml`을 옮긴 뒤 파일 경로를 주세요.
- `--base-id`: 룰 ID 시작 번호입니다. 이 Wazuh에는 다른 룰이 이미 100200~100203을 쓰고 있어서 **100500**을 씁니다. 다른 번호를 쓰려면 먼저 `sudo grep -rhoE 'id="1[0-9]{5}"' /var/ossec/etc/rules/ | sort -u`로 30칸이 비어 있는지 확인하세요.

빈도 임계값은 옵션으로 바꿉니다: `--f1-count 20 --f1-window 30 --f2-count 10 --f2-window 60 --burst-ignore 60`

`--burst-ignore`는 빈도 룰이 한 번 울린 뒤 다시 울리지 않는 시간(초)입니다. 1만 건 ID 열거 때 F2 경보가 1만 개 쌓이는 것을 막습니다. Wazuh의 `ignore`는 IP별이 아니라 룰 전체에 걸리므로, 같은 시간에 두 IP가 동시에 대량 유출을 하면 두 번째 IP의 F2는 늦게 울릴 수 있습니다. 그동안에도 L3 경보는 요청마다 계속 남습니다.

### 2. 파이썬으로 로직 검증 (Wazuh 없이)

```bash
python3 gen_shadow_rules.py test -v
```

명세 안 16개 작업, 쿼리스트링, 끝 슬래시, 없는 버전 탐색, 명세 밖 메서드, v1 토큰 없음(401), v1 IDOR 성공(200), 슬래시 겹치기 우회, 빈도 룰까지 36개 항목을 확인합니다.

### 3. 기존 로그로 미리 돌려보기

```bash
python3 gen_shadow_rules.py replay /home/ubuntu/sesac_shop_web_php/logs/app.log
python3 gen_shadow_rules.py replay /var/ossec/logs/archives/archives.json
```

단계별 경보 수와 첫 발생 시각, IP별 최고 단계, 많이 호출된 명세 밖 엔드포인트를 출력합니다. 지난 PentAGI 공격 로그나 정상 세션 로그로 오탐과 임계값을 미리 확인할 때 씁니다.

### 4. Wazuh에 배포

```bash
sudo cp shadow_api_rules.xml /var/ossec/etc/rules/shadow_api_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/shadow_api_rules.xml
sudo chmod 660 /var/ossec/etc/rules/shadow_api_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t     # 설정 문법 검사
sudo systemctl restart wazuh-manager
```

웹서버 에이전트가 `app.log`를 **JSON 형식**으로 읽고 있어야 합니다 (`agent.conf` 또는 웹서버 `ossec.conf`):

```xml
<localfile>
  <log_format>json</log_format>
  <location>/home/ubuntu/sesac_shop_web_php/logs/app.log</location>
</localfile>
```

### 5. 실제 Wazuh에서 확인 (중요)

```bash
sudo python3 gen_shadow_rules.py logtest -v
```

테스트 케이스를 `wazuh-logtest`에 넣고, 실제로 걸린 룰 ID를 기대값과 비교합니다. 원본 출력은 `logtest_output.txt`에 저장됩니다.

**이 단계를 꼭 거쳐야 하는 이유:** 룰은 Wazuh 없이 만들고 검증했습니다(XML 문법, 파이썬 재현 로직). 다음 두 가지는 실제 Wazuh에서만 확인할 수 있습니다.

1. **`status` 필드 해석:** Wazuh JSON 디코더는 `status`처럼 정적 필드와 이름이 같은 키를 정적 필드에 넣는 것으로 알고 있어 기본값을 `<status>`로 했습니다. logtest에서 L1~L3E 케이스가 전부 100201~100205에서 멈추면 반대 방식으로 다시 만드세요.
   ```bash
   python3 gen_shadow_rules.py build --spec openapi.yaml --base-id 100500 --status-option field
   ```
2. **빈도 룰 발화 시점:** Wazuh의 `frequency`가 정확히 몇 번째 요청에서 울리는지는 버전에 따라 한 건 정도 차이가 날 수 있습니다. 실제 공격 세션 후 경보 시각으로 확인합니다.

## 명세가 바뀌면

1. 웹서버의 `openapi.yaml` 수정
2. `build` 다시 실행 → `test` → Wazuh에 배포 → `logtest`

룰 파일 머리말에 명세 SHA256이 적혀 있어서, 지금 배포된 룰이 어떤 명세로 만든 것인지 확인할 수 있습니다.

## 알려진 한계

- `app.log`에 남는 요청만 봅니다. Apache의 v1 IP 제한(`V1_ALLOWED_NET`)이나 ModSecurity가 PHP 앞에서 막은 요청(403)은 `app.log`에 없으므로 이 룰로 잡히지 않습니다. 계획서 11.2의 확인 사항입니다.
- 명세에 있는 API 안의 결함(v2 자체의 BOLA 등)은 범위 밖입니다.
- 메서드는 대소문자를 구분합니다. 소문자 `get` 요청은 명세 밖 메서드로 판정됩니다.
