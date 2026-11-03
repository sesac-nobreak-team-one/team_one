# 패킷 캡처(`flows`)부터 `openapi.yaml` 및 Wazuh Shadow API 탐지 룰 생성 통합 가이드

이 문서는 운영 중인 웹서버의 정상 API 트래픽을 캡처하여 **OpenAPI 3.0 명세서(`openapi.yaml`)**를 자동으로 추출하고, 이를 화이트리스트(Allowlist)로 삼아 **명세에 정의되지 않은 비정상/문서화되지 않은 API(Shadow API) 호출을 탐지하는 Wazuh 커스텀 룰(`shadow_api_rules.xml`)**을 생성·검증·배포하는 전 과정을 정리한 통합 가이드입니다.

---

## 전체 파이프라인 개요

1. **트래픽 캡처 (`mitmweb`)**: 웹서버와 클라이언트 간의 정상 API 호출 패킷을 캡처하여 `flows` 파일로 저장
2. **명세 초안 추출 (`mitmproxy2swagger` 1차)**: `flows`에서 호출된 모든 URL 경로를 추출
3. **경로 템플릿 정리 (`x-path-templates`)**: 정적 에셋 제외(`ignore:`), 경로 파라미터(`{id}`) 일반화 및 우선순위 정렬
4. **최종 명세 완성 (`mitmproxy2swagger` 2차)**: 요청/응답 스키마 및 예제 데이터가 포함된 `openapi.yaml` 완성
5. **Wazuh 룰 컴파일 (`gen_shadow_rules.py build`)**: `openapi.yaml`을 읽어 화이트리스트 반전(`negate="yes"`) 기반의 Wazuh 룰 XML 및 테스트 케이스 자동 생성
6. **검증 및 배포 (`test` / `logtest`)**: 로컬 검증 후 Wazuh Manager에 배포

---

## 사전 준비 (설치)

Python 환경이 설치된 PC에서 `mitmproxy`, `mitmproxy2swagger`, `pyyaml` 패키지를 설치합니다.

```powershell
pip install mitmproxy mitmproxy2swagger pyyaml
```

---

## 1단계: `mitmproxy`로 API 트래픽 캡처 (`flows` 파일 생성)

웹서버가 로컬(`localhost`)이 아니라 원격/내부망 IP(예: `http://192.168.0.141:8000`)에서 동작할 때는 **리버스 프록시(Reverse Proxy) 모드** 또는 **일반 프록시 모드**로 패킷을 캡처합니다.

### 방법 A: 리버스 프록시 모드 (권장)
내 PC의 `8080` 포트로 들어오는 요청을 대상 웹서버(`http://192.168.0.141:8000`)로 전달하면서 트래픽을 기록합니다.

```powershell
# 실행 시 웹 UI(http://127.0.0.1:8081)가 자동으로 열립니다.
mitmweb --mode reverse:http://192.168.0.141:8000 -p 8080
```
* **트래픽 발생시키기**: 브라우저에서 `http://localhost:8080`으로 접속하여 회원가입, 로그인, 상품 조회/검색, 장바구니 추가/수정/삭제, 주문/취소 등 **정상적인 사용자 시나리오의 모든 기능**을 수행합니다.

### 방법 B: 일반 프록시 모드 (클라이언트 접속 주소를 바꾸기 어려울 때)
```powershell
mitmweb -p 8080
```
* OS 또는 브라우저의 프록시 서버를 `127.0.0.1:8080`으로 설정한 뒤, 원래 주소(`http://192.168.0.141:8000`)로 접속해 정상 기능을 수행합니다.

### `flows` 파일 저장하기
1. `mitmweb` 관리 화면(`http://127.0.0.1:8081`) 상단 메뉴에서 **File → Save**를 클릭합니다.
2. 다운로드 폴더에 `flows` 파일(예: `C:\Users\sesac\Downloads\flows`)이 저장됩니다.
   *(또는 처음부터 `-w flows` 옵션을 주어 파일로 바로 기록할 수도 있습니다.)*

---

## 2단계: `mitmproxy2swagger`로 `openapi.yaml` 생성

`mitmproxy2swagger`는 **1차 실행(경로 템플릿 추출)** → **편집(`ignore:` 제거 및 `{id}` 정리)** → **2차 실행(스키마 및 예제 생성)**의 2단계로 동작합니다.

> **주의 (Windows 인코딩 오류 방지)**
> Windows 환경의 Python에서는 한글 데이터나 주석을 읽을 때 `cp949` 인코딩 에러(`UnicodeDecodeError`)가 발생할 수 있으므로, 실행 전 항상 **`$env:PYTHONUTF8="1"`**을 설정합니다.

### 2-1. 1차 실행 (엔드포인트 목록 초안 추출)

* `-i`: 1단계에서 저장한 `flows` 파일 경로
* `-o`: 생성할 `openapi.yaml` 파일 경로
* `-p`: 캡처된 대상 서버의 실제 주소 프리픽스 (`http://192.168.0.141:8000`)
* `-f flow`: mitmproxy 덤프 포맷 지정

```powershell
$env:PYTHONUTF8="1"
mitmproxy2swagger -i "C:\Users\sesac\Downloads\flows" -o "C:\Users\sesac\Downloads\openapi.yaml" -p http://192.168.0.141:8000 -f flow
```

### 2-2. `openapi.yaml` 편집 (`x-path-templates` 정리)

생성된 `openapi.yaml`을 에디터로 열어 하단의 `x-path-templates:` 목록을 정리합니다.

1. **정적 파일 및 웹 페이지 제외**: `.php`, `.js`, `.css`, `.ico` 등은 문서화 대상이 아니므로 `ignore:`를 그대로 유지합니다.
2. **문서화할 API의 `ignore:` 제거**: `/api/...` 엔드포인트 앞의 `ignore:`를 제거합니다.
3. **하드코딩된 숫자 경로 정리**:
   * `mitmproxy2swagger`는 `/api/v2/products/{id}`와 함께 `/api/v2/products/1`, `/api/v2/products/2`처럼 개별 숫자 경로도 함께 나열합니다.
   * `{id}` 템플릿만 남기고 개별 숫자 경로 줄은 삭제합니다.
4. **고정 문자열 경로 우선 배치 (매우 중요)**:
   * `x-path-templates`는 **위쪽에 있는 줄이 먼저 매칭(Greedy Matching)**됩니다.
   * `{id}`는 모든 문자열을 매칭하므로, **`/api/v2/orders/me`나 `/api/v2/products/search` 같은 고정 경로는 반드시 `{id}`가 포함된 경로보다 위쪽에 배치**해야 `{id}`에 흡수되지 않습니다.

```yaml
x-path-templates:
# 정적 페이지/에셋은 ignore: 유지
- ignore:/
- ignore:/assets/app.js
- ignore:/assets/style.css
- ignore:/cart.php
- ignore:/favicon.ico
- ignore:/login.php
- ignore:/me.php
- ignore:/order.php
- ignore:/orders.php
- ignore:/product.php
- ignore:/products.php
- ignore:/signup.php

# API 경로 (고정 문자열 경로인 /me, /search 를 {id} 보다 위에 배치!)
- /api/v2/cart
- /api/v2/cart/{id}
- /api/v2/login
- /api/v2/orders
- /api/v2/orders/me
- /api/v2/orders/{id}
- /api/v2/orders/{id}/cancel
- /api/v2/products
- /api/v2/products/search
- /api/v2/products/{id}
- /api/v2/signup
- /api/v2/users/me
```

### 2-3. 2차 실행 (최종 스키마 및 예제 데이터 반영)

편집한 `openapi.yaml`을 저장한 뒤, `--examples` 옵션을 추가하여 동일한 명령어를 한 번 더 실행합니다.

```powershell
$env:PYTHONUTF8="1"
mitmproxy2swagger -i "C:\Users\sesac\Downloads\flows" -o "C:\Users\sesac\Downloads\openapi.yaml" -p http://192.168.0.141:8000 -f flow --examples
```

실행이 완료되면 `paths:` 아래에 각 엔드포인트의 HTTP 메서드, 경로/쿼리 파라미터, 요청 본문(`requestBody`), 응답 스키마(`responses`)가 모두 채워진 최종 `openapi.yaml`이 완성됩니다.

---

## 3단계: `openapi.yaml` 기반 범용 Wazuh 룰 생성

완성된 `openapi.yaml`을 입력받아 Wazuh 룰 XML을 생성하기 위해 `gen_shadow_rules.py`를 사용합니다.

### 3-1. 범용 룰 생성 원리

`gen_shadow_rules.py`는 특정 API 경로에 종속되지 않고, 어떤 `openapi.yaml`이 입력되든 다음 규칙으로 Wazuh 룰을 컴파일합니다.

| 계층 | 룰 ID (예: `--base-id 100500`) | Level | 동작 원리 |
| :--- | :---: | :---: | :--- |
| **1. 기반 룰 (Scope)** | `100500` | `0` | `openapi.yaml`의 경로 프리픽스(예: `^/+api(?:/\|\?\|$)` 또는 `/rest` 등 자동 추론)에 해당하는 JSON 로그만 필터링합니다. **명세에 등록된 정상 요청은 여기서 종료(경보 없음)**됩니다. |
| **2. 미정의 메서드 판정** | `100501` | `6` | `openapi.yaml`에 등장하지 않는 HTTP 메서드(`PUT`, `OPTIONS`, `HEAD` 등)를 `negate="yes"`로 탐지합니다. |
| **3. 메서드별 미정의 경로 판정** | `100502` ~ `100505` | `6` | 메서드별로 허용된 모든 경로 템플릿(`{id}` → `[^/?]+` 또는 타입별 정규식)을 묶은 뒤 `negate="yes"`를 적용해 **명세에 없는 경로 호출**을 탐지합니다. |
| **4. 응답 코드별 단계 분류** | `100510` (L1 정찰)<br>`100511` (L2 발견)<br>`100512` (L3 악용)<br>`100513` (L3-E 오류) | `5`<br>`8`<br>`12`<br>`10` | 미정의 API 호출에 대한 서버 응답 코드로 공격 단계를 판별합니다:<br>• `404/405`: 존재하지 않는 경로/메서드 스캐닝 (L1)<br>• `401/403`: 숨은 API가 존재하나 인증/권한에 막힘 (L2)<br>• `2xx`: 숨은 Shadow API 호출 성공 (L3, MITRE T1190)<br>• `5xx`: 서버 내부 오류 유발 (L3-E) |
| **5. 빈도(Burst) 룰** | `100520` (F1 스캔)<br>`100521` (F2 유출) | `10`<br>`14` | 동일 `client_ip`에서 단시간 내 반복 호출 시 경보를 격상합니다:<br>• 30초 내 L1 20회 이상 → F1 자동화 정찰 (T1595.003)<br>• 60초 내 L3 10회 이상 → F2 대량 유출 (T1119) |

### 3-2. 룰 빌드(`build`) 실행

```powershell
$env:PYTHONUTF8="1"

# 기본 빌드 (생성 파일은 현재 실행 디렉토리 '.' 에 저장됨)
python D:\Project\team_one\detection\shadow_api\gen_shadow_rules.py build `
  --spec "C:\Users\sesac\Downloads\openapi.yaml" `
  --base-id 100500

# 특정 폴더에 결과물(shadow_api_rules.xml, rules_meta.json, testcases.jsonl)을 생성할 때 (-d / --out-dir)
python D:\Project\team_one\detection\shadow_api\gen_shadow_rules.py build `
  --spec "C:\Users\sesac\Downloads\openapi.yaml" `
  --base-id 100500 `
  -d "C:\Users\sesac\Downloads\output"
```

#### 주요 범용 옵션
* `-d <폴더경로>` / `--out-dir <폴더경로>`: 생성되는 파일(`shadow_api_rules.xml`, `rules_meta.json`, `testcases.jsonl`)의 저장 폴더를 지정합니다. 생략하면 **명령어를 실행한 현재 디렉토리(`.`)**에 생성됩니다. (개별 파일 경로는 `--out`, `--meta`, `--cases`로 각각 지정 가능)
* `--strict-param-types`: `openapi.yaml`의 `parameters`에 정의된 `schema.type`을 읽어 `integer`는 `[0-9]+`, `number`는 `[0-9]+(?:\.[0-9]+)?`, `uuid`는 UUID 정규식으로 엄격하게 제한합니다.
* `--scope-regex "<정규식>"`: API 검사 대상 경로 정규식을 수동으로 지정할 때 사용합니다. (생략 시 `openapi.yaml`에서 자동 추론)
* `--allowlist <파일경로>`: 명세서에는 없지만 헬스체크 등 정상 운영에 쓰이는 내부 API 예외 목록(`shadow_api_allowlist.yaml`)을 반영합니다.

빌드 실행 시 다음 3개 파일이 생성됩니다:
* `shadow_api_rules.xml`: Wazuh Manager에 배포할 최종 룰 XML
* `rules_meta.json`: 명세 SHA256 해시, 추출된 엔드포인트 목록, 룰 ID 매핑 메타데이터
* `testcases.jsonl`: 입력된 명세로부터 동적 생성된 정상/비정상 검증용 테스트 케이스

---

## 4단계: 생성된 룰 검증 및 Wazuh 서버 배포

### 4-1. 로컬 로직 검증 (`test`)
Wazuh 서버에 올리기 전, 파이썬 엔진으로 정상 요청(경보 없음)과 공격 단계별(L1, L2, L3, L3E, OTHER, F1, F2) 시나리오가 모두 의도대로 판정되는지 테스트합니다.

```powershell
$env:PYTHONUTF8="1"
python D:\Project\team_one\detection\shadow_api\gen_shadow_rules.py test -v
```

### 4-2. 기존 로그 리플레이 (`replay`, 선택 사항)
기존에 수집된 `app.log`나 `archives.json` 파일이 있다면, 배포 전에 미리 룰에 통과시켜 오탐 여부와 IP별 탐지 통계를 확인할 수 있습니다.

```powershell
python D:\Project\team_one\detection\shadow_api\gen_shadow_rules.py replay /path/to/app.log
```

### 4-3. Wazuh Manager 배포 및 `wazuh-logtest` 검증

생성된 `shadow_api_rules.xml`을 Wazuh Manager 서버의 `/var/ossec/etc/rules/` 경로에 배포합니다.

```bash
# 1. 룰 파일 복사 및 권한 설정
sudo cp shadow_api_rules.xml /var/ossec/etc/rules/shadow_api_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/shadow_api_rules.xml
sudo chmod 660 /var/ossec/etc/rules/shadow_api_rules.xml

# 2. Wazuh 설정 문법 검사 및 재시작
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager

# 3. 실제 wazuh-logtest 바이너리에 테스트 케이스를 주입해 룰 ID 매칭 확인
sudo python3 gen_shadow_rules.py logtest -v
```
