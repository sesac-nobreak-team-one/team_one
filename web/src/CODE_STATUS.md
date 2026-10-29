# 코드 현황 정리 (sesac_shop_web_SSH_v1)

> 작성일: 2026-10-27
> 이 폴더는 git 저장소가 아니고 모든 파일의 수정 시각이 똑같습니다(2026-10-27 10:30, 복사된 시점). 그래서 **누가 무엇을 바꿨는지(diff)는 알 수 없습니다.** 이 문서는 **현재 코드 상태 그대로**를 정리한 것이며, 바뀐 흔적으로 보이는 부분은 "⚠ 확인 필요"로 표시했습니다.

---

## 1. 한 줄 요약

PHP 7.4 + Apache로 만든 **보안 프로젝트 시연용 쇼핑몰 웹 서버(DMZ, 192.168.20.10)** 입니다.
- **v2 API**: 정상 API (JWT 인증, 입력 검증, prepared statement)
- **v1 API**: **일부러 넣은 취약점**이 있는 레거시 API (인증 없는 개인정보 조회, 명령어 주입)
- 원래 FastAPI(Python)였던 코드를 PHP로 옮긴 것입니다(주석의 `← app/...py` 표시).
- DB(MySQL)는 별도 서버(LAN, 192.168.10.20)에 있고, 이 폴더에는 DB 쪽 파일이 없습니다.

---

## 2. 폴더 구조

```
.
├─ Dockerfile                 php:7.4-apache 이미지 빌드 (pdo_mysql, mbstring, rewrite, unique_id)
├─ compose.web.yml            웹 컨테이너 실행 (실제 사용)
├─ docker-compose.yml         compose.web.yml 과 내용 100% 동일
├─ INSTALL.txt                웹 VM 설치 안내
├─ .env / .env.example        환경변수 (DB 주소, JWT 키, v1 허용 대역 등)
├─ composer.json / vendor/    firebase/php-jwt ^6.0 (vendor 포함됨 → 오프라인 가능)
├─ config/config.php          DB·JWT 설정 (환경변수 우선)
├─ deploy/apache-vhost.conf   Apache 가상호스트 (v1 접근 IP 제한)
├─ public/                    웹 루트 (DocumentRoot)
│   ├─ index.php              → /products.php 로 리다이렉트
│   ├─ products.php, product.php, login.php, signup.php, me.php, orders.php   (화면)
│   ├─ assets/app.js, style.css   화면 로직 (v2 API만 호출)
│   ├─ api/index.php          v2 API 프런트 컨트롤러
│   ├─ api/v1/index.php       v1(레거시) API 프런트 컨트롤러
│   └─ docs/                  Swagger UI + openapi.yaml (v2만 문서화)
├─ src/                       App\ 네임스페이스 (PSR-4)
│   ├─ Api/                   컨트롤러 (V1, V2) + AuthMiddleware
│   ├─ Core/                  Router, Request, Response, Security(JWT/bcrypt), Logger, Database
│   ├─ Services/              업무 규칙 + 업무 예외 클래스
│   ├─ Repositories/          SQL 실행 (전부 prepared statement)
│   ├─ Validation/            입력 검증 (실패 시 422)
│   └─ View/layout.php        화면 공통 header/footer
├─ logs/                      app.log, apache/*.log (용량 큼, 아래 6번 참고)
└─ wazuh-agent.deb            Wazuh 에이전트 설치 파일 (13MB) ⚠
```

계층 구조(v2): `Controller → Service → Repository → DB`
v1은 일부러 이 규칙을 어기고 Controller가 Repository를 바로 부릅니다.

---

## 3. API 목록

### v2 (정식, `public/api/index.php`)

| 메서드 | 경로 | 인증 | 설명 |
|---|---|---|---|
| POST | `/api/v2/signup` | - | 회원가입 (bcrypt 해시, 이메일 중복 409) |
| POST | `/api/v2/login` | - | 로그인 → JWT 발급 (HS256, 60분) |
| GET | `/api/v2/users/me` | JWT | 내 정보 |
| GET | `/api/v2/products` | - | 상품 목록 (`limit` 1~100, `offset`, `category`) |
| GET | `/api/v2/products/{id}` | - | 상품 상세 |
| POST | `/api/v2/orders` | JWT | 주문 (최대 10종, 수량 1~99, 가격은 DB 값 사용, 트랜잭션 + `FOR UPDATE` 재고 잠금) |
| GET | `/api/v2/orders/me` | JWT | 내 주문 목록 |

- 에러는 모두 `{"detail": "..."}` 형태, 500 에러 내용은 응답에 노출 안 함.
- `openapi.yaml`에 위 7개가 그대로 문서화되어 있고, 프런트(`app.js`)도 이 7개만 사용합니다.

### v1 (레거시 · 의도된 취약점, `public/api/v1/index.php`)

| 메서드 | 경로 | 취약점 |
|---|---|---|
| GET | `/api/v1/users/{id}` | **BOLA/IDOR** – JWT 서명·만료는 검증하지만 소유권 검사가 없음. 아무 계정이나 로그인한 토큰으로 번호만 바꾸면 남의 이름/이메일/전화/주소 조회 |
| GET | `/api/v1/diagnostics/ping?host=` | **OS 명령어 주입(RCE)** – `shell_exec("ping -c 1 " . $host)`, 검증 전혀 없음 |

- **v1 진입점에서 JWT(서명+만료)만 확인**하고, 그 뒤 인가(소유권·권한) 검사는 전혀 없음 → "토큰=신뢰"로 착각한 전형적 사례(2022년식 침해 모양).
  - 공격 체인: v2 `signup`(무인증 공개) 으로 아무 계정 자가가입 → 토큰 획득 → v1에서 대량 BOLA + RCE.
  - 인증을 통과하므로 `app.log` 의 `user_id` 에 호출자 id가 찍힘 → "한 유저가 짧은 시간에 user id를 순차 열거" 같은 탐지 룰 실습이 가능.
- 문서(openapi)에는 일부러 빠져 있음 ("Shadow API" 시나리오).
- 접근 제한은 코드가 아니라 **Apache 설정(IP 제한) + JWT** 으로만 합니다 → 4번 참고.

---

## 4. 배포 / 설정 현황

### 실행 방식 (`compose.web.yml`)
- 이미지 `shop-web-web:latest` 를 **재사용**, `pull_policy: never` → **폐쇄망용으로 바뀐 버전**입니다.
- `build:` 항목이 없음. 대신 `public, src, config, vendor, logs` 를 **볼륨 마운트**해서 재빌드 없이 코드 수정이 바로 반영되게 되어 있음.
- 필수 환경변수(`DB_HOST`, `DB_PASSWORD`, `JWT_SECRET`, `V1_ALLOWED_NET`)가 없으면 compose가 실행을 거부함.

### 현재 `.env` 값 (비밀값 제외)
| 키 | 값 |
|---|---|
| WEB_BIND | 0.0.0.0 |
| DB_HOST | 192.168.10.20 |
| DB_PORT | 3306 |
| V1_ALLOWED_NET | 192.168.0.0/24 |
| JWT_SECRET / DB_PASSWORD / MYSQL_ROOT_PASSWORD | 기본값(`change-me`)에서 **변경되어 있음** ✅ |

### Apache 설정 (`deploy/apache-vhost.conf`)
```apache
<Directory /var/www/html/public/api/v1>
    Require ip ${V1_ALLOWED_NET}
    Require ip 172.16.0.0/12      # 도커 내부망 대역 허용  ← 추가된 것으로 보임
</Directory>
```

---

## 5. ⚠ 확인이 필요한 부분 (변경 흔적 / 불일치)

1. **v1 접근 제한에 `172.16.0.0/12`(도커 내부망) 추가**
   - `Require` 여러 줄은 **OR 조건**이라, 도커 게이트웨이(예: `172.18.0.1`)를 거쳐 들어온 요청은 팀 대역이 아니어도 v1에 접근됩니다.
   - 실제로 `app.log` 초반 기록의 client_ip가 `172.18.0.1` 입니다. 포트 포워딩 방식에 따라 **외부 요청이 172.18.0.1로 보이면 v1 IP 제한이 사실상 무력화**될 수 있으니 의도한 것인지 확인 필요.

2. ~~vhost 설정은 이미지에 구워져 있음~~ → **수정됨**: compose 에서 `deploy/apache-vhost.conf` 를 마운트하므로 재빌드 없이 컨테이너 재시작만으로 반영됨.

3. **INSTALL.txt 와 compose 불일치**
   - INSTALL.txt: `docker compose -f compose.web.yml up -d --build`, 폴더명 `sesac_shop_web_php`
   - 실제 compose: `build:` 없음 + `pull_policy: never` → `--build` 는 의미 없고, **`shop-web-web:latest` 이미지가 미리 있어야만** 뜹니다. 새 VM에서는 이미지를 `docker load` 등으로 먼저 넣어야 함.

4. **`docker-compose.yml` 과 `compose.web.yml` 이 완전히 동일** – 하나는 정리 대상으로 보임.

5. **`wazuh-agent.deb` 추가** – Wazuh(보안 모니터링) 에이전트 설치 파일이 들어 있음. 설치 안내/설정 파일은 없어서 어디까지 진행했는지 알 수 없음.

6. **Swagger 문서(`/docs`)가 CDN(jsdelivr)에서 로드** – 폐쇄망이면 문서 화면이 안 뜸.

7. **`.env.example` 상단 주석이 옛날 구성(192.168.0.147 한 대) 기준** – 아래쪽 값은 DMZ/LAN 분리 기준으로 갱신됨.

8. ~~v1 로그의 `response_bytes` 는 항상 0~~ → **수정됨**: v1도 `Response::json()` 을 거쳐 실제 크기가 기록됨.

9. **DB 관련 파일 없음** – `.env.example` 이 언급하는 `compose.db.yml`, `deploy/mysql-init/02-user.sql` 은 이 폴더에 없음(DB 서버 쪽에 있을 것으로 추정).

---

## 6. 로그 상태 (실제 테스트 진행 흔적)

| 파일 | 크기 |
|---|---|
| `logs/app.log` | 약 71MB (271,489줄, 요청 1건 = JSON 1줄) |
| `logs/apache/shop_access.log` | 약 92MB |
| `logs/apache/shop_error.log` | 약 58MB |

- 기간: **2026-10-26 19:46 ~ 2026-10-27 10:22** (KST)
- User-Agent 상위: `Fuzz` 약 20만 건, `gobuster` 약 6.9만, `python-requests` 1,727, `sqlmap` 277, `curl` 106
  → **퍼징·디렉터리 스캔·SQL 인젝션 등 공격 시뮬레이션을 이미 돌려본 상태**입니다.
- 마지막 기록은 `192.168.0.27` 에서 curl로 `/api/v1/users/...` 를 테스트한 것.
- 로그가 커서 계속 쌓이면 디스크 정리/로테이션이 필요할 수 있음.

---

## 7. 정리: 지금 어디까지 되어 있나

| 항목 | 상태 |
|---|---|
| 쇼핑몰 화면 + v2 API (회원/상품/주문) | ✅ 구현 완료 |
| JWT 인증, 입력 검증, SQL 인젝션 방어 | ✅ 구현 완료 |
| v1 의도된 취약점 2개 (IDOR, 명령어 주입) | ✅ 구현 완료 |
| 요청 로그 (JSON, request_id 로 Apache 로그와 연결) | ✅ 구현 완료 |
| DMZ/LAN 분리 배포 설정 (.env, INSTALL) | ✅ 반영됨 (일부 문서 불일치) |
| 폐쇄망 실행 (이미지 재사용 + 볼륨 마운트) | ✅ 반영됨 (이미지 사전 준비 필요) |
| v1 IP 제한에 도커 대역 추가 | ⚠ 의도 확인 필요 (5-1, 5-2) |
| 공격 시뮬레이션 | ✅ 진행된 흔적 있음 (6번) |
| Wazuh 에이전트 연동 | ❓ 설치 파일만 있음 |

---

## 7. WAF·Wazuh 연동 전 로그 정비 (적용됨)

| 문제 | 조치 |
|---|---|
| `logs/` 권한 문제로 `app.log` 쓰기 실패 (10/26 08:16~10:16 UTC, 207,102건 누락) | compose `command` 에서 시작할 때마다 `logs/`, `app.log` 를 `www-data` 소유로 변경 (Dockerfile의 chown은 바인드 마운트에 가려짐) |
| Apache 로그 UTC / app.log KST | 컨테이너에 `TZ=Asia/Seoul`. 추가로 Apache 로그 끝에 `UNIQUE_ID` 를 남겨 app.log `request_id` 와 1:1 대조 가능 |
| v1 `response_bytes` 항상 0 | v1 응답을 전부 `Response::json()` 으로 통일 |
| v1 `user_id` 항상 null | 커밋 c86f597 에서 JWT 검증 추가로 해결 (그 이전 로그라서 null) |
| WAF 프록시 뒤에서 client_ip 가 WAF IP로 바뀜 | `mod_remoteip` + `RemoteIPInternalProxy ${WAF_PROXY_NET}`. REMOTE_ADDR·`Require ip`·Apache 로그(`%a`)가 모두 실제 IP 기준. WAF는 반드시 `X-Forwarded-For` 를 붙여야 함 |
