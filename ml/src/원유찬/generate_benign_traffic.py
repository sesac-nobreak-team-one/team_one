#!/usr/bin/env python3
r"""
B-Profile 기반 정상 사용자 트래픽 생성기 (CICIDS2017 방법론 기반)
------------------------------------------------------------------
논문: Sharafaldin et al., "Toward Generating a New Intrusion Detection Dataset" (2018)

[1 PC = 1 고객]
  팀원 6명이 각자 PC 에서 실행하고, 각 PC(=IP 1개)는 '한 명의 고객'으로
      방문(쇼핑) -> 사이트 이탈(휴식) -> 재방문 -> ...
  을 반복합니다. 한 사람 = 하나의 기기(User-Agent) + 하나의 계정 + 하나의 브라우저(쿠키/JWT/캐시 유지)

[2026-10-29 보정 (v3)] 실제 사람/브라우저와 같아지도록
  1) 실제 프론트엔드(assets/app.js) 호출 흐름 그대로 재현
       products.php -> GET /api/v2/products?limit=20&offset=0[&category=..]
       product.php?id=N -> GET /api/v2/products/N
       orders.php -> GET /api/v2/orders/me?limit=10&offset=0 (로그인 필요, 아니면 login.php 로 이동)
       me.php -> GET /api/v2/users/me
       login.php -> POST /api/v2/login -> products.php 로 이동
       signup.php -> POST /api/v2/signup -> login.php?joined=1
       주문 -> POST /api/v2/orders {items:[{product_id, quantity}]} -> 상품 다시 조회
     상품 72개(id 1~72), 카테고리 5종, 페이지당 20개
  2) 체류 시간: 실제 사람 로그(Elastic 공개 데이터) 실측 분포에 맞춤
       페이지 간 간격 중앙값 약 6초, 75% 16초 이내, 90% 29초 이내 (기존 1.5~5초는 너무 빠르고 규칙적)
       로그인/회원가입 폼 입력 시간 별도 반영
  3) 브라우저처럼 정적 파일(/assets/style.css, /assets/app.js)과 Referer 헤더 전송
       (방문 첫 페이지에서 받고 이후 캐시 사용, 재방문 시 일부 재검증)
  4) 행동 추가: 카테고리 필터, 다음 페이지, 상품 주문, 신규 회원가입
       DB 에 주문/계정을 쓰지 않으려면 --no-writes
  5) 서버 상태 점검: 시작 시 API 가 정상인지 확인, 실행 중 5xx/접속실패가 많아지면 자동 중단
       (DB 장애 중 수집된 '500 에러투성이 정상 데이터'가 학습에 섞이는 것 방지)

실행 예시 (팀원 번호 1~6 을 각자 다르게 지정):
  python generate_benign_traffic.py --member 1 --duration 1800
  python generate_benign_traffic.py --member 2 --duration 1800 --device iphone
  python generate_benign_traffic.py --member 6 --duration 1800 --start-as-guest   # 비회원으로 시작, 도중에 가입
"""

import argparse
import collections
import csv
import datetime
import http.cookiejar
import io
import json
import math
import pathlib
import random
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# 윈도우 콘솔 즉시 출력(Flush) 및 UTF-8 인코딩 설정
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', line_buffering=True)
        sys.stderr.reconfigure(encoding='utf-8', line_buffering=True)
    except AttributeError:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)

# -------------------------------------------------------------
# 사이트 정보 (2026-10-29 실제 쇼핑몰 app.js / API 확인 결과)
# -------------------------------------------------------------
PRODUCT_IDS = list(range(1, 73))
CATEGORIES = ["의류", "전자기기", "생활용품", "식품", "도서"]
PRODUCT_PAGE_SIZE = 20
ORDER_PAGE_SIZE = 10
STATIC_ASSETS = ["/assets/style.css", "/assets/app.js"]
TYPO_PATHS = ["/product_old.php", "/item/999", "/cart.html", "/help.php", "/event.php"]

DEVICES = {
    "win-chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "iphone": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "galaxy": "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "win-edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "mac-safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
}

USER_ACCOUNTS_18 = [{"email": f"user{i}@example.com", "password": "Test1234!"} for i in range(1, 19)]
KOREAN_NAMES = ["김민준", "이서연", "박지훈", "최수빈", "정하은", "강도윤", "조예린", "윤시우", "장유나", "임준서"]

# 방문 의도(페르소나) 가중치
PERSONAS = ["단순구경", "꼼꼼탐색", "주문확인", "구매", "신규가입"]
PERSONA_WEIGHTS = {"단순구경": 0.40, "꼼꼼탐색": 0.30, "주문확인": 0.20, "구매": 0.10, "신규가입": 0.0}
GUEST_SIGNUP_PROB = 0.15  # 비회원 상태인 사람이 방문 시 가입할 확률

# 서버 상태 감시 (최근 N개 요청 중 5xx/접속실패 비율이 기준 이상이면 중단)
HEALTH_WINDOW = 30
HEALTH_MIN_SAMPLES = 10
HEALTH_MAX_ERROR_RATIO = 0.3

stats_lock = threading.Lock()
total_requests = 0
status_counts = {}
persona_counts = {p: 0 for p in PERSONAS}


class ServerUnhealthy(Exception):
    """API 가 5xx 를 계속 반환하거나 접속이 안 될 때"""


# -------------------------------------------------------------
# 사람의 시간 (실측 분포 기반)
# -------------------------------------------------------------
def dwell_seconds():
    """페이지 체류 시간: 로그정규(중앙값 ~6초, 긴 꼬리), 1~90초"""
    return max(1.0, min(random.lognormvariate(math.log(6.0), 1.1), 90.0))


def typing_seconds(kind):
    """폼 입력 시간"""
    if kind == "login":
        return max(4.0, min(random.lognormvariate(math.log(9.0), 0.4), 30.0))
    if kind == "signup":
        return max(15.0, min(random.lognormvariate(math.log(35.0), 0.35), 90.0))
    return max(1.0, min(random.lognormvariate(math.log(3.0), 0.5), 15.0))  # 수량 선택 등


def utc_now_str():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def detect_local_ip(target_host):
    """대상 서버로 나가는 로컬 IP 확인 (실제 패킷 전송 없음) - manifest 기록용"""
    try:
        u = urllib.parse.urlparse(target_host)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((u.hostname, u.port or 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


class Person:
    """
    한 명의 고객 (= 하나의 기기, 하나의 계정, 하나의 브라우저)
    쿠키, JWT(localStorage), 정적 파일 캐시는 방문 사이에도 유지됩니다.
    """

    def __init__(self, target_host, device, account, stop_event, allow_writes=True, member=0):
        self.base = target_host.rstrip('/')
        self.device_name = device
        self.user_agent = DEVICES[device]
        self.account = account
        self.stop_event = stop_event
        self.allow_writes = allow_writes
        self.member = member
        self.jwt_token = None
        self.current_page = None          # Referer 로 쓸 현재 페이지 URL
        self.assets_cached = False
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar))
        self.recent = collections.deque(maxlen=HEALTH_WINDOW)
        self.visit_requests = 0
        self.visit_status = {}

    # ---------------------------------------------------------
    # 시간 흐름
    # ---------------------------------------------------------
    def wait(self, sec):
        if self.stop_event.wait(sec):
            raise KeyboardInterrupt

    def dwell(self):
        self.wait(dwell_seconds())

    # ---------------------------------------------------------
    # HTTP (브라우저 동작 흉내)
    # ---------------------------------------------------------
    def _send(self, method, path, kind, data=None, referer=None):
        headers = {"User-Agent": self.user_agent, "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7"}
        if kind == "page":
            headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        elif kind == "asset":
            headers["Accept"] = "text/css,*/*;q=0.1" if path.endswith(".css") else "*/*"
        else:  # api (fetch)
            headers["Accept"] = "*/*"
            if self.jwt_token:
                headers["Authorization"] = f"Bearer {self.jwt_token}"
        if referer:
            headers["Referer"] = referer

        body = None
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        status, payload, final_url = 0, b"", self.base + path
        try:
            with self.opener.open(req, timeout=10) as resp:
                status, payload, final_url = resp.status, resp.read(), resp.geturl()
        except urllib.error.HTTPError as e:
            status = e.code
            try:
                payload = e.read()
            except Exception:
                payload = b""
        except Exception:
            status = 0
        self._record(status, kind)
        return status, payload, final_url

    def _record(self, status, kind):
        global total_requests
        self.visit_requests += 1
        self.visit_status[status] = self.visit_status.get(status, 0) + 1
        with stats_lock:
            total_requests += 1
            status_counts[status] = status_counts.get(status, 0) + 1
        if kind in ("page", "api"):
            self.recent.append(status)
            errs = sum(1 for s in self.recent if s == 0 or s >= 500)
            if len(self.recent) >= HEALTH_MIN_SAMPLES and errs / len(self.recent) >= HEALTH_MAX_ERROR_RATIO:
                raise ServerUnhealthy(f"최근 요청 {len(self.recent)}건 중 {errs}건이 5xx/접속실패")

    def api(self, method, path, data=None):
        """app.js 의 fetch() 호출. 401 이면 로그인 만료로 보고 토큰 삭제"""
        self.wait(random.uniform(0.05, 0.3))  # 페이지 로드 후 스크립트 실행까지
        status, payload, _ = self._send(method, path, "api", data=data, referer=self.current_page)
        if status == 401:
            self.jwt_token = None
        return status, payload

    def open_page(self, path, from_link=True):
        """페이지 이동: HTML -> (캐시 없으면) css/js -> 해당 페이지의 API 호출"""
        referer = self.current_page if from_link else None
        status, _, final_url = self._send("GET", path, "page", referer=referer)
        self.current_page = final_url
        if status != 200:
            return status
        if not self.assets_cached:
            for a in STATIC_ASSETS:
                self._send("GET", a, "asset", referer=self.current_page)
            self.assets_cached = True

        final_path = urllib.parse.urlparse(final_url).path
        q = urllib.parse.parse_qs(urllib.parse.urlparse(final_url).query)
        if final_path == "/products.php":
            self.api("GET", f"/api/v2/products?limit={PRODUCT_PAGE_SIZE}&offset=0")
        elif final_path == "/product.php" and "id" in q:
            self.api("GET", f"/api/v2/products/{q['id'][0]}")
        elif final_path == "/orders.php":
            if not self.jwt_token:          # requireLogin() -> login.php 로 이동
                return self.open_page("/login.php")
            self.api("GET", f"/api/v2/orders/me?limit={ORDER_PAGE_SIZE}&offset=0")
        elif final_path == "/me.php":
            if not self.jwt_token:
                return self.open_page("/login.php")
            self.api("GET", "/api/v2/users/me")
        return status

    # ---------------------------------------------------------
    # 화면 안에서의 동작 (페이지 이동 없이 API 만 호출)
    # ---------------------------------------------------------
    def click_category(self):
        cat = random.choice(CATEGORIES)
        params = urllib.parse.urlencode({"limit": PRODUCT_PAGE_SIZE, "offset": 0, "category": cat})
        self.api("GET", f"/api/v2/products?{params}")

    def click_next_page(self, offset):
        self.api("GET", f"/api/v2/products?limit={PRODUCT_PAGE_SIZE}&offset={offset}")

    def login(self):
        """login.php 에서 아이디/비밀번호 입력 후 로그인 -> products.php 로 이동"""
        if self.jwt_token or not self.account:
            return bool(self.jwt_token)
        if urllib.parse.urlparse(self.current_page or "").path != "/login.php":
            self.open_page("/login.php")
            self.wait(1.0)
        self.wait(typing_seconds("login"))
        status, payload = self.api("POST", "/api/v2/login", data=self.account)
        if status == 200:
            try:
                self.jwt_token = json.loads(payload.decode()).get("access_token")
            except Exception:
                self.jwt_token = None
        if self.jwt_token:
            self.open_page("/products.php")
        return bool(self.jwt_token)

    def place_order(self, pid):
        """상품 상세에서 수량 선택 후 주문 -> 상품 다시 조회 (app.js 와 동일)"""
        if not self.allow_writes or not self.jwt_token:
            return
        self.wait(typing_seconds("other"))
        qty = random.choices([1, 2, 3], weights=[0.75, 0.2, 0.05])[0]
        status, _ = self.api("POST", "/api/v2/orders", data={"items": [{"product_id": pid, "quantity": qty}]})
        if status == 200:
            self.api("GET", f"/api/v2/products/{pid}")

    def signup(self):
        """비회원 -> 회원가입 -> 로그인 (가입한 계정이 이 사람의 계정이 됨)"""
        if not self.allow_writes or self.account:
            return
        self.open_page("/signup.php")
        self.wait(typing_seconds("signup"))
        email = f"m{self.member}_{int(time.time())}_{random.randint(100, 999)}@example.com"
        body = {"name": random.choice(KOREAN_NAMES), "email": email, "password": "Test1234!"}
        if random.random() < 0.5:
            body["phone"] = f"010-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}"
        status, _ = self.api("POST", "/api/v2/signup", data=body)
        if status in (200, 201):
            self.account = {"email": email, "password": "Test1234!"}
            self.open_page("/login.php?joined=1")
            self.login()

    def maybe_typo(self, prob):
        if random.random() < prob:
            self._send("GET", random.choice(TYPO_PATHS), "page", referer=None)
            self.wait(random.uniform(1.0, 3.0))

    def visible_product(self, offset=0):
        page = PRODUCT_IDS[offset:offset + PRODUCT_PAGE_SIZE] or PRODUCT_IDS
        return random.choice(page)

    # ---------------------------------------------------------
    # 방문 시나리오
    # ---------------------------------------------------------
    def enter_site(self):
        """사이트 진입: 메인 주소 / 북마크한 목록 / 공유받은 상품 링크"""
        r = random.random()
        if r < 0.5:
            self.open_page("/index.php", from_link=False)   # -> products.php 로 리다이렉트
        elif r < 0.85:
            self.open_page("/products.php", from_link=False)
        else:
            self.open_page(f"/product.php?id={random.choice(PRODUCT_IDS)}", from_link=False)

    def _browse_list(self, max_details):
        offset = 0
        # 카테고리/다음 페이지 버튼은 상품 목록 화면에만 있으므로 목록이 아니면 먼저 목록으로 이동
        if urllib.parse.urlparse(self.current_page or "").path != "/products.php":
            self.dwell(); self.open_page("/products.php")
        if random.random() < 0.35:
            self.dwell(); self.click_category()
        elif random.random() < 0.25:
            offset = random.choice([20, 40, 60])
            self.dwell(); self.click_next_page(offset)
        for _ in range(random.randint(0, max_details)):
            self.dwell()
            self.open_page(f"/product.php?id={self.visible_product(offset)}")

    def scenario_casual(self):
        """단순구경: 목록 보고 상품 0~2개 보고 나감"""
        self.enter_site()
        self._browse_list(max_details=2)
        self.dwell()
        self.maybe_typo(0.02)

    def scenario_explore(self):
        """꼼꼼탐색: 여러 상품 비교, 목록으로 돌아오기, 카테고리 변경, 가끔 구매"""
        self.enter_site()
        for _ in range(random.randint(1, 3)):
            self._browse_list(max_details=3)
            self.dwell()
            if random.random() < 0.5:
                self.open_page("/products.php")
        if self.account and random.random() < 0.15:
            if self.login():
                pid = self.visible_product()
                self.dwell(); self.open_page(f"/product.php?id={pid}")
                self.dwell(); self.place_order(pid)
        self.dwell()
        self.maybe_typo(0.03)

    def scenario_account(self):
        """주문확인: 로그인 -> 내 주문 -> (내 정보) -> (목록)"""
        self.enter_site()
        self.dwell()
        if not self.login():
            return
        self.dwell(); self.open_page("/orders.php")
        if random.random() < 0.6:
            self.dwell(); self.open_page("/me.php")
        if random.random() < 0.3:
            self.dwell(); self.open_page("/products.php")
        self.dwell()

    def scenario_buy(self):
        """구매: 상품 확인 -> 로그인 -> 주문 -> 내 주문 확인"""
        self.enter_site()
        pid = self.visible_product()
        self.dwell(); self.open_page(f"/product.php?id={pid}")
        if random.random() < 0.4:
            other = self.visible_product()
            self.dwell(); self.open_page(f"/product.php?id={other}")
            self.dwell(); self.open_page(f"/product.php?id={pid}")
        if not self.jwt_token:
            self.dwell()
            if not self.login():
                return
            self.dwell(); self.open_page(f"/product.php?id={pid}")
        self.dwell(); self.place_order(pid)
        if random.random() < 0.5:
            self.dwell(); self.open_page("/orders.php")
        self.dwell()

    def scenario_signup(self):
        """신규가입: 둘러보다가 가입 -> 로그인"""
        self.enter_site()
        self.dwell()
        self.signup()
        self.dwell()

    def choose_persona(self):
        if not self.account:
            if self.allow_writes and random.random() < GUEST_SIGNUP_PROB:
                return "신규가입"
            return random.choices(["단순구경", "꼼꼼탐색"], weights=[0.6, 0.4])[0]
        weights = dict(PERSONA_WEIGHTS)
        if not self.allow_writes:
            weights["꼼꼼탐색"] += weights.pop("구매")
        names = [p for p in weights if weights[p] > 0]
        return random.choices(names, weights=[weights[p] for p in names])[0]

    def visit(self, persona):
        """한 번의 방문 수행. 방문 요약(dict) 반환"""
        self.visit_requests = 0
        self.visit_status = {}
        self.current_page = None
        # 브라우저 캐시: 재방문 시 30% 확률로 정적 파일을 다시 받음 (캐시 만료/재검증)
        if random.random() < 0.3:
            self.assets_cached = False
        start = utc_now_str()
        with stats_lock:
            persona_counts[persona] += 1
        error = ""
        try:
            {"단순구경": self.scenario_casual, "꼼꼼탐색": self.scenario_explore, "주문확인": self.scenario_account,
             "구매": self.scenario_buy, "신규가입": self.scenario_signup}[persona]()
        except ServerUnhealthy as e:
            error = str(e)
        return {
            "persona": persona,
            "logged_in": bool(self.jwt_token),
            "start_utc": start,
            "end_utc": utc_now_str(),
            "requests": self.visit_requests,
            "status_counts": json.dumps(self.visit_status),
            "error": error,
        }


# -------------------------------------------------------------
# 서버 상태 점검 (시작 전)
# -------------------------------------------------------------
def preflight(person):
    """
    실제 브라우저처럼 products.php 를 열어 목록 API 가 200 인지 확인합니다.
    (API 만 단독으로 찌르면 '페이지 없는 API 호출'이 정상 로그에 남으므로 페이지 흐름으로 점검)
    """
    person.visit_requests = 0
    person.visit_status = {}
    try:
        person.open_page("/products.php", from_link=False)
    except ServerUnhealthy:
        pass
    codes = person.visit_status
    ok = codes.get(200, 0) >= 2 and not any(s == 0 or s >= 500 for s in codes)
    return ok, codes


# -------------------------------------------------------------
# 1 PC = 1 고객 모드 (기본)
# -------------------------------------------------------------
def run_single_customer(args, account, device, manifest_path, local_ip):
    stop_event = threading.Event()
    person = Person(args.target, device, account, stop_event, allow_writes=not args.no_writes, member=args.member)
    start_time = time.time()
    visit_idx = 0

    ok, codes = preflight(person)
    if not ok:
        print(f"[중단] 서버 점검 실패: products.php 응답 코드 {codes}")
        print("       API 가 5xx 를 반환하거나 접속이 안 됩니다. 웹서버/DB 상태를 확인한 뒤 다시 실행하세요.")
        print("       (이 상태로 수집한 데이터는 정상 데이터로 쓸 수 없습니다)")
        return 0, "preflight_failed"
    print(f"[점검] 서버 정상 (products.php 응답 {codes})\n")

    fields = ["member", "local_ip", "visit_idx", "persona", "account", "device", "logged_in",
              "start_utc", "end_utc", "requests", "status_counts", "error", "label"]
    abort_reason = ""
    with open(manifest_path, "w", newline="", encoding="utf-8-sig") as mf:
        writer = csv.DictWriter(mf, fieldnames=fields)
        writer.writeheader()
        try:
            person.wait(random.uniform(5, 20))
            while time.time() - start_time < args.duration:
                visit_idx += 1
                persona = person.choose_persona()
                acct_name = person.account["email"].split("@")[0] if person.account else "비회원"
                now = datetime.datetime.now().strftime("%H:%M:%S")
                print(f"[{now}] [+] 방문 #{visit_idx:03d} 입장 ({device}, {persona}, {acct_name})")

                summary = person.visit(persona)
                acct_name = person.account["email"].split("@")[0] if person.account else "비회원"
                writer.writerow({"member": args.member, "local_ip": local_ip, "visit_idx": visit_idx,
                                 "account": acct_name, "device": device, "label": 0, **summary})
                mf.flush()

                now = datetime.datetime.now().strftime("%H:%M:%S")
                elapsed = int(time.time() - start_time)
                print(f"[{now}] [-] 방문 #{visit_idx:03d} 이탈 - 요청 {summary['requests']}건 "
                      f"{summary['status_counts']} (경과 {elapsed}s / {args.duration}s)")
                if summary["error"]:
                    abort_reason = summary["error"]
                    print(f"\n[중단] 서버 이상 감지: {abort_reason}")
                    print(f"       이 방문(#{visit_idx}) 이후 데이터는 학습에서 제외하세요. 웹서버/DB 확인 후 다시 실행하세요.")
                    break

                remaining = args.duration - (time.time() - start_time)
                if remaining <= args.away_min:
                    break
                away = min(random.uniform(args.away_min, args.away_max), remaining)
                print(f"           ... {away:.0f}초 동안 사이트 이탈 후 재방문")
                person.wait(away)
        except KeyboardInterrupt:
            print("\n[알림] 사용자에 의해 중단되었습니다.")
    return visit_idx, abort_reason


# -------------------------------------------------------------
# (레거시) 한 PC 에서 여러 명 동시 접속 모드 - IP 기준 학습에는 비권장
# -------------------------------------------------------------
def get_dynamic_target(elapsed_sec, period_sec, min_users, max_users):
    progress = (elapsed_sec % period_sec) / period_sec
    mid = (min_users + max_users) / 2.0
    amplitude = (max_users - min_users) / 2.0
    target = int(round(mid + amplitude * math.sin(progress * 2 * math.pi) + random.uniform(-1.0, 1.0)))
    return max(min_users, min(max_users, target))


def run_multi_customers(args):
    stop_event = threading.Event()
    threads, counter, start_time = [], 0, time.time()

    def worker(p):
        try:
            p.visit(p.choose_persona())
        except KeyboardInterrupt:
            pass

    try:
        while time.time() - start_time < args.duration:
            threads = [t for t in threads if t.is_alive()]
            target = get_dynamic_target(time.time() - start_time, 90.0, args.min_users, args.max_users)
            for _ in range(min(max(0, target - len(threads)), random.randint(1, 3))):
                counter += 1
                acct = random.choice(USER_ACCOUNTS_18) if random.random() < 0.6 else None
                p = Person(args.target, random.choice(list(DEVICES)), acct, stop_event,
                           allow_writes=not args.no_writes, member=args.member)
                t = threading.Thread(target=worker, args=(p,), daemon=True)
                t.start()
                threads.append(t)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[알림] 사용자에 의해 중단되었습니다.")
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=1.5)
    return counter, ""


def main():
    curr = pathlib.Path(__file__).resolve().parent
    base_dir = curr.parent.parent if curr.parent.name == "src" else curr.parent

    parser = argparse.ArgumentParser(description="B-Profile Benign Traffic Generator (1 PC = 1 customer)")
    parser.add_argument("--target", default="http://192.168.0.141:8000", help="대상 쇼핑몰 URL")
    parser.add_argument("--member", type=int, default=0,
                        help="팀원 번호(1~6). 계정 user{번호}@example.com 을 사용하고 manifest 에 기록")
    parser.add_argument("--account-email", default=None, help="계정 직접 지정 (기본: --member 번호 계정)")
    parser.add_argument("--start-as-guest", action="store_true",
                        help="비회원으로 시작 (방문 중 일정 확률로 회원가입 후 그 계정 사용)")
    parser.add_argument("--no-writes", action="store_true", help="주문/회원가입 안 함 (DB 에 쓰기 없음)")
    parser.add_argument("--device", default="auto", choices=["auto"] + list(DEVICES),
                        help="사용 기기 (기본 auto: 실행 시 1개를 무작위로 골라 끝까지 유지)")
    parser.add_argument("--duration", type=int, default=1800, help="총 실행 시간(초), 기본 1800 (30분)")
    parser.add_argument("--away-min", type=float, default=15.0, help="방문 사이 이탈 시간 최소(초)")
    parser.add_argument("--away-max", type=float, default=90.0, help="방문 사이 이탈 시간 최대(초)")
    parser.add_argument("--min-users", type=int, default=1, help="(레거시) 동시 접속자 최소")
    parser.add_argument("--max-users", type=int, default=1, help="(레거시) 동시 접속자 최대. 2 이상이면 다중 접속 모드")
    parser.add_argument("--seed", type=int, default=None, help="난수 시드 (재현용)")
    parser.add_argument("--manifest-dir", default=str(base_dir / "data" / "manifests"),
                        help="방문 기록 CSV 저장 폴더")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
    if not (1 <= args.member <= 6):
        print(f"[주의] --member {args.member}: 팀원 번호는 1~6 을 권장합니다 (계정이 서로 겹치지 않도록).")

    if args.start_as_guest:
        account = None
    elif args.account_email:
        account = {"email": args.account_email, "password": "Test1234!"}
    elif 1 <= args.member <= len(USER_ACCOUNTS_18):
        account = USER_ACCOUNTS_18[args.member - 1]
    else:
        account = random.choice(USER_ACCOUNTS_18)
    device = random.choice(list(DEVICES)) if args.device == "auto" else args.device
    local_ip = detect_local_ip(args.target)

    multi = args.max_users > 1
    print("=" * 72)
    print(" [B-Profile v3] 정상 사용자 트래픽 생성기" + (" - (레거시) 다중 접속 모드" if multi else " - 1 PC = 1 고객"))
    print("=" * 72)
    print(f" * 대상 서버 URL     : {args.target}")
    print(f" * 팀원 번호         : {args.member or '-'}   로컬 IP: {local_ip}")
    print(f" * 총 실행 시간      : {args.duration}초 ({args.duration // 60}분 {args.duration % 60}초)")
    print(f" * 시작 시각 (UTC)   : {utc_now_str()}   <- Wazuh 로그와 대조할 때 사용")
    if multi:
        print(f" * 동시 접속자 범위  : {args.min_users}~{args.max_users}명")
        print(" * [주의] IP 하나에 여러 사람이 섞입니다. IP 기준 피처 학습에는 권장하지 않습니다.")
    else:
        print(f" * 고객 프로필       : 기기={device}, 계정={account['email'] if account else '비회원(도중 가입 가능)'}")
        print(f" * 방문 간 이탈 시간 : {args.away_min:.0f}~{args.away_max:.0f}초")
        print(f" * 주문/회원가입     : {'안 함 (--no-writes)' if args.no_writes else '함 (낮은 확률)'}")
        print(" * 체류 시간         : 실측 분포 (중앙값 약 6초, 최대 90초) + 폼 입력 시간")
    print("=" * 72)

    start = time.time()
    manifest_path = None
    if multi:
        visits, abort_reason = run_multi_customers(args)
    else:
        mdir = pathlib.Path(args.manifest_dir)
        mdir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        manifest_path = mdir / f"benign_member{args.member or 0}_{local_ip.replace('.', '-')}_{stamp}.csv"
        visits, abort_reason = run_single_customer(args, account, device, manifest_path, local_ip)

    total_time = round(time.time() - start, 1)
    print("\n" + "=" * 72)
    print(" [완료] 정상 사용자 트래픽 생성 요약" + (f"  ※ 중단됨: {abort_reason}" if abort_reason else ""))
    print("=" * 72)
    print(f" * 총 소요 시간      : {total_time}초 ({round(total_time / 60, 1)}분)")
    print(f" * 종료 시각 (UTC)   : {utc_now_str()}")
    print(f" * 총 방문 수        : {visits}회")
    for p_name, p_cnt in persona_counts.items():
        if p_cnt:
            print(f"   - {p_name:6s}: {p_cnt}회 ({round(p_cnt / max(1, visits) * 100, 1)}%)")
    print(f" * 총 HTTP 요청 수   : {total_requests}건 (평균 {round(total_requests / max(1, total_time), 3)} req/sec)")
    print(" * HTTP 응답 상태코드:")
    for code, count in sorted(status_counts.items()):
        print(f"   - {code}: {count}건 ({round(count / max(1, total_requests) * 100, 1)}%)")
    bad = sum(c for s, c in status_counts.items() if s == 0 or s >= 500)
    if total_requests and bad / total_requests > 0.05:
        print(f" [경고] 5xx/접속실패가 {bad}건입니다. 이 실행 데이터는 학습에 쓰기 전에 확인하세요.")
    if manifest_path:
        print(f" * 방문 기록 저장    : {manifest_path}")
    print("=" * 72)


if __name__ == "__main__":
    main()
