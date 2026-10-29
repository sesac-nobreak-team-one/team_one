#!/usr/bin/env python3
r"""
B-Profile 기반 정상 사용자 트래픽 생성기 (CICIDS2017 방법론 기반)
------------------------------------------------------------------
논문: Sharafaldin et al., "Toward Generating a New Intrusion Detection Dataset" (2018)

[1 PC = 1 고객]
  팀원 6명이 각자 PC 에서 실행하고, 각 PC(=IP 1개)는 '한 명의 고객'으로
      방문(쇼핑) -> 사이트 이탈(휴식) -> 재방문 -> ...
  을 반복합니다. 한 사람 = 하나의 기기(User-Agent) + 하나의 계정 + 하나의 브라우저(쿠키/JWT/캐시 유지)

[v3 보정] 실제 사람 체류 시간 분포(중앙값 ~6초, 긴 꼬리), 정적 파일 + Referer, 서버 상태 점검/자동 중단

[v4] 웹 개편(app.js?v=20261029-b2)에 맞춰 실제 프론트엔드 호출 흐름을 그대로 재현
  공통   로그인 상태면 모든 페이지(장바구니 제외)에서 GET /api/v2/cart (상단 장바구니 배지)
         정적 파일은 HTML 의 <link>/<script> 에서 버전 붙은 주소를 읽어서 요청 (/assets/app.js?v=...)
  목록   products.php -> GET /api/v2/products?limit=20&offset=0[&category=]
         검색/정렬    -> GET /api/v2/products/search?limit=..&offset=..[&category=][&q=][&sort=]
         표시 개수 20/40/100, 카테고리 칩, 다음 페이지
  상세   product.php?id=N -> GET /api/v2/products/N
         장바구니 담기 POST /api/v2/cart {product_id, quantity} / 바로 구매 POST /api/v2/orders
  장바구니 cart.php -> GET /api/v2/cart, 수량 PATCH /api/v2/cart/{pid}, 삭제 DELETE /api/v2/cart/{pid}
         결제 POST /api/v2/orders -> DELETE /api/v2/cart -> GET /api/v2/cart, 비우기 DELETE /api/v2/cart
  주문   orders.php -> GET /api/v2/orders/me?limit=10&offset=0[&status=결제완료|배송중|배송완료|취소]
         order.php?id=N -> GET /api/v2/orders/N, 취소(결제완료만) POST /api/v2/orders/N/cancel
  내정보 me.php -> GET /api/v2/users/me, 수정 PATCH /api/v2/users/me (바뀐 항목만)
  기타   로그인/회원가입/로그아웃
  상품/주문 ID 는 실제 API 응답에서 골라 클릭합니다 (목록에 보이는 상품, 내 주문 번호).

  --no-writes : 주문/주문취소/회원가입/내정보 수정을 하지 않음 (장바구니는 임시 데이터라 허용)

[2026-10-29 v5] shop-web-v2-full 소스(app.js 의 모든 이벤트 핸들러) 기준으로 화면에서 가능한 행동 전부 반영
  목록   이전/다음 페이지, 검색어 X(Esc) 지우기, '검색 해제하고 전체 보기', 정렬만 바꿔 검색, 분류 '전체'
  상세   품절/비로그인이면 주문 버튼 없음, 수량 -/+, 담은 뒤 '장바구니 보기', 주문 뒤 '주문 상세 보기' 링크
  장바구니 수량 -/+ 는 누를 때마다 PATCH 1번(연속 클릭), 실제 수량으로 결제, 10종류 초과/품절 시 빼고 주문,
         상품 이름 클릭, '쇼핑 계속하기'
  주문   상태 탭('전체' 포함), 이전/다음, 주문 상세의 상품 이름 클릭(재구매)
  내정보 수정 화면 열었다 취소, 이름/전화/주소 수정, 옆 메뉴(주문 내역/장바구니)
  계정   비밀번호 오타 후 재시도(401), 토큰 만료 시 login.php?expired=1, 가입 화면만 보고 이탈
  화면에 없는 API 기능(min_price/max_price 가격 필터, /docs/ API 문서)은 일반 사용자가 쓸 수 없으므로 제외

[2026-10-29 v5.1 점검 수정]
  - 장바구니 담기/주문 성공 응답이 201 인데 200 만 성공으로 봐서, 주문 뒤 장바구니 비우기(DELETE /api/v2/cart)와
    상품 다시 조회가 빠지고 장바구니가 계속 쌓이던 문제 수정
  - 내 정보 수정: app.js 처럼 실제로 바뀐 항목만 PATCH (같은 값이면 요청 없이 끝)
  - 시작 점검: 쇼핑몰이 개편 버전(app.js?v=..., 검색창)이 아니면 시작하지 않음
    실행 중 화면 API 가 404 를 계속 받으면(서버에 그 기능이 없음) 자동 중단
  - Ctrl+C 로 멈춰도 진행 중이던 방문까지 manifest 에 기록

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
import re
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
# 사이트 정보 (2026-10-29 개편된 쇼핑몰 app.js 확인 결과)
# -------------------------------------------------------------
PRODUCT_IDS = list(range(1, 73))
CATEGORIES = ["의류", "전자기기", "생활용품", "식품", "도서"]
LIST_LIMITS = [20, 40, 100]                      # 표시 개수 선택지 (기본 20)
SORTS = ["newest", "price_asc", "price_desc", "name"]
ORDER_PAGE_SIZE = 10
ORDER_TABS = ["결제완료", "배송중", "배송완료", "취소"]
LOGIN_REQUIRED_PAGES = {"/cart.php", "/orders.php", "/order.php", "/me.php"}
FALLBACK_ASSETS = ["/assets/style.css", "/assets/app.js"]
ASSET_RE = re.compile(r'(?:href|src)="(/assets/[^"]+\.(?:css|js)(?:\?[^"]*)?)"')
TYPO_PATHS = ["/product_old.php", "/item/999", "/cart.html", "/help.php", "/event.php"]

# 사람이 실제로 칠 법한 검색어 (상품명 일부 + 결과 없는 검색 일부)
SEARCH_WORDS = ["후드티", "청바지", "셔츠", "니트", "패딩", "슬랙스", "이어폰", "무선 이어폰", "보조배터리",
                "키보드", "마우스", "스마트워치", "텀블러", "수건", "무드등", "청소기", "가습기", "견과류",
                "원두", "곶감", "즉석밥", "파이썬", "보안", "네트워크", "소설", "프리미엄", "한정판"]
SEARCH_NO_RESULT = ["노트북", "운동화", "에어팟", "커피머신", "모니터"]

DEVICES = {
    "win-chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "iphone": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "galaxy": "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "win-edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "mac-safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
}

USER_ACCOUNTS_18 = [{"email": f"user{i}@example.com", "password": "Test1234!"} for i in range(1, 19)]
KOREAN_NAMES = ["김민준", "이서연", "박지훈", "최수빈", "정하은", "강도윤", "조예린", "윤시우", "장유나", "임준서"]
ADDRESSES = ["서울시 금천구 가산디지털1로 10", "서울시 관악구 남부순환로 1800", "경기도 광명시 오리로 20",
             "서울시 구로구 디지털로 300", "인천시 부평구 부평대로 50"]

# 방문 의도(페르소나) 가중치 - 회원 기준. 비회원은 choose_persona() 참고
PERSONAS = ["단순구경", "검색", "꼼꼼탐색", "장바구니구매", "바로구매", "주문확인", "내정보수정", "신규가입"]
PERSONA_WEIGHTS = {"단순구경": 0.28, "검색": 0.15, "꼼꼼탐색": 0.18, "장바구니구매": 0.13,
                   "바로구매": 0.05, "주문확인": 0.17, "내정보수정": 0.04, "신규가입": 0.0}
WRITE_PERSONAS = {"바로구매", "내정보수정"}       # --no-writes 일 때 다른 행동으로 대체
GUEST_SIGNUP_PROB = 0.15  # 비회원 상태인 사람이 방문 시 가입할 확률
LOGOUT_PROB = 0.08        # 방문 끝에 로그아웃할 확률
LOGIN_TYPO_PROB = 0.05    # 로그인할 때 비밀번호를 한 번 틀릴 확률
MAX_ORDER_ITEMS = 10      # 한 번에 주문 가능한 상품 종류 (화면에서 먼저 막음)

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
    """폼 입력/조작 시간"""
    if kind == "login":
        return max(4.0, min(random.lognormvariate(math.log(9.0), 0.4), 30.0))
    if kind == "signup":
        return max(15.0, min(random.lognormvariate(math.log(35.0), 0.35), 90.0))
    if kind == "search":
        return max(1.5, min(random.lognormvariate(math.log(3.5), 0.4), 12.0))
    if kind == "profile":
        return max(8.0, min(random.lognormvariate(math.log(20.0), 0.4), 60.0))
    return max(1.0, min(random.lognormvariate(math.log(3.0), 0.5), 15.0))  # 수량 선택, 확인 창 등


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


def _json(payload):
    try:
        return json.loads(payload.decode("utf-8"))
    except Exception:
        return None


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
        self.asset_urls = list(FALLBACK_ASSETS)
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar))
        self.recent = collections.deque(maxlen=HEALTH_WINDOW)
        self.recent_api = collections.deque(maxlen=HEALTH_WINDOW)
        self.last_html = ""
        self.visit_requests = 0
        self.visit_status = {}
        # 화면 상태 (실제 API 응답으로 갱신)
        self.list_state = {"limit": 20, "offset": 0, "category": "", "q": "", "sort": "default"}
        self.listed_ids = []              # 목록/검색 화면에 보이는 상품 id
        self.product_info = None          # 보고 있는 상품 (재고 확인용)
        self.cart = []                    # 장바구니 항목 [{product_id, quantity, stock, ...}]
        self.orders_state = {"limit": ORDER_PAGE_SIZE, "offset": 0, "status": ""}
        self.my_orders = []               # 내 주문 목록 응답
        self.order_detail = None          # 보고 있는 주문 상세
        self.me = None                    # 내 정보 (GET /api/v2/users/me 응답)

    # ---------------------------------------------------------
    # 시간 흐름
    # ---------------------------------------------------------
    def wait(self, sec):
        if self.stop_event.wait(sec):
            raise KeyboardInterrupt

    def dwell(self):
        self.wait(dwell_seconds())

    def page_path(self):
        return urllib.parse.urlparse(self.current_page or "").path

    # ---------------------------------------------------------
    # HTTP (브라우저 동작 흉내)
    # ---------------------------------------------------------
    def _send(self, method, path, kind, data=None, referer=None):
        headers = {"User-Agent": self.user_agent, "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7"}
        if kind == "page":
            headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        elif kind == "asset":
            headers["Accept"] = "text/css,*/*;q=0.1" if ".css" in path else "*/*"
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
        if kind == "api":
            # 화면이 부르는 API 가 404 면 서버에 그 기능이 없는 것 = 쇼핑몰 버전이 생성기와 다름
            self.recent_api.append(status)
            n404 = sum(1 for s in self.recent_api if s == 404)
            if len(self.recent_api) >= HEALTH_MIN_SAMPLES and n404 / len(self.recent_api) >= HEALTH_MAX_ERROR_RATIO:
                raise ServerUnhealthy(f"최근 API 요청 {len(self.recent_api)}건 중 {n404}건이 404 "
                                      "(쇼핑몰이 생성기와 다른 버전일 수 있음)")

    def api(self, method, path, data=None, delay=True):
        """
        app.js 의 fetch() 호출.
        로그인한 상태에서 401 이 오면 handleAuthError() 처럼 토큰을 지우고 login.php?expired=1 로 이동
        """
        if delay:
            self.wait(random.uniform(0.05, 0.3))  # 화면 조작/스크립트 실행 후 요청까지
        had_token = bool(self.jwt_token)
        status, payload, _ = self._send(method, path, "api", data=data, referer=self.current_page)
        if status == 401 and had_token and path != "/api/v2/login":
            self.jwt_token = None
            self.open_page("/login.php?expired=1")
        return status, _json(payload)

    # ---------------------------------------------------------
    # 페이지 이동 (HTML -> css/js -> 장바구니 배지 -> 페이지별 API)
    # ---------------------------------------------------------
    def open_page(self, path, from_link=True):
        referer = self.current_page if from_link else None
        status, payload, final_url = self._send("GET", path, "page", referer=referer)
        self.current_page = final_url
        if status != 200:
            return status
        self.last_html = payload.decode("utf-8", "replace")
        if not self.assets_cached:
            found = ASSET_RE.findall(payload.decode("utf-8", "replace"))
            if found:
                self.asset_urls = list(dict.fromkeys(found))
            for a in self.asset_urls:
                self._send("GET", a, "asset", referer=self.current_page)
            self.assets_cached = True

        final_path = self.page_path()
        q = urllib.parse.parse_qs(urllib.parse.urlparse(final_url).query)

        # requireLogin(): 로그인 안 돼 있으면 login.php 로 이동
        if final_path in LOGIN_REQUIRED_PAGES and not self.jwt_token:
            self.wait(random.uniform(0.05, 0.2))
            return self.open_page("/login.php")

        # renderNav(): 로그인 상태 + 장바구니 페이지가 아니면 배지용 장바구니 조회
        if self.jwt_token and final_path != "/cart.php":
            self.api("GET", "/api/v2/cart")

        if final_path == "/products.php":
            self.list_state = {"limit": 20, "offset": 0, "category": "", "q": "", "sort": "default"}
            self.load_list(delay=False)
        elif final_path == "/product.php" and "id" in q:
            self.load_product(q["id"][0], delay=False)
        elif final_path == "/cart.php":
            self.load_cart(delay=False)
        elif final_path == "/orders.php":
            self.orders_state = {"limit": ORDER_PAGE_SIZE, "offset": 0, "status": ""}
            self.load_orders(delay=False)
        elif final_path == "/order.php" and "id" in q:
            self.load_order(q["id"][0], delay=False)
        elif final_path == "/me.php":
            st, data = self.api("GET", "/api/v2/users/me", delay=False)
            self.me = data if st == 200 and isinstance(data, dict) else None
        return status

    def nav(self, path):
        """상단 메뉴/링크 클릭"""
        self.dwell()
        self.open_page(path)

    # ---------------------------------------------------------
    # 상품 목록 화면 (검색창 / 정렬 / 분류 칩 / 표시 개수 / 이전·다음)
    # ---------------------------------------------------------
    def load_list(self, delay=True):
        s = self.list_state
        params = [("limit", s["limit"]), ("offset", s["offset"])]
        if s["category"]:
            params.append(("category", s["category"]))
        searching = s["q"] != "" or s["sort"] != "default"
        if s["q"]:
            params.append(("q", s["q"]))
        if s["sort"] != "default":
            params.append(("sort", s["sort"]))
        base = "/api/v2/products/search?" if searching else "/api/v2/products?"
        status, data = self.api("GET", base + urllib.parse.urlencode(params), delay=delay)
        if status == 200 and isinstance(data, list):
            self.listed_ids = [p.get("id") for p in data if isinstance(p, dict) and p.get("id")]

    def ensure_list_page(self):
        if self.page_path() != "/products.php":
            self.nav("/products.php")

    def click_category(self):
        """분류 칩 (검색어는 그대로 두고 분류만 바꿈, '전체' 포함)"""
        self.list_state.update(category=random.choice([""] + CATEGORIES), offset=0)
        self.load_list()

    def click_next_page(self):
        if len(self.listed_ids) >= self.list_state["limit"]:
            self.list_state["offset"] += self.list_state["limit"]
            self.load_list()
            return True
        return False

    def click_prev_page(self):
        if self.list_state["offset"] > 0:
            self.list_state["offset"] = max(0, self.list_state["offset"] - self.list_state["limit"])
            self.load_list()

    def change_limit(self):
        self.list_state.update(limit=random.choice([l for l in LIST_LIMITS if l != self.list_state["limit"]]), offset=0)
        self.load_list()

    def search(self):
        """검색창 입력 + 정렬 선택 후 [검색] (검색어 없이 정렬만 바꿔 검색하기도 함)"""
        self.wait(typing_seconds("search"))
        r = random.random()
        if r < 0.1:
            word = random.choice(SEARCH_NO_RESULT)
        elif r < 0.9:
            word = random.choice(SEARCH_WORDS)
        else:
            word = ""                                   # 정렬만 바꿔서 검색
        sort = random.choice(SORTS) if (random.random() < 0.35 or word == "") else "default"
        self.list_state.update(q=word, sort=sort, offset=0)
        self.load_list()

    def change_sort(self):
        self.list_state.update(sort=random.choice(SORTS), offset=0)
        self.load_list()

    def clear_keyword(self):
        """검색창 X 버튼 / Esc: 검색어만 지움 (정렬·분류 유지)"""
        if self.list_state.get("q"):
            self.list_state.update(q="", offset=0)
            self.load_list()

    def reset_search(self):
        """'검색 해제하고 전체 보기': 검색어 + 정렬 초기화"""
        if self.list_state.get("q") or self.list_state.get("sort") != "default":
            self.list_state.update(q="", sort="default", offset=0)
            self.load_list()

    def pick_listed(self):
        return random.choice(self.listed_ids) if self.listed_ids else random.choice(PRODUCT_IDS)

    def browse_list(self, max_details):
        """목록에서 분류/정렬/표시개수/페이지를 만지고 상품 몇 개를 열어 봄"""
        self.ensure_list_page()
        r = random.random()
        if r < 0.28:
            self.dwell(); self.click_category()
        elif r < 0.43:
            self.dwell()
            if self.click_next_page() and random.random() < 0.3:
                self.dwell(); self.click_prev_page()
        elif r < 0.52:
            self.dwell(); self.change_sort()
        elif r < 0.60:
            self.dwell(); self.change_limit()
        for _ in range(random.randint(0, max_details)):
            self.view_product()
            if random.random() < 0.4:      # 목록으로 돌아감 (상단 '상품' 메뉴 / 로고)
                self.nav("/products.php")

    # ---------------------------------------------------------
    # 상품 상세 화면 (수량 -/+ 는 화면 안에서만, 장바구니 담기 / 바로 주문)
    # ---------------------------------------------------------
    def load_product(self, pid, delay=True):
        status, data = self.api("GET", f"/api/v2/products/{pid}", delay=delay)
        self.product_info = data if status == 200 and isinstance(data, dict) else None

    def view_product(self, pid=None):
        pid = pid or self.pick_listed()
        self.nav(f"/product.php?id={pid}")
        return pid

    def in_stock(self):
        p = self.product_info or {}
        try:
            return int(p.get("stock", 1)) >= 1
        except (TypeError, ValueError):
            return True

    def choose_qty(self):
        """수량 -/+ 조작 (요청 없음, 시간만 걸림)"""
        qty = random.choices([1, 2, 3], weights=[0.75, 0.2, 0.05])[0]
        if qty > 1:
            self.wait(random.uniform(0.5, 2.0))
        return qty

    def add_to_cart(self, pid):
        if not self.jwt_token or not self.in_stock():
            return
        self.wait(typing_seconds("other"))
        status, data = self.api("POST", "/api/v2/cart", data={"product_id": int(pid), "quantity": self.choose_qty()})
        if 200 <= status < 300 and isinstance(data, dict):   # 담기 성공은 201
            self.cart = [it for it in data.get("items", []) if isinstance(it, dict)]
            if random.random() < 0.25:                       # '장바구니 보기' 링크
                self.nav("/cart.php")

    def buy_now(self, pid):
        if not (self.allow_writes and self.jwt_token and self.in_stock()):
            return
        self.wait(typing_seconds("other"))
        status, data = self.api("POST", "/api/v2/orders",
                                data={"items": [{"product_id": int(pid), "quantity": self.choose_qty()}]})
        if 200 <= status < 300:                              # 주문 성공은 201
            self.load_product(pid, delay=False)              # 재고 갱신을 위해 상품 다시 조회
            if isinstance(data, dict) and data.get("order_id") and random.random() < 0.5:
                self.nav(f"/order.php?id={data['order_id']}")  # '주문 상세 보기' 링크

    # ---------------------------------------------------------
    # 장바구니 화면
    # ---------------------------------------------------------
    def load_cart(self, delay=True):
        status, data = self.api("GET", "/api/v2/cart", delay=delay)
        if status == 200 and isinstance(data, dict):
            self.cart = [it for it in data.get("items", []) if isinstance(it, dict)]

    def _set_cart(self, status, data):
        if status == 200 and isinstance(data, dict):
            self.cart = [it for it in data.get("items", []) if isinstance(it, dict)]

    def cart_stepper(self):
        """수량 -/+ 버튼: 누를 때마다 PATCH 한 번 (1~3번 연속으로 누름)"""
        if not self.cart:
            return
        it = random.choice(self.cart)
        pid, qty = it.get("product_id"), int(it.get("quantity", 1) or 1)
        stock = int(it.get("stock", 99) or 99)
        step = random.choice([1, -1]) if qty > 1 else 1
        self.wait(random.uniform(1.0, 3.0))
        for _ in range(random.choices([1, 2, 3], weights=[0.6, 0.3, 0.1])[0]):
            new_q = max(1, min(99, stock, qty + step))
            if new_q == qty:
                break
            status, data = self.api("PATCH", f"/api/v2/cart/{pid}", data={"quantity": new_q})
            self._set_cart(status, data)
            qty = new_q
            self.wait(random.uniform(0.4, 1.2))

    def cart_remove(self):
        if not self.cart:
            return
        pid = random.choice(self.cart).get("product_id")
        self.wait(typing_seconds("other"))
        self._set_cart(*self.api("DELETE", f"/api/v2/cart/{pid}"))

    def cart_checkout(self):
        """'전체 주문하기': 주문 생성 -> 장바구니 비우기 -> 장바구니 다시 조회 (app.js 와 동일)"""
        if not (self.allow_writes and self.cart):
            return
        while len(self.cart) > MAX_ORDER_ITEMS:            # 화면에서 막힘 -> 몇 개 빼고 다시
            self.cart_remove()
        bad = [it for it in self.cart if int(it.get("stock", 1) or 0) < int(it.get("quantity", 1) or 1)]
        for it in bad:                                     # 품절/재고 부족 안내 -> 빼고 주문
            self.wait(typing_seconds("other"))
            self._set_cart(*self.api("DELETE", f"/api/v2/cart/{it.get('product_id')}"))
        if not self.cart:
            return
        self.wait(typing_seconds("other"))
        items = [{"product_id": int(it["product_id"]), "quantity": int(it.get("quantity", 1))} for it in self.cart]
        status, data = self.api("POST", "/api/v2/orders", data={"items": items})
        if 200 <= status < 300:                              # 주문 성공은 201 -> 장바구니 비우기
            self.api("DELETE", "/api/v2/cart", delay=False)
            self.load_cart(delay=False)
            if isinstance(data, dict) and data.get("order_id") and random.random() < 0.5:
                self.nav(f"/order.php?id={data['order_id']}")

    def cart_clear(self):
        """'전체 비우기' (확인 창)"""
        if not self.cart:
            return
        self.wait(typing_seconds("other"))
        self.api("DELETE", "/api/v2/cart")
        self.load_cart(delay=False)

    # ---------------------------------------------------------
    # 주문 화면 (상태 탭 / 이전·다음 / 주문 상세 / 취소)
    # ---------------------------------------------------------
    def load_orders(self, delay=True):
        s = self.orders_state
        params = [("limit", s["limit"]), ("offset", s["offset"])]
        if s["status"]:
            params.append(("status", s["status"]))
        status, data = self.api("GET", "/api/v2/orders/me?" + urllib.parse.urlencode(params), delay=delay)
        if status == 200 and isinstance(data, list):
            self.my_orders = [o for o in data if isinstance(o, dict) and o.get("id")]

    def click_order_tab(self):
        self.orders_state.update(status=random.choice([""] + ORDER_TABS), offset=0)
        self.load_orders()

    def orders_next_page(self):
        if len(self.my_orders) >= self.orders_state["limit"]:
            self.orders_state["offset"] += self.orders_state["limit"]
            self.load_orders()
            if random.random() < 0.3:
                self.dwell()
                self.orders_state["offset"] = max(0, self.orders_state["offset"] - self.orders_state["limit"])
                self.load_orders()

    def load_order(self, oid, delay=True):
        status, data = self.api("GET", f"/api/v2/orders/{oid}", delay=delay)
        self.order_detail = data if status == 200 and isinstance(data, dict) else None

    def cancel_order(self):
        """주문 상세에서 '주문 취소' (결제완료 상태만, 확인 창 후)"""
        o = self.order_detail
        if not (self.allow_writes and o and o.get("status") == "결제완료"):
            return
        self.wait(typing_seconds("other"))
        status, _ = self.api("POST", f"/api/v2/orders/{o.get('id')}/cancel")
        if status == 200:
            self.load_order(o.get("id"), delay=False)

    def order_item_product(self):
        """주문 상세의 상품 이름 클릭 -> 상품 상세 (재구매)"""
        items = (self.order_detail or {}).get("items") or []
        pids = [it.get("product_id") for it in items if isinstance(it, dict) and it.get("product_id")]
        if pids:
            return self.view_product(random.choice(pids))
        return None

    # ---------------------------------------------------------
    # 계정
    # ---------------------------------------------------------
    def login(self):
        """login.php 에서 아이디/비밀번호 입력 후 로그인 -> products.php 로 이동 (가끔 비밀번호 오타)"""
        if self.jwt_token or not self.account:
            return bool(self.jwt_token)
        if self.page_path() != "/login.php":
            self.nav("/login.php")
        if random.random() < LOGIN_TYPO_PROB:
            self.wait(typing_seconds("login"))
            wrong = dict(self.account, password=self.account["password"][:-1])
            self.api("POST", "/api/v2/login", data=wrong)     # 401: 이메일 또는 비밀번호 오류
            self.wait(random.uniform(2.0, 6.0))
        self.wait(typing_seconds("login"))
        status, data = self.api("POST", "/api/v2/login", data=self.account)
        if status == 200 and isinstance(data, dict):
            self.jwt_token = data.get("access_token")
        if self.jwt_token:
            self.wait(random.uniform(0.05, 0.2))
            self.open_page("/products.php")                  # go('/products.php')
        return bool(self.jwt_token)

    def logout(self):
        if self.jwt_token:
            self.wait(random.uniform(0.5, 2.0))
            self.jwt_token = None                             # clearToken() -> go('/login.php')
            self.open_page("/login.php")

    def signup(self):
        """비회원 -> 회원가입 -> 로그인 (가입한 계정이 이 사람의 계정이 됨)"""
        if not self.allow_writes or self.account:
            return
        self.nav("/signup.php")
        self.wait(typing_seconds("signup"))
        email = f"m{self.member}_{int(time.time())}_{random.randint(100, 999)}@example.com"
        body = {"name": random.choice(KOREAN_NAMES), "email": email, "password": "Test1234!"}
        if random.random() < 0.5:
            body["phone"] = f"010-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}"
        if random.random() < 0.4:
            body["address"] = random.choice(ADDRESSES)
        status, _ = self.api("POST", "/api/v2/signup", data=body)
        if status in (200, 201):
            self.account = {"email": email, "password": "Test1234!"}
            self.wait(random.uniform(0.05, 0.2))
            self.open_page("/login.php?joined=1")            # go('/login.php?joined=1')
            self.login()

    def edit_profile(self):
        """내 정보 -> [정보 수정] -> (취소하거나) 바뀐 항목만 PATCH -> 보기 화면"""
        if not (self.allow_writes and self.jwt_token):
            return
        self.wait(random.uniform(1.0, 3.0))                  # [정보 수정] 클릭 (요청 없음)
        if random.random() < 0.15:                           # 보다가 [취소]
            self.wait(random.uniform(2.0, 8.0))
            return
        self.wait(typing_seconds("profile"))
        phone = f"010-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}"
        body = random.choice([
            {"address": random.choice(ADDRESSES)},
            {"phone": phone},
            {"address": random.choice(ADDRESSES), "phone": phone},
            {"name": random.choice(KOREAN_NAMES)},
        ])
        # app.js 처럼 '바뀐 항목만' 보냄. 바뀐 게 없으면 '변경된 내용이 없습니다' -> 요청 없이 끝
        me = self.me or {}
        body = {k: v for k, v in body.items() if (me.get(k) or "") != v}
        if not body:
            self.wait(random.uniform(1.0, 3.0))
            return
        st, data = self.api("PATCH", "/api/v2/users/me", data=body)
        if st == 200 and isinstance(data, dict):
            self.me = data

    def maybe_typo(self, prob):
        if random.random() < prob:
            self._send("GET", random.choice(TYPO_PATHS), "page", referer=None)
            self.wait(random.uniform(1.0, 3.0))

    # ---------------------------------------------------------
    # 방문 시나리오
    # ---------------------------------------------------------
    def enter_site(self):
        """사이트 진입: 메인 주소 / 북마크한 목록 / 공유받은 상품 링크 / 북마크한 내 주문"""
        r = random.random()
        if r < 0.45:
            self.open_page("/index.php", from_link=False)   # -> products.php 로 리다이렉트
        elif r < 0.80:
            self.open_page("/products.php", from_link=False)
        elif r < 0.93:
            self.open_page(f"/product.php?id={random.choice(PRODUCT_IDS)}", from_link=False)
        else:
            self.open_page("/orders.php", from_link=False)  # 로그아웃 상태면 login.php 로 이동

    def scenario_casual(self):
        """단순구경: 목록 보고 상품 0~2개 보고 나감"""
        self.enter_site()
        self.browse_list(max_details=2)
        self.dwell()
        self.maybe_typo(0.02)

    def scenario_search(self):
        """검색: 검색 -> (정렬 변경 / 분류 칩 / X 로 검색어 지우기 / 재검색 / 검색 해제) -> 상품 확인"""
        self.enter_site()
        self.ensure_list_page()
        self.dwell(); self.search()
        r = random.random()
        if r < 0.25:
            self.dwell(); self.change_sort()
        elif r < 0.45:
            self.dwell(); self.click_category()
        if random.random() < 0.3:
            self.dwell()
            if random.random() < 0.5:
                self.clear_keyword()
            self.search()
        if not self.listed_ids or random.random() < 0.15:
            self.dwell(); self.reset_search()               # 결과 없음 -> '검색 해제하고 전체 보기'
        for _ in range(random.randint(1, 2)):
            self.view_product()
        if self.jwt_token and random.random() < 0.25:
            self.add_to_cart(self.current_pid())
        self.dwell()

    def scenario_explore(self):
        """꼼꼼탐색: 여러 번 목록 탐색 + 비교, 로그인 상태면 가끔 장바구니 담기"""
        self.enter_site()
        for _ in range(random.randint(1, 3)):
            self.browse_list(max_details=3)
        if self.jwt_token and self.page_path() == "/product.php" and random.random() < 0.35:
            self.add_to_cart(self.current_pid())
        self.dwell()
        self.maybe_typo(0.03)

    def scenario_cart_buy(self):
        """장바구니구매: 담기 1~3개 -> 장바구니 -> (수량 -/+ / 빼기 / 상품 다시 보기) -> 결제 or 비우기 or 보류"""
        self.enter_site()
        if not self.jwt_token:
            self.dwell()
            if not self.login():
                return
        for _ in range(random.randint(1, 3)):
            self.ensure_list_page()
            if random.random() < 0.3:
                self.dwell(); self.search()
            pid = self.view_product()
            self.dwell(); self.add_to_cart(pid)
        if self.page_path() != "/cart.php":
            self.nav("/cart.php")
        if random.random() < 0.4:
            self.cart_stepper()
        if random.random() < 0.2:
            self.dwell(); self.cart_remove()
        if self.cart and random.random() < 0.1:              # 장바구니에서 상품 이름 눌러 다시 확인
            self.view_product(random.choice(self.cart).get("product_id"))
            self.nav("/cart.php")
        r = random.random()
        if r < 0.6:
            self.dwell(); self.cart_checkout()
        elif r < 0.7:
            self.dwell(); self.cart_clear()
        elif r < 0.8:
            self.nav("/products.php")                        # '쇼핑 계속하기'
            self.browse_list(max_details=1)
        self.dwell()                                         # 나머지는 담아만 두고 떠남

    def scenario_buy_now(self):
        """바로구매: 상품 확인 -> (비로그인이면 '로그인' 링크) -> 바로 주문 -> (주문 상세)"""
        self.enter_site()
        pid = self.view_product()
        if not self.jwt_token:
            self.dwell()
            if not self.login():
                return
            pid = self.view_product(pid)
        self.dwell(); self.buy_now(pid)
        if self.page_path() != "/order.php" and random.random() < 0.4:
            self.nav("/orders.php")
        self.dwell()

    def scenario_account(self):
        """주문확인: 내 주문 -> (상태 탭 / 이전·다음) -> 주문 상세 -> (취소 / 상품 다시 보기) -> (내 정보)"""
        self.enter_site()
        if not self.jwt_token:
            self.dwell()
            if not self.login():
                return
        if self.page_path() != "/orders.php":
            self.nav("/orders.php")
        if random.random() < 0.35:
            self.dwell(); self.click_order_tab()
        if random.random() < 0.2:
            self.dwell(); self.orders_next_page()
        if self.my_orders and random.random() < 0.65:
            oid = random.choice(self.my_orders).get("id")
            self.nav(f"/order.php?id={oid}")
            if random.random() < 0.12:
                self.cancel_order()
            if random.random() < 0.15:
                pid = self.order_item_product()
                if pid and random.random() < 0.3:
                    self.dwell(); self.add_to_cart(pid)       # 재구매
            elif random.random() < 0.4:
                self.nav("/orders.php")
        if random.random() < 0.3:
            self.nav("/me.php")
            if random.random() < 0.3:
                self.nav(random.choice(["/orders.php", "/cart.php"]))   # 마이페이지 옆 메뉴
        self.dwell()

    def scenario_profile(self):
        """내정보수정: 내 정보 -> 정보 수정 (가끔 취소) -> (옆 메뉴)"""
        self.enter_site()
        if not self.jwt_token:
            self.dwell()
            if not self.login():
                return
        self.nav("/me.php")
        self.edit_profile()
        if random.random() < 0.3:
            self.nav(random.choice(["/orders.php", "/cart.php"]))
        self.dwell()

    def scenario_signup(self):
        """신규가입: 둘러보다가 가입 -> 로그인 (가끔 가입 화면만 보고 나감)"""
        self.enter_site()
        self.dwell()
        if random.random() < 0.15:
            self.nav("/signup.php")
            self.dwell()
            return
        self.signup()
        self.dwell()

    def current_pid(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.current_page or "").query)
        return q.get("id", [self.pick_listed()])[0]

    def choose_persona(self):
        if not self.account:
            if self.allow_writes and random.random() < GUEST_SIGNUP_PROB:
                return "신규가입"
            return random.choices(["단순구경", "검색", "꼼꼼탐색"], weights=[0.5, 0.25, 0.25])[0]
        weights = dict(PERSONA_WEIGHTS)
        if not self.allow_writes:
            for p in WRITE_PERSONAS:
                weights["꼼꼼탐색"] += weights.pop(p)
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
        interrupted = False
        try:
            {"단순구경": self.scenario_casual, "검색": self.scenario_search, "꼼꼼탐색": self.scenario_explore,
             "장바구니구매": self.scenario_cart_buy, "바로구매": self.scenario_buy_now,
             "주문확인": self.scenario_account, "내정보수정": self.scenario_profile,
             "신규가입": self.scenario_signup}[persona]()
            if random.random() < LOGOUT_PROB:
                self.logout()
        except ServerUnhealthy as e:
            error = str(e)
        except KeyboardInterrupt:
            error = "사용자 중단(Ctrl+C)"
            interrupted = True
        return {
            "interrupted": interrupted,
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
    # 이 생성기는 개편된 쇼핑몰(app.js?v=..., 검색창/분류 칩, 장바구니 API) 기준.
    # 예전 쇼핑몰이면 장바구니/검색/주문상세 API 가 404 라 정상 데이터에 가짜 404 가 섞이므로 시작하지 않음
    html = person.last_html
    if ok and not ("app.js?v=" in html and 'id="search-form"' in html):
        return False, {"version": "쇼핑몰 화면이 생성기 기준(개편 버전: app.js?v=..., 검색창)과 다릅니다", **codes}
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
        if "version" in codes:
            print(f"[중단] {codes.pop('version')}")
            print("       DMZ 웹서버에 개편된 쇼핑몰(web/src, ASSET_VERSION 20261029-b2 이후)이 배포됐는지 확인하세요.")
            print("       예전 쇼핑몰에는 장바구니/검색/주문상세 API 가 없어 정상 데이터에 가짜 404 가 섞입니다.")
        else:
            print(f"[중단] 서버 점검 실패: products.php 응답 코드 {codes}")
            print("       API 가 5xx 를 반환하거나 접속이 안 됩니다. 웹서버/DB 상태를 확인한 뒤 다시 실행하세요.")
        print("       (이 상태로 수집한 데이터는 정상 데이터로 쓸 수 없습니다)")
        return 0, "preflight_failed"
    print(f"[점검] 서버 정상 (products.php 응답 {codes})\n")

    fields = ["member", "local_ip", "visit_idx", "persona", "account", "device", "logged_in",
              "start_utc", "end_utc", "requests", "status_counts", "error", "label"]
    abort_reason = ""
    with open(manifest_path, "w", newline="", encoding="utf-8-sig") as mf:
        writer = csv.DictWriter(mf, fieldnames=fields, extrasaction="ignore")
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
                if summary.get("interrupted"):
                    print("\n[알림] 사용자에 의해 중단되었습니다. (마지막 방문까지 manifest 에 기록)")
                    break
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
    parser = argparse.ArgumentParser(description="B-Profile Benign Traffic Generator (1 PC = 1 customer)")
    parser.add_argument("--target", default="http://192.168.0.141:8000", help="대상 쇼핑몰 URL")
    parser.add_argument("--member", type=int, default=0,
                        help="팀원 번호(1~6). 계정 user{번호}@example.com 을 사용하고 manifest 에 기록")
    parser.add_argument("--account-email", default=None, help="계정 직접 지정 (기본: --member 번호 계정)")
    parser.add_argument("--start-as-guest", action="store_true",
                        help="비회원으로 시작 (방문 중 일정 확률로 회원가입 후 그 계정 사용)")
    parser.add_argument("--no-writes", action="store_true", help="주문/주문취소/회원가입/내정보 수정 안 함 (장바구니는 허용)")
    parser.add_argument("--device", default="auto", choices=["auto"] + list(DEVICES),
                        help="사용 기기 (기본 auto: 실행 시 1개를 무작위로 골라 끝까지 유지)")
    parser.add_argument("--duration", type=int, default=1800, help="총 실행 시간(초), 기본 1800 (30분)")
    parser.add_argument("--away-min", type=float, default=15.0, help="방문 사이 이탈 시간 최소(초)")
    parser.add_argument("--away-max", type=float, default=90.0, help="방문 사이 이탈 시간 최대(초)")
    parser.add_argument("--min-users", type=int, default=1, help="(레거시) 동시 접속자 최소")
    parser.add_argument("--max-users", type=int, default=1, help="(레거시) 동시 접속자 최대. 2 이상이면 다중 접속 모드")
    parser.add_argument("--seed", type=int, default=None, help="난수 시드 (재현용)")
    parser.add_argument("--manifest-dir", default=str(pathlib.Path.cwd() / "manifests"),
                        help="방문 기록 CSV 저장 폴더 (기본: 현재 폴더의 manifests/)")
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
    print(" [B-Profile v5] 정상 사용자 트래픽 생성기" + (" - (레거시) 다중 접속 모드" if multi else " - 1 PC = 1 고객"))
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
        print(f" * 주문/취소/가입/정보수정 : {'안 함 (--no-writes)' if args.no_writes else '함 (낮은 확률)'}  (장바구니는 항상 사용)")
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
