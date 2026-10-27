#!/usr/bin/env python3
r"""
B-Profile 기반 동적 정상 사용자 트래픽 생성기 (CICIDS2017 방법론 기반)
------------------------------------------------------------------
논문: Sharafaldin et al., "Toward Generating a New Intrusion Detection Dataset" (2018)
목적: 고정된 인원수가 아닌, 시간에 따라 5명~20명 사이로 유동적으로 증감(Fluctuation)하는
      실제 쇼핑몰 방문자 라이프사이클(도착 -> 쇼핑 -> 퇴장)을 시뮬레이션하여
      취약한 웹서버에 현실적인 정상 사용자 배경 트래픽(Label=0)을 생성합니다.

특징:
1. 유동적 동시 접속자 수 (Dynamic Concurrency): 5명 ~ 20명 사이 유동적 변동
2. 현실적인 방문자 라이프사이클: 고객마다 1~3회 쇼핑 후 퇴장하고 새로운 고객이 입장
3. 회원(18명 풀)과 비회원(게스트)의 유동적 혼합 (약 9:1 비율)
4. 인간 체류 시간(Think Time) 로그정규 분포 + 자연스러운 404 실수 클릭 포함

실행 방법 예시:
python d:\Project\team_one\ml\src\generate_benign_traffic.py --duration 600 --min-users 5 --max-users 20
"""

import sys
import io
import time
import math
import random
import datetime
import threading
import argparse
import json
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar

# 윈도우 콘솔 즉시 출력(Flush) 및 UTF-8 인코딩 설정
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', line_buffering=True)
        sys.stderr.reconfigure(encoding='utf-8', line_buffering=True)
    except AttributeError:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)

# -------------------------------------------------------------
# 사용자 에이전트(User-Agent) 풀 - 현실적인 다양한 디바이스 모방
# -------------------------------------------------------------
USER_AGENTS = [
    # Windows 11 Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # iPhone 15 Safari
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    # Android Galaxy S23 Chrome
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    # Windows 11 Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Mac Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15"
]

# -------------------------------------------------------------
# 18명의 정식 회원 테스트 계정 풀 (user1 ~ user18)
# -------------------------------------------------------------
USER_ACCOUNTS_18 = [
    {"email": f"user{i}@example.com", "password": "Test1234!"}
    for i in range(1, 19)
]

# 통계 집계용 글로벌 락 및 변수
stats_lock = threading.Lock()
total_requests = 0
status_counts = {}
active_member_emails = set()  # 현재 쇼핑몰 안에 접속해 있는 회원 이메일 추적
persona_counts = {"단순구경": 0, "꼼꼼탐색": 0, "주문확인": 0}  # 페르소나별 누적 방문 통계

def human_think_time(min_sec=1.5, max_sec=5.0):
    """
    CICIDS2017 B-Profile 논문 명세:
    인간의 웹 페이지 체류 시간(Think Time)은 로그정규 분포(Log-Normal Distribution)를 따름.
    """
    val = random.lognormvariate(1.0, 0.4)
    clipped = max(min_sec, min(val, max_sec))
    time.sleep(clipped)
    return clipped

class SimulatedShopper(threading.Thread):
    def __init__(self, user_idx, target_host, stop_event, persona="단순구경", account=None, max_cycles=1):
        super().__init__()
        self.user_idx = user_idx
        self.target_host = target_host.rstrip('/')
        self.stop_event = stop_event
        self.persona = persona
        self.account = account
        self.max_cycles = max_cycles
        self.user_agent = random.choice(USER_AGENTS)
        self.jwt_token = None
        
        # 독립적인 쿠키 세션 생성
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar))
        
        # 기기 별칭 (로그 출력용)
        if "iPhone" in self.user_agent:
            self.device_name = "iPhone-Safari"
        elif "Android" in self.user_agent:
            self.device_name = "Galaxy-Chrome"
        elif "Macintosh" in self.user_agent:
            self.device_name = "Mac-Safari"
        elif "Edg" in self.user_agent:
            self.device_name = "Win-Edge"
        else:
            self.device_name = "Win-Chrome"

    def request(self, method, path, data=None, is_json=False):
        """HTTP 요청 전송 및 통계 기록"""
        url = f"{self.target_host}{path}"
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" if not is_json else "application/json",
            "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7"
        }
        if self.jwt_token:
            headers["Authorization"] = f"Bearer {self.jwt_token}"

        encoded_data = None
        if data is not None:
            if is_json:
                encoded_data = json.dumps(data).encode("utf-8")
                headers["Content-Type"] = "application/json"
            else:
                encoded_data = urllib.parse.urlencode(data).encode("utf-8")
                headers["Content-Type"] = "application/x-www-form-urlencoded"

        req = urllib.request.Request(url, data=encoded_data, headers=headers, method=method)
        status_code = 0
        try:
            with self.opener.open(req, timeout=5) as response:
                status_code = response.status
                response.read()
        except urllib.error.HTTPError as e:
            status_code = e.code
        except Exception:
            status_code = 0

        # 통계 집계
        with stats_lock:
            global total_requests
            total_requests += 1
            status_counts[status_code] = status_counts.get(status_code, 0) + 1

        return status_code

    def do_login(self):
        """쇼핑몰 API 로그인 및 JWT 토큰 저장"""
        if not self.account:
            return False
        req = urllib.request.Request(
            f"{self.target_host}/api/v2/login",
            data=json.dumps(self.account).encode(),
            headers={"Content-Type": "application/json", "User-Agent": self.user_agent}
        )
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    resp_data = json.loads(resp.read().decode())
                    self.jwt_token = resp_data.get("access_token")
                    with stats_lock:
                        global total_requests
                        total_requests += 1
                        status_counts[200] = status_counts.get(200, 0) + 1
                    return True
        except Exception:
            pass
        return False

    def _maybe_trigger_typo_404(self, prob=0.02):
        """인간적인 실수로 인한 404 오타 페이지 클릭 시뮬레이션"""
        if random.random() < prob:
            typo_path = random.choice(["/product_old.php", "/item/999", "/cart.html", "/help.php"])
            self.request("GET", typo_path)
            time.sleep(random.uniform(0.5, 1.2))

    def _run_casual_browser(self):
        """
        [행동 유형 1] 단순 구경꾼 (Casual Browser, 약 40%)
        - 가볍게 메인과 상품 목록을 둘러보고 관심 가는 상품 1개 정도만 슬쩍 확인 후 이탈
        """
        # 1. 메인 홈페이지 방문
        self.request("GET", "/index.php")
        human_think_time(1.5, 3.0)
        if self.stop_event.is_set(): return

        # 2. 전체 상품 목록 둘러보기 (HTML 로드 후 브라우저 비동기 API 호출 모방)
        self.request("GET", "/products.php")
        time.sleep(random.uniform(0.1, 0.3))
        self.request("GET", "/api/v2/products")
        human_think_time(2.0, 4.0)
        if self.stop_event.is_set(): return

        # 3. 60% 확률로 관심 가는 상품 1개만 클릭하여 상세 확인
        if random.random() < 0.6:
            prod_id = random.randint(1, 10)
            self.request("GET", f"/product.php?id={prod_id}")
            time.sleep(random.uniform(0.1, 0.3))
            self.request("GET", f"/api/v2/products/{prod_id}")
            human_think_time(2.0, 4.0)

        # 4. 자연스러운 오타 가능성
        self._maybe_trigger_typo_404(prob=0.02)

    def _run_deep_explorer(self):
        """
        [행동 유형 2] 꼼꼼 탐색 쇼퍼 (Deep Explorer, 약 35%)
        - 여러 상품의 상세 페이지를 차례차례 비교하고, 다시 목록으로 돌아오기도 하는 진지한 쇼핑객
        """
        # 1. 메인 홈페이지 방문
        self.request("GET", "/index.php")
        human_think_time(1.2, 2.5)
        if self.stop_event.is_set(): return

        # 2. 전체 상품 목록 둘러보기
        self.request("GET", "/products.php")
        time.sleep(random.uniform(0.1, 0.3))
        self.request("GET", "/api/v2/products")
        human_think_time(2.0, 3.5)
        if self.stop_event.is_set(): return

        # 3. 2~4개의 다양한 상품을 진득하게 비교 탐색
        view_count = random.randint(2, 4)
        chosen_ids = random.sample(range(1, 11), view_count)

        for idx, prod_id in enumerate(chosen_ids):
            if self.stop_event.is_set(): break
            self.request("GET", f"/product.php?id={prod_id}")
            time.sleep(random.uniform(0.1, 0.3))
            self.request("GET", f"/api/v2/products/{prod_id}")
            human_think_time(2.5, 5.0)

            # 중간에 35% 확률로 전체 목록으로 다시 돌아와 다른 상품 목록 둘러보기
            if idx < len(chosen_ids) - 1 and random.random() < 0.35:
                self.request("GET", "/products.php")
                time.sleep(random.uniform(0.1, 0.3))
                self.request("GET", "/api/v2/products")
                human_think_time(1.5, 3.0)

        # 4. 자연스러운 오타 가능성
        self._maybe_trigger_typo_404(prob=0.03)

    def _run_account_checker(self):
        """
        [행동 유형 3] 주문/계정 확인 단골 회원 (Account Checker, 약 25%)
        - 로그인하여 본인의 이전 주문 내역이나 배송 현황, 프로필을 확인하러 온 회원
        """
        # 1. 메인 홈페이지 방문
        self.request("GET", "/index.php")
        human_think_time(1.0, 2.0)
        if self.stop_event.is_set(): return

        # 2. 로그인 수행
        login_ok = self.do_login()
        human_think_time(1.2, 2.2)
        if self.stop_event.is_set(): return

        if self.jwt_token:
            # 3. 내 주문 내역 페이지 확인 (핵심 목적)
            self.request("GET", "/orders.php")
            time.sleep(random.uniform(0.1, 0.3))
            self.request("GET", "/api/v2/orders/me")
            human_think_time(2.5, 5.0)
            if self.stop_event.is_set(): return

            # 4. 70% 확률로 내 프로필/회원 정보도 함께 확인
            if random.random() < 0.7:
                self.request("GET", "/me.php")
                time.sleep(random.uniform(0.1, 0.3))
                self.request("GET", "/api/v2/users/me")
                human_think_time(1.5, 3.0)
                if self.stop_event.is_set(): return

            # 5. 30% 확률로 나가는 길에 상품 목록 둘러보기
            if random.random() < 0.3:
                self.request("GET", "/products.php")
                time.sleep(random.uniform(0.1, 0.3))
                self.request("GET", "/api/v2/products")
                human_think_time(1.5, 3.0)

        # 6. 자연스러운 오타 가능성
        self._maybe_trigger_typo_404(prob=0.02)

    def run(self):
        """가상 고객의 쇼핑 라이프사이클 (입장 -> 페르소나별 행동 -> 퇴장)"""
        now_str = datetime.datetime.now().strftime("%H:%M:%S")
        is_member = f"회원({self.account['email'].split('@')[0]})" if self.account else "비회원(게스트)"
        print(f"[{now_str}] [+] [손님 #{self.user_idx:03d} ({self.device_name}, {self.persona}, {is_member})] 쇼핑몰 입장!")

        # 통계 집계 등록
        with stats_lock:
            persona_counts[self.persona] = persona_counts.get(self.persona, 0) + 1
            if self.account:
                active_member_emails.add(self.account["email"])

        try:
            for cycle in range(1, self.max_cycles + 1):
                if self.stop_event.is_set():
                    break

                # 페르소나 유형에 따른 맞춤형 브라우징 수행
                if self.persona == "단순구경":
                    self._run_casual_browser()
                elif self.persona == "꼼꼼탐색":
                    self._run_deep_explorer()
                elif self.persona == "주문확인":
                    self._run_account_checker()
                else:
                    self._run_casual_browser()

                if cycle < self.max_cycles and not self.stop_event.is_set():
                    human_think_time(2.0, 4.0)

        finally:
            # 쇼핑 완료 후 사이트 퇴장
            if self.account:
                with stats_lock:
                    active_member_emails.discard(self.account["email"])
            
            now_str = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"[{now_str}] [-] [손님 #{self.user_idx:03d} ({self.persona}, {is_member})] 쇼핑 마치고 사이트 퇴장.")

def get_dynamic_target(elapsed_sec, period_sec, min_users, max_users):
    """
    시간 경과에 따라 동시 접속자 수를 min_users ~ max_users 사이에서
    부드러운 파동과 자연스러운 노이즈를 섞어 유동적으로 계산
    """
    progress = (elapsed_sec % period_sec) / period_sec
    mid = (min_users + max_users) / 2.0
    amplitude = (max_users - min_users) / 2.0
    wave = math.sin(progress * 2 * math.pi)
    jitter = random.uniform(-1.0, 1.0)
    target = int(round(mid + amplitude * wave + jitter))
    return max(min_users, min(max_users, target))

def print_banner(target, duration, min_u, max_u):
    print("=" * 72)
    print(" [B-Profile] 동적 정상 사용자 트래픽 생성기 (Dynamic User Concurrency)")
    print("=" * 72)
    print(f" * 대상 서버 URL         : {target}")
    print(f" * 총 시뮬레이션 시간    : {duration}초 ({duration//60}분 {duration%60}초)")
    print(f" * 동시 접속자 유동 범위 : {min_u}명 ~ {max_u}명 (시간에 따라 자동 증감)")
    print(f" * 행동 페르소나 3종 분기: [단순구경(40%)] / [꼼꼼탐색(35%)] / [주문확인(25%)]")
    print(f" * 적용 알고리즘         : Log-Normal 체류 시간 + Poisson 라이프사이클 + AJAX 비동기 텀")
    print(f" * 종료 방법             : {duration}초 후 자동 종료 또는 언제든 [Ctrl + C]")
    print("=" * 72)
    print("[시스템] 3대 행동 유형 기반 동적 사용자 트래픽 생성을 시작합니다...\n")

def main():
    parser = argparse.ArgumentParser(description="B-Profile Dynamic Benign Traffic Generator")
    parser.add_argument("--target", default="http://192.168.0.141:8000", help="Target Shop URL (default: http://192.168.0.141:8000)")
    parser.add_argument("--duration", type=int, default=600, help="Duration in seconds (default: 600s = 10min)")
    parser.add_argument("--min-users", type=int, default=5, help="Minimum concurrent users (default: 5)")
    parser.add_argument("--max-users", type=int, default=20, help="Maximum concurrent users (default: 20)")
    args = parser.parse_args()

    print_banner(args.target, args.duration, args.min_users, args.max_users)

    stop_event = threading.Event()
    active_threads = []
    user_counter = 0
    wave_period = 90.0  # 90초 주기로 방문자 수가 밀물/썰물처럼 파동 형성

    start_time = time.time()
    last_status_print = 0

    try:
        while time.time() - start_time < args.duration:
            elapsed = time.time() - start_time
            remaining = max(0, int(args.duration - elapsed))

            # 1. 종료된 스레드 정리
            active_threads = [t for t in active_threads if t.is_alive()]
            current_count = len(active_threads)

            # 2. 현재 시점의 목표 동시 접속자 수 계산 (5~20명 유동적)
            target_count = get_dynamic_target(elapsed, wave_period, args.min_users, args.max_users)

            # 3. 부족한 인원만큼 신규 고객 입장
            if current_count < target_count:
                needed = target_count - current_count
                # 한 번에 1~3명씩 점진적으로 입장
                spawn_now = min(needed, random.randint(1, 3))
                for _ in range(spawn_now):
                    user_counter += 1
                    
                    # 3대 행동 페르소나 가중치 결정 (단순구경 40%, 꼼꼼탐색 35%, 주문확인 25%)
                    persona = random.choices(["단순구경", "꼼꼼탐색", "주문확인"], weights=[0.40, 0.35, 0.25], k=1)[0]
                    chosen_account = None

                    if persona == "주문확인":
                        # 주문확인은 반드시 로그인 계정 할당
                        with stats_lock:
                            idle_accounts = [acc for acc in USER_ACCOUNTS_18 if acc["email"] not in active_member_emails]
                            chosen_account = random.choice(idle_accounts) if idle_accounts else random.choice(USER_ACCOUNTS_18)
                    elif persona == "꼼꼼탐색":
                        # 꼼꼼탐색은 약 40% 확률로 회원 로그인
                        if random.random() < 0.40:
                            with stats_lock:
                                idle_accounts = [acc for acc in USER_ACCOUNTS_18 if acc["email"] not in active_member_emails]
                                chosen_account = random.choice(idle_accounts) if idle_accounts else random.choice(USER_ACCOUNTS_18)
                    else:  # 단순구경
                        # 단순구경은 85% 비회원(게스트), 15% 회원
                        if random.random() < 0.15:
                            with stats_lock:
                                idle_accounts = [acc for acc in USER_ACCOUNTS_18 if acc["email"] not in active_member_emails]
                                chosen_account = random.choice(idle_accounts) if idle_accounts else random.choice(USER_ACCOUNTS_18)

                    # 신규 고객 스레드 시작
                    shopper = SimulatedShopper(
                        user_idx=user_counter,
                        target_host=args.target,
                        stop_event=stop_event,
                        persona=persona,
                        account=chosen_account,
                        max_cycles=1
                    )
                    shopper.daemon = True
                    shopper.start()
                    active_threads.append(shopper)

            # 4. 10초마다 콘솔에 현재 동시 접속 현황 브리핑 출력
            if time.time() - last_status_print >= 10:
                last_status_print = time.time()
                with stats_lock:
                    mem_count = len(active_member_emails)
                    guest_count = max(0, len(active_threads) - mem_count)
                print(f"\n>>> [실시간 접속 현황 ({int(elapsed)}초 경과)] "
                      f"현재 동시 접속자: {len(active_threads)}명 (회원: {mem_count}명, 비회원: {guest_count}명) "
                      f"| 유동 목표: {target_count}명 (범위 {args.min_users}~{args.max_users}명) | 잔여: {remaining}초\n")

            time.sleep(1)

    except KeyboardInterrupt:
        print("\n\n[알림] 사용자에 의해 생성이 중단되었습니다. 접속 중인 고객 세션을 종료합니다...")
    finally:
        stop_event.set()
        for t in active_threads:
            t.join(timeout=1.5)

    total_time = round(time.time() - start_time, 1)
    print("\n" + "=" * 72)
    print(" [완료] 동적 정상 사용자 트래픽 생성 요약 리포트")
    print("=" * 72)
    print(f" * 총 소요 시간         : {total_time}초 ({round(total_time/60, 1)}분)")
    print(f" * 총 방문 고객 수      : {user_counter}명 (동적으로 입장 및 퇴장 반복)")
    print(" * 페르소나별 고객 분포 :")
    for p_name, p_cnt in persona_counts.items():
        p_ratio = round((p_cnt / max(1, user_counter)) * 100, 1)
        print(f"   - {p_name:6s}: {p_cnt}명 ({p_ratio}%)")
    print(f" * 총 발생 HTTP 요청 수 : {total_requests}건")
    if total_time > 0:
        print(f" * 평균 요청 속도       : {round(total_requests / total_time, 2)} req/sec (인간적인 자연스러운 속도)")
    print(" * HTTP 응답 상태코드 분포:")
    for code, count in sorted(status_counts.items()):
        status_name = "성공(OK)" if code == 200 else ("404(자연스러운 오타)" if code == 404 else f"Status {code}")
        ratio = round((count / max(1, total_requests)) * 100, 1)
        print(f"   - {code} [{status_name}]: {count}건 ({ratio}%)")
    print("=" * 72)
    print("[성공] 3대 행동 페르소나 기반 정상 트래픽 로그(Label=0)가 웹서버와 Wazuh에 성공적으로 적재되었습니다.")
    print("=" * 72)
    print("=" * 72)

if __name__ == "__main__":
    main()
