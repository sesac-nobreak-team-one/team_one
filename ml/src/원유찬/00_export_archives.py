#!/usr/bin/env python3
"""
00_export_archives.py — Wazuh 서버의 archives.json 에서 원하는 시간대 로그를 CSV 로 추출

왜 필요한가
  OpenSearch 대시보드(Discover)의 CSV 내보내기는 최대 10,000행까지만 받아집니다.
  (예: pentagi_session_1026 이 정확히 10,000행 -> 공격 초반 약 3분 누락)
  archives.json 은 Wazuh 가 받은 '모든' 이벤트를 행 수 제한 없이 저장하므로
  여기서 직접 잘라내면 데이터가 빠지지 않습니다.

실행 위치
  Wazuh 매니저 서버 (192.168.10.30) 에서 실행합니다. 표준 라이브러리만 사용 (Python 3.6+).
  archives 폴더는 root 권한이 필요하므로 sudo 로 실행하세요.

사용 예시 (시각은 기본 KST)
  sudo python3 00_export_archives.py --start "2026-10-29 14:00:00" --end "2026-10-29 14:30:00" \
       --name user_session_1029_1400-1430

  sudo python3 00_export_archives.py --start "2026-10-29 15:00:00" --end "2026-10-29 15:10:00" \
       --name pentagi_session_1029_1500-1510

  -> /tmp/wazuh_export/<name>.csv 생성. 이 파일을 PC 의 ml/data/raw_logs/ 로 옮긴 뒤
     01_preprocess.py 를 실행하면 됩니다. (파일명에 attack/pentagi 가 있으면 공격으로 라벨링)

읽는 파일
  /var/ossec/logs/archives/archives.json                          (오늘)
  /var/ossec/logs/archives/YYYY/Mon/ossec-archive-DD*.json[.gz]   (지난 날짜, 자정에 로테이션)
"""

import argparse
import csv
import datetime
import glob
import gzip
import io
import json
import os
import re
import sys
from collections import Counter

# 기본으로 뽑을 로그 (웹서버 Apache 접근 로그 + 앱 비즈니스 로그)
#   WAF 컨테이너의 access.log 도 Apache 형식이라 같이 뽑으면 같은 요청이 두 번 잡히므로 기본 제외
DEFAULT_LOCATIONS = ["shop_access.log", "app.log"]

TS_RE = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?([+-]\d{2}:?\d{2}|Z)?$')
IP_RE = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})\s')


def parse_tz(text):
    """'+09:00' / '+0900' -> timezone"""
    m = re.match(r'^([+-])(\d{2}):?(\d{2})$', text)
    if not m:
        raise ValueError("타임존 형식 오류: %s (예: +09:00)" % text)
    sign = 1 if m.group(1) == '+' else -1
    return datetime.timezone(sign * datetime.timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))


def parse_archive_ts(text):
    """archives.json 의 timestamp ('2026-10-29T10:58:35.232+0900') -> aware datetime"""
    m = TS_RE.match(text or "")
    if not m:
        return None
    base, frac, tz = m.groups()
    dt = datetime.datetime.strptime(base, "%Y-%m-%dT%H:%M:%S")
    if frac:
        dt = dt.replace(microsecond=int(frac[:6].ljust(6, '0')))
    if tz in (None, 'Z'):
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.replace(tzinfo=parse_tz(tz))


def candidate_files(archives_dir, start, end):
    """시간 범위에 해당하는 archives 파일 목록"""
    files = []
    day = start.date()
    while day <= end.date():
        month_dir = os.path.join(archives_dir, day.strftime("%Y"), day.strftime("%b"))
        pattern = os.path.join(month_dir, "ossec-archive-%02d*.json*" % day.day)
        files.extend(sorted(glob.glob(pattern)))
        day += datetime.timedelta(days=1)
    current = os.path.join(archives_dir, "archives.json")
    if os.path.isfile(current):
        files.append(current)
    return [f for f in files if not f.endswith(".sum")]


def open_any(path):
    if path.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def main():
    ap = argparse.ArgumentParser(description="Wazuh archives.json -> 01_preprocess 호환 CSV 추출")
    ap.add_argument("--start", required=True, help='시작 시각 "YYYY-MM-DD HH:MM:SS" (기본 KST)')
    ap.add_argument("--end", required=True, help='종료 시각 "YYYY-MM-DD HH:MM:SS" (기본 KST)')
    ap.add_argument("--name", required=True,
                    help="출력 파일 이름 (예: user_session_1029_1400-1430, pentagi_session_1029_1500-1510)")
    ap.add_argument("--tz", default="+09:00", help="--start/--end 의 타임존 (기본 +09:00 KST)")
    ap.add_argument("--locations", nargs="*", default=DEFAULT_LOCATIONS,
                    help="추출할 로그 위치(부분 일치). 기본: shop_access.log app.log")
    ap.add_argument("--all-locations", action="store_true", help="위치 필터 없이 전부 추출")
    ap.add_argument("--agent", default=None, help="에이전트 이름 필터 (예: web-server)")
    ap.add_argument("--archives-dir", default="/var/ossec/logs/archives")
    ap.add_argument("--out-dir", default="/tmp/wazuh_export")
    args = ap.parse_args()

    tz = parse_tz(args.tz)
    start = datetime.datetime.strptime(args.start, "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz)
    end = datetime.datetime.strptime(args.end, "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz)
    if end <= start:
        sys.exit("[ERROR] --end 가 --start 보다 늦어야 합니다.")

    files = candidate_files(args.archives_dir, start, end)
    if not files:
        sys.exit("[ERROR] archives 파일을 찾지 못했습니다: %s (sudo 로 실행했는지, logall_json 이 켜져 있는지 확인)"
                 % args.archives_dir)

    os.makedirs(args.out_dir, exist_ok=True)
    out_path = os.path.join(args.out_dir, args.name + ".csv")
    locations = None if args.all_locations else args.locations

    print("=" * 70)
    print(" Wazuh archives 추출")
    print("=" * 70)
    print(" * 기간     : %s ~ %s (%s)" % (args.start, args.end, args.tz))
    print(" * 위치 필터: %s" % ("없음(전체)" if locations is None else ", ".join(locations)))
    print(" * 읽을 파일:")
    for f in files:
        print("     - %s" % f)

    n_written, n_bad = 0, 0
    loc_counter, ip_counter = Counter(), Counter()
    first_ts, last_ts = None, None

    with open(out_path, "w", newline="", encoding="utf-8-sig") as out:
        writer = csv.writer(out)
        writer.writerow(["timestamp", "agent_name", "location", "full_log"])

        for path in files:
            with open_any(path) as fh:
                for line in fh:
                    # 빠른 사전 필터: JSON 파싱 전에 문자열로 위치 확인
                    if locations is not None and not any(loc in line for loc in locations):
                        continue
                    try:
                        ev = json.loads(line)
                    except ValueError:
                        n_bad += 1
                        continue

                    location = ev.get("location", "")
                    if locations is not None and not any(loc in location for loc in locations):
                        continue
                    agent_name = (ev.get("agent") or {}).get("name", "")
                    if args.agent and agent_name != args.agent:
                        continue

                    ts = parse_archive_ts(ev.get("timestamp"))
                    if ts is None or ts < start or ts >= end:
                        continue

                    full_log = ev.get("full_log", "")
                    writer.writerow([ev.get("timestamp"), agent_name, location, full_log])
                    n_written += 1
                    loc_counter[os.path.basename(location)] += 1
                    m = IP_RE.match(full_log)
                    if m:
                        ip_counter[m.group(1)] += 1
                    first_ts = ts if first_ts is None or ts < first_ts else first_ts
                    last_ts = ts if last_ts is None or ts > last_ts else last_ts

    print("-" * 70)
    print(" * 추출 건수 : %d건 -> %s" % (n_written, out_path))
    if n_written:
        print(" * 실제 범위 : %s ~ %s" % (first_ts.astimezone(tz).strftime("%H:%M:%S"),
                                         last_ts.astimezone(tz).strftime("%H:%M:%S")))
    print(" * 위치별    : %s" % dict(loc_counter))
    print(" * 출발지 IP (access 로그 기준, 상위 10개):")
    for ip, cnt in ip_counter.most_common(10):
        print("     - %-16s %d건" % (ip, cnt))
    if n_bad:
        print(" * JSON 파싱 실패 줄: %d (무시)" % n_bad)
    if n_written == 0:
        print(" [주의] 0건입니다. 시간대/타임존(--tz), 위치 필터를 확인하세요.")
    print("=" * 70)


if __name__ == "__main__":
    main()
