"""
01_preprocess.py — Wazuh 원본 로그(CSV) -> IP별 30초 창 머신러닝 피처 추출

[2026-10-29 수정 사항]
  1) interval_mean / interval_std 단위 버그 수정
     - 기존: np.diff(...).astype('float64') / 1e9  (나노초 가정)
     - pandas 2.x/3.x 는 파이썬 datetime 을 datetime64[us](마이크로초)로 저장하는 경우가 있어
       값이 실제보다 1000배 작게 계산되었음 (예: 0.066초 -> 0.0001)
     - 수정: np.diff(...) / np.timedelta64(1, 's')  (단위와 무관하게 항상 '초')
  2) access.log / app.log 이중 집계 수정
     - 같은 API 요청이 shop_access.log 와 app.log 에 동시에 남는데 둘 다 레코드로 넣고 있었음
       (예: user_session_1027 -> access 5,655건 + app 2,407건 중복 합산)
     - 수정: 한 파일 안에서 access > app > OpenSearch 분할컬럼 순으로 '한 가지 소스만' 사용
  3) 밀리초 타임스탬프 및 타임존 지원
     - Apache 로그가 초 단위라 요청 간격의 상당수가 0으로 계산되었음
     - Apache LogFormat 에 밀리초를 추가하면 자동으로 인식하도록 정규식/파서 확장
       예) [27/Oct/2026:05:44:13.123 +0000]
     - '+0000', '+0900' 등 타임존을 실제로 해석하여 UTC 로 통일 (기존에는 무시하고 버림)

[2026-10-29 경로] 기본 입출력 폴더가 '현재 폴더' 기준: ./raw_logs -> ./features
  (예: ml/data 폴더에서 python ../src/원유찬/01_preprocess.py 실행)

[추가 기능]
  - 정상/공격이 한 파일에 섞인 경우: 파일명에 'mixed' 를 넣고 --attack-ips 로 IP 라벨링
      (mixed 가 없는 기존 파일은 지금처럼 파일명으로 라벨링 -> 기존 데이터 라벨이 바뀌지 않음)
  - --benign-ips : mixed 파일에서 정상 IP 목록을 주면, 어느 목록에도 없는 IP(테스트 curl,
      다른 사람 접속 등)는 학습에서 제외하고 경고
                   (정상 배경 트래픽을 켜둔 상태에서 PentAGI 를 돌리는 경우)
  - Wazuh location 필드로 shop_access.log / app.log 만 사용 (WAF access.log 이중 집계 방지)
  - 00_export_archives.py 로 뽑은 CSV(full_log, location 컬럼)도 그대로 처리
  - Shadow API / IDOR 탐지 피처 추가 (shadow_api_ratio, orphan_api_ratio, unique_id_count,
    id_seq_ratio, auth_fail_ratio, interval_cv, method_nunique)
  - 피처 정리 (14종): 중복/무의미 피처 제거, unique_url_ratio, api_2xx_bytes_sum, error_5xx_ratio 로 교체·추가
    orphan_api_ratio 기준 5초 -> 5분 (정상 로그인 오탐 방지)
  - session_id 를 '파일명__IP' 로 저장 -> 팀원 6명(6개 IP)이 각각 별도 세션이 되어
    02_train_rf.py 의 Session Split(데이터 누수 방지)이 가능해짐
"""

import argparse
import datetime
import json
import pathlib
import re
import sys

import numpy as np
import pandas as pd

# 콘솔 UTF-8 설정
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

STATIC_EXTS = ('.png', '.jpg', '.jpeg', '.gif', '.css', '.js', '.ico', '.woff', '.woff2', '.svg', '.map')

# Apache Combined Log
#   - 시간: 초 단위 또는 밀리초/마이크로초(.123 / .123456) 모두 허용
#   - 타임존(+0000, +0900) 캡처
APACHE_RE = re.compile(
    r'(\S+)\s+\S+\s+\S+\s+'
    r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})(?:[.,](\d{1,6}))?\s*([+-]\d{4})?\]\s+'
    r'"(\S+)\s+([^"\s]+)\s+[^"]*"\s+(\d{3})\s+(\d+|-)\s+"[^"]*"\s+"([^"]*)"'
)

SOURCE_PRIORITY = ["access", "app", "opensearch"]

# 학습에 쓰는 로그 위치 (Wazuh location 필드 기준, 부분 일치)
#   WAF 컨테이너의 logs/waf/access.log 도 Apache 형식이라 섞이면 같은 요청이 두 번 집계되므로 제외
ACCESS_LOG_HINT = "shop_access.log"
APP_LOG_HINT = "app.log"


def _strip_query_ext(path):
    return path.split('?', 1)[0].lower().endswith(STATIC_EXTS)


def parse_apache_time(base, frac, tz):
    """'27/Oct/2026:05:44:13' + '123' + '+0000' -> UTC naive datetime"""
    dt = datetime.datetime.strptime(base, '%d/%b/%Y:%H:%M:%S')
    if frac:
        dt = dt.replace(microsecond=int(frac.ljust(6, '0')))
    if tz:
        sign = 1 if tz[0] == '+' else -1
        offset = datetime.timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * sign
        dt = dt - offset  # UTC 로 변환
    return dt


def _s(row, key):
    """NaN 을 빈 문자열로 처리하는 안전한 컬럼 조회"""
    v = row.get(key, '')
    return '' if pd.isna(v) else str(v).strip()


def to_utc_naive(dt):
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return dt


def parse_wazuh_csv(csv_path):
    """
    Wazuh OpenSearch 에서 내려받은 CSV 를 파싱하여 HTTP 요청 레코드 리스트로 반환.
    각 레코드에 source('access' | 'app' | 'opensearch') 를 표시합니다.
    """
    records = []
    df = pd.read_csv(csv_path, low_memory=False)

    for _, row in df.iterrows():
        raw_full = row.get('_source.full_log', '')
        if pd.isna(raw_full) or not str(raw_full).strip():
            raw_full = row.get('full_log', '')
        full_log = str(raw_full if not pd.isna(raw_full) else '').strip()
        location = _s(row, '_source.location') or _s(row, 'location')

        # 1-1. JSON (app.log 비즈니스 로그)
        if full_log.startswith('{') and full_log.endswith('}'):
            try:
                d = json.loads(full_log)
                ts_str = d.get('timestamp')
                dt = to_utc_naive(datetime.datetime.fromisoformat(ts_str)) if ts_str else None
                path = d.get('path', '')
                if _strip_query_ext(path):
                    continue
                records.append({
                    'timestamp': dt,
                    'client_ip': d.get('client_ip', 'unknown'),
                    'method': d.get('method', 'GET'),
                    'path': path,
                    'status': int(d.get('status', 200)),
                    'response_bytes': int(d.get('response_bytes', 0) or 0),
                    'duration_ms': float(d.get('duration_ms', 0.0) or 0.0),
                    'user_agent': d.get('user_agent', ''),
                    'source': 'app',
                    'location': location,
                })
                continue
            except Exception:
                pass

        # 1-2. Apache Combined Access Log (shop_access.log)
        m = APACHE_RE.match(full_log)
        if m:
            ip, ts_base, frac, tz, method, path, status, bytes_val, ua = m.groups()
            try:
                if _strip_query_ext(path):
                    continue
                records.append({
                    'timestamp': parse_apache_time(ts_base, frac, tz),
                    'client_ip': ip,
                    'method': method,
                    'path': path,
                    'status': int(status),
                    'response_bytes': 0 if bytes_val == '-' else int(bytes_val),
                    'duration_ms': 0.0,
                    'user_agent': ua,
                    'source': 'access',
                    'location': location,
                })
                continue
            except Exception:
                pass

        # 1-3. OpenSearch 분할 컬럼 직접 추출 (Fallback)
        path_col = _s(row, '_source.data.path') or _s(row, '_source.data.url')
        status_col = _s(row, '_source.data.status') or _s(row, '_source.data.id')
        ip_col = _s(row, '_source.data.client_ip') or _s(row, '_source.data.srcip')
        if path_col and status_col.isdigit():
            try:
                clean_ts = _s(row, '_source.@timestamp').replace('@', '').strip()
                dt = datetime.datetime.strptime(clean_ts.split('.')[0], '%b %d, %Y  %H:%M:%S')
                records.append({
                    'timestamp': dt,
                    'client_ip': ip_col or 'unknown',
                    'method': _s(row, '_source.data.method') or 'GET',
                    'path': path_col,
                    'status': int(status_col),
                    'response_bytes': 0,
                    'duration_ms': 0.0,
                    'user_agent': _s(row, '_source.data.user_agent'),
                    'source': 'opensearch',
                    'location': location,
                })
            except Exception:
                pass

    return records


def select_single_source(records):
    """
    같은 요청이 여러 로그에 중복 기록되는 문제를 막기 위해
    파일 안에서 우선순위가 가장 높은 소스 하나만 사용합니다.
    access.log 는 정적파일/PHP페이지/API 를 모두 포함하는 상위집합이므로 1순위입니다.
    """
    # 우리 웹서버 로그(shop_access.log / app.log)가 들어 있으면 그 위치만 사용
    #   -> WAF access.log 등 같은 형식의 다른 로그가 섞여도 이중 집계되지 않음
    #   (외부 공개 데이터셋처럼 위치 이름이 다르면 필터 없이 그대로 사용)
    hints = {'access': ACCESS_LOG_HINT, 'app': APP_LOG_HINT}
    for src, hint in hints.items():
        if any(hint in (r.get('location') or '') for r in records if r['source'] == src):
            records = [r for r in records if r['source'] != src or hint in (r.get('location') or '')]

    counts = {s: sum(1 for r in records if r['source'] == s) for s in SOURCE_PRIORITY}
    chosen = next((s for s in SOURCE_PRIORITY if counts[s] > 0), None)
    if chosen is None:
        return [], counts, None
    return [r for r in records if r['source'] == chosen], counts, chosen


# -------------------------------------------------------------
# Shadow API / IDOR 탐지용 설정
# -------------------------------------------------------------
# 프론트엔드(app.js)와 openapi.yaml 에 '문서화된' API 경로 접두사.
#   이 목록에 없는 /api/ 호출(예: /api/v1/users/{id}, /api/v0, /api/beta)은 Shadow API 접근으로 집계
DOCUMENTED_API_PREFIXES = ("/api/v2/",)
# API 호출 직전 N초 안에 이 IP 가 HTML 페이지를 한 번도 로드하지 않았으면 '페이지 없는 API 직접 호출'로 판단
#   (실제 브라우저는 페이지를 먼저 받고 app.js 가 API 를 호출함 / 에이전트는 API 를 바로 호출)
#   [2026-10-29] 5초 -> 300초(5분): 사람이 login.php 를 열고 아이디/비밀번호를 입력하는 데
#   10~30초가 걸리므로 5초 기준은 정상 로그인(POST /api/v2/login)을 오탐함
ORPHAN_API_SEC = 300.0

ID_IN_PATH_RE = re.compile(r'/(\d+)(?=/|$)')
ID_IN_QUERY_RE = re.compile(r'[?&][A-Za-z_]*id=(\d+)', re.IGNORECASE)


def _extract_ids(path):
    """경로/쿼리에서 숫자 ID 추출 (/api/v1/users/17, product.php?id=3)"""
    base, _, query = path.partition('?')
    ids = [int(x) for x in ID_IN_PATH_RE.findall(base)]
    if query:
        ids += [int(x) for x in ID_IN_QUERY_RE.findall('?' + query)]
    return ids


def _add_request_flags(g):
    """IP 하나의 요청 시계열에 요청 단위 플래그를 추가"""
    g = g.sort_values('timestamp').copy()
    base = g['path'].str.split('?', n=1).str[0]
    g['is_api'] = base.str.startswith('/api/')
    g['is_shadow'] = g['is_api'] & ~base.str.startswith(DOCUMENTED_API_PREFIXES)
    g['is_page'] = ~g['is_api'] & (base.str.endswith('.php') | base.str.endswith('/') | (base == ''))
    g['is_auth_fail'] = g['status'].isin([401, 403])

    # 페이지 없는 API 직접 호출: 직전 ORPHAN_API_SEC 초(5분) 안에 페이지 로드가 한 번도 없었던 API 요청
    t = g['timestamp'].values
    page_t = t[g['is_page'].values]
    orphan = np.zeros(len(g), dtype=bool)
    if g['is_api'].any():
        api_idx = np.where(g['is_api'].values)[0]
        if len(page_t) == 0:
            orphan[api_idx] = True
        else:
            pos = np.searchsorted(page_t, t[api_idx], side='right') - 1
            gap = np.full(len(api_idx), np.inf)
            ok = pos >= 0
            gap[ok] = (t[api_idx][ok] - page_t[pos[ok]]) / np.timedelta64(1, 's')
            orphan[api_idx] = gap > ORPHAN_API_SEC
    g['is_orphan_api'] = orphan
    g['ids'] = g['path'].map(_extract_ids)
    return g


def _window_row(w, window_seconds):
    """30초 창 하나(w)의 피처 계산"""
    n = len(w)
    if n > 1:
        # [버그 수정 1] datetime64 의 내부 단위(ns/us)와 무관하게 '초'로 변환
        intervals = np.diff(w['timestamp'].values) / np.timedelta64(1, 's')
        interval_mean = float(np.mean(intervals))
        interval_std = float(np.std(intervals))
    else:
        interval_mean, interval_std = float(window_seconds), 0.0

    ids = [i for lst in w['ids'] for i in lst]
    if len(ids) >= 2:
        diffs = np.abs(np.diff(ids))
        id_seq_ratio = float((diffs == 1).mean())
    else:
        id_seq_ratio = 0.0
    n_api = int(w['is_api'].sum())
    api_2xx = w['is_api'] & (w['status'] >= 200) & (w['status'] < 300)

    # [2026-10-29 피처 정리] 제거: unique_ua_count(1PC=1고객 이후 항상 1), error_abnormal_ratio(404/401/403 과 중복),
    #   interval_std(interval_cv 와 중복), api_ratio(orphan_api_ratio 와 중복, 사이트 구조 의존)
    #   교체: unique_url_count -> unique_url_ratio, bytes_mean/bytes_max -> api_2xx_bytes_sum
    #   추가: error_5xx_ratio
    return {
        # --- 요청 속도 / 리듬 ---
        'req_count': n,                                                     # 30초 요청 수
        'interval_mean': round(interval_mean, 4),                           # 평균 요청 간격(초)
        'interval_cv': round(interval_std / interval_mean, 4) if interval_mean > 0 else 0.0,  # 간격 변동계수, 낮을수록 기계적
        # --- 탐색 / 에러 ---
        'unique_url_ratio': round(w['path'].nunique() / n, 4),             # 서로 다른 URL 비율 (퍼징 ~1.0, 사람은 재방문으로 낮음)
        'error_404_ratio': round((w['status'] == 404).sum() / n, 4),       # 없는 경로 탐색
        'auth_fail_ratio': round(w['is_auth_fail'].sum() / n, 4),          # 401/403 권한 우회 시도
        'error_5xx_ratio': round((w['status'] >= 500).sum() / n, 4),       # 인젝션 등으로 인한 서버 에러
        # --- Shadow API / IDOR ---
        'shadow_api_ratio': round(w['is_shadow'].sum() / n, 4),            # 문서에 없는 API 접근 비율
        'orphan_api_ratio': round(w['is_orphan_api'].sum() / n_api, 4) if n_api else 0.0,  # 페이지 없이 API 직접 호출
        'unique_id_count': len(set(ids)),                                   # 창 안에서 조회한 서로 다른 ID 수
        'id_seq_ratio': round(id_seq_ratio, 4),                             # 연속 ID(1,2,3..) 열거 비율
        'api_2xx_bytes_sum': int(w.loc[api_2xx, 'response_bytes'].sum()),  # 성공한 API 응답 바이트 합 (유출량)
        # --- 요청 방식 ---
        'ratio_post': round((w['method'] == 'POST').sum() / n, 4),
        'method_nunique': w['method'].nunique(),
    }


def extract_window_features(df_raw, file_stem, window_seconds=30):
    """
    IP별 / 30초 창 단위로 행동 피처를 계산합니다.
    창 경계는 파일 전체의 첫 요청 시각 기준으로 모든 IP 가 동일하게 맞춰집니다.
    요청이 없는 창은 만들지 않습니다.
    """
    if df_raw.empty:
        return pd.DataFrame()

    start_time = df_raw['timestamp'].min()
    window = pd.Timedelta(seconds=window_seconds)
    features_list = []

    for ip, ip_group in df_raw.groupby('client_ip'):
        g = _add_request_flags(ip_group)
        session_label = int(g['label'].iloc[0])
        session_id = f"{file_stem}__{ip}"
        g['window_idx'] = ((g['timestamp'] - start_time) // window).astype(int)

        for widx, w in g.groupby('window_idx', sort=True):
            row = {
                'session_id': session_id,
                'window_idx': int(widx),
                'client_ip': ip,
                'window_start': (start_time + widx * window).strftime('%Y-%m-%d %H:%M:%S'),
            }
            row.update(_window_row(w, window_seconds))
            row['label'] = session_label  # 0: 정상, 1: 공격
            features_list.append(row)

    return pd.DataFrame(features_list)


def main():
    # 경로 기본값은 '실행한 현재 폴더' 기준 (스크립트 위치와 무관)
    cwd = pathlib.Path.cwd()

    ap = argparse.ArgumentParser(description="Wazuh 원본 로그 -> 30초 창 피처 추출")
    ap.add_argument("--raw-dir", default=str(cwd / "raw_logs"), help="원본 CSV 폴더 (기본: ./raw_logs)")
    ap.add_argument("--out-dir", default=str(cwd / "features"), help="피처 저장 폴더 (기본: ./features)")
    ap.add_argument("--window", type=int, default=30, help="시간 창 크기(초), 기본 30")
    ap.add_argument("--attack-ips", nargs="*", default=None,
                    help="공격자 IP 목록. 파일명에 'mixed' 가 들어간 파일에만 적용 (정상/공격이 섞인 로그)")
    ap.add_argument("--benign-ips", nargs="*", default=None,
                    help="정상(팀원 PC) IP 목록. 지정하면 mixed 파일에서 두 목록 어디에도 없는 IP 는 제외")
    ap.add_argument("--exclude-ips", nargs="*", default=["127.0.0.1"],
                    help="제외할 IP (기본: 127.0.0.1 아파치 내부 더미 연결)")
    args = ap.parse_args()

    raw_dir = pathlib.Path(args.raw_dir)
    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    attack_ips = set(args.attack_ips or [])
    benign_ips = set(args.benign_ips or [])

    print("=" * 65)
    print("[Wazuh 원본 로그 -> IP별 30초 창 머신러닝 특징값 추출]")
    print(f" * 원천 로그 폴더 : {raw_dir}")
    print(f" * 저장 폴더      : {out_dir}")
    print(" * 라벨링 방식    : 파일명에 mixed -> IP 목록 / 그 외 -> 파일명(attack/pentagi 포함 시 공격)")
    if attack_ips:
        print(f" * 공격 IP        : {sorted(attack_ips)}")
    if benign_ips:
        print(f" * 정상 IP        : {sorted(benign_ips)}")
    print("=" * 65)

    csv_files = sorted(raw_dir.glob("*.csv"))
    if not csv_files:
        print("[ERROR] 처리할 CSV 파일이 raw_logs 폴더에 없습니다.")
        return

    saved = []
    for f in csv_files:
        fname = f.name.lower()
        is_mixed = "mixed" in fname
        file_label = 1 if ("attack" in fname or "pentagi" in fname) else 0
        if is_mixed and not attack_ips:
            print(f"\n[ERROR] {f.name} 는 mixed 파일인데 --attack-ips 가 없습니다. 공격자 IP 를 지정하세요. (건너뜀)")
            continue
        print(f"\n[FILE] {f.name}")

        records = parse_wazuh_csv(f)
        records, counts, chosen = select_single_source(records)
        print(f"   - 소스별 레코드: access={counts['access']}, app={counts['app']}, opensearch={counts['opensearch']}"
              f"  -> 사용: {chosen} (중복 집계 방지)")
        if not records:
            print("   - 유효한 데이터가 없습니다.")
            continue

        df_raw = pd.DataFrame(records)
        df_raw['timestamp'] = pd.to_datetime(df_raw['timestamp'])
        df_raw = df_raw.dropna(subset=['timestamp'])
        df_raw = df_raw[~df_raw['client_ip'].isin(args.exclude_ips)]

        if is_mixed:
            if benign_ips:
                known = attack_ips | benign_ips
                unknown = df_raw.loc[~df_raw['client_ip'].isin(known), 'client_ip'].value_counts()
                for ip, n in unknown.items():
                    print(f"   - [제외] 목록에 없는 IP {ip} ({n}건)")
                df_raw = df_raw[df_raw['client_ip'].isin(known)]
            missing = attack_ips - set(df_raw['client_ip'])
            if missing:
                print(f"   - [주의] 지정한 공격 IP 가 이 파일에 없습니다: {sorted(missing)}")
            df_raw['label'] = df_raw['client_ip'].isin(attack_ips).astype(int)
            print("   - 라벨링: IP 목록 기준 (mixed)")
        else:
            df_raw['label'] = file_label

        # 밀리초 정보가 있는지 진단 (없으면 interval 피처 정밀도가 낮음)
        has_subsec = (df_raw['timestamp'].dt.microsecond != 0).mean()
        if has_subsec < 0.05:
            print("   - [주의] 타임스탬프가 초 단위입니다. Apache LogFormat 에 밀리초 추가를 권장합니다.")

        df_feat = extract_window_features(df_raw, f.stem, window_seconds=args.window)
        if df_feat.empty:
            print("   - 유효한 데이터가 없습니다.")
            continue

        out_csv = out_dir / f"{f.stem}_features.csv"
        df_feat.to_csv(out_csv, index=False, encoding='utf-8-sig')
        per_ip = df_feat.groupby(['client_ip', 'label']).size()
        for (ip, lb), n in per_ip.items():
            print(f"   - {ip:<16} label={lb}  창 {n}개")
        print(f"   -> 저장: {out_csv.name}")
        saved.append((out_csv, df_feat))

    if saved:
        print("\n" + "=" * 65)
        print(f"[SUCCESS] 피처 파일 {len(saved)}개 저장 완료")
        for out_csv, df_feat in saved:
            vc = df_feat['label'].value_counts().to_dict()
            print(f" - {out_csv.name:<58} : 정상 {vc.get(0, 0)} / 공격 {vc.get(1, 0)} 창")
        print("=" * 65)


if __name__ == "__main__":
    main()
