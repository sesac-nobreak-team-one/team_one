"""
01b_label_sessions.py — 한 파일에 정상/여러 공격 도구가 섞인 로그를 '규칙표'로 라벨링해서 피처 추출

01_preprocess.py 의 --attack-ips 는 IP 하나 = 라벨 하나라서 아래 경우를 처리하지 못합니다.
  - 공격 도구 두 개(kali-claude, ARTEX)를 같은 PC(같은 IP)에서, 시간이 겹치게 실행한 경우
  - 같은 정상 PC 에서 생성기를 여러 번(기기를 바꿔) 실행한 경우
  - 같은 IP 에서 학습에 넣으면 안 되는 트래픽(수동 테스트, 1회성 curl 등)이 섞인 경우

그래서 (IP, User-Agent 일부, 시간 구간) -> (라벨, 세션 이름) 규칙표를 받아
요청 하나하나에 세션을 붙이고, 세션마다 30초 창 피처를 계산합니다.
피처 계산 로직은 01_preprocess.py 의 함수를 그대로 가져다 씁니다 (결과 컬럼이 완전히 같음).

규칙표 CSV 컬럼 (예: ml/data/labels/mixed_1029_1309-1517_rules.csv)
  ip, ua_contains, start, end, label, session, note
  - start/end : "YYYY-MM-DD HH:MM:SS" (기본 KST, --tz 로 변경). start 이상 end 미만
  - ua_contains : User-Agent 에 이 문자열이 포함되면 일치 (비우면 UA 무관)
  - session : 세션 이름. 공격은 반드시 '도구이름_' 으로 시작 (03_train_eval.py 가 첫 단어를 공격 계열로 사용)
              예) claude_1029_r1, artex_1029_r2 / 정상은 benign_ 으로 시작 권장
  - 위에서부터 처음 일치하는 규칙 하나만 적용. 어떤 규칙에도 맞지 않는 요청은 학습에서 제외(목록 출력)

출력 session_id = "<session>__<IP>"

실행 예시
  (ml/data 폴더에서 실행)
  python ../src/원유찬/01b_label_sessions.py --raw raw_logs/mixed_1029_1309-1517.csv \
                                           --rules labels/mixed_1029_1309-1517_rules.csv
  -> ./features/labeled_1029_1309-1517_features.csv
  규칙표를 손으로 쓰지 않으려면 build_label_rules.py (또는 run_pipeline.py) 로 자동 생성
     (01_preprocess.py 출력 이름 'mixed_..._features.csv' 와 겹치지 않도록 mixed -> labeled 로 저장)
"""

import argparse
import datetime
import importlib.util
import pathlib
import sys
import tempfile

import pandas as pd

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = pathlib.Path(__file__).resolve().parent


def load_preprocess():
    spec = importlib.util.spec_from_file_location("preprocess01", HERE / "01_preprocess.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def parse_tz(text):
    sign = 1 if text[0] == "+" else -1
    hh, mm = text[1:].replace(":", "")[:2], text[1:].replace(":", "")[2:4]
    return datetime.timedelta(hours=sign * int(hh), minutes=sign * int(mm))


def load_rules(path, tz_offset):
    rules = pd.read_csv(path, encoding="utf-8-sig", dtype=str).fillna("")
    need = {"ip", "ua_contains", "start", "end", "label", "session"}
    if not need.issubset(rules.columns):
        sys.exit(f"[ERROR] 규칙표 컬럼이 부족합니다. 필요: {sorted(need)} / 현재: {list(rules.columns)}")
    # 로그 타임스탬프는 01_preprocess 에서 UTC(naive) 로 통일되므로 규칙 시각도 UTC 로 변환
    rules["start_utc"] = pd.to_datetime(rules["start"]) - tz_offset
    rules["end_utc"] = pd.to_datetime(rules["end"]) - tz_offset
    rules["label"] = rules["label"].astype(int)
    bad = rules[(rules.label == 1) & rules.session.str.startswith("benign")]
    if len(bad):
        sys.exit(f"[ERROR] 공격(label=1) 세션 이름이 benign 으로 시작합니다: {bad.session.tolist()}")
    return rules


def assign_sessions(df, rules):
    df = df.copy()
    df["session"] = ""
    df["label"] = -1
    for _, r in rules.iterrows():
        m = (df["session"] == "") & (df["client_ip"] == r.ip) \
            & (df["timestamp"] >= r.start_utc) & (df["timestamp"] < r.end_utc)
        if r.ua_contains:
            m &= df["user_agent"].str.contains(r.ua_contains, regex=False, na=False)
        df.loc[m, "session"] = r.session
        df.loc[m, "label"] = r.label
    return df


def main():
    ap = argparse.ArgumentParser(description="규칙표(IP+UA+시간)로 세션 라벨링 후 30초 창 피처 추출")
    ap.add_argument("--raw", required=True, help="00_export_archives.py 로 뽑은 원본 CSV")
    ap.add_argument("--rules", required=True, help="규칙표 CSV")
    ap.add_argument("--out", default=None, help="출력 피처 CSV (기본: ./features/<이름>_features.csv)")
    ap.add_argument("--window", type=int, default=30)
    ap.add_argument("--tz", default="+09:00", help="규칙표 시각의 타임존 (기본 KST)")
    args = ap.parse_args()

    pre = load_preprocess()
    raw = pathlib.Path(args.raw)
    out = pathlib.Path(args.out) if args.out else \
        pathlib.Path.cwd() / "features" / (raw.stem.replace("mixed", "labeled") + "_features.csv")

    # 1) 원본 CSV 의 완전 중복 행 제거 (archives 를 두 번 읽은 구버전 추출 파일 대비)
    src = pd.read_csv(raw, low_memory=False)
    n0 = len(src)
    src = src.drop_duplicates()
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as tmp:
        src.to_csv(tmp.name, index=False)
        tmp_path = tmp.name

    # 2) 01_preprocess 와 같은 방식으로 파싱 + 소스 하나만 사용
    records = pre.parse_wazuh_csv(tmp_path)
    records, counts, chosen = pre.select_single_source(records)
    pathlib.Path(tmp_path).unlink(missing_ok=True)
    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.dropna(subset=["timestamp"])

    print("=" * 72)
    print(" [01b] 규칙표 기반 세션 라벨링 + 피처 추출")
    print("=" * 72)
    print(f" * 원본     : {raw.name}  ({n0}행, 중복 제거 {n0 - len(src)}행)")
    print(f" * 사용 소스: {chosen}  (access={counts['access']}, app={counts['app']})")
    print(f" * 규칙표   : {pathlib.Path(args.rules).name}")

    # 3) 규칙 적용
    rules = load_rules(args.rules, parse_tz(args.tz))
    df = assign_sessions(df, rules)

    dropped = df[df["session"] == ""]
    if len(dropped):
        print("\n[제외] 어떤 규칙에도 맞지 않는 요청 (학습에서 뺌)")
        tz = parse_tz(args.tz)
        for (ip, ua), g in dropped.groupby(["client_ip", "user_agent"]):
            print(f"   - {ip:<15} {len(g):>4}건  {(g.timestamp.min() + tz):%H:%M:%S}~{(g.timestamp.max() + tz):%H:%M:%S}  UA={ua[:60]}")
    df = df[df["session"] != ""].copy()

    unused = set(rules.session) - set(df.session)
    if unused:
        print(f"\n[주의] 요청이 하나도 없는 규칙: {sorted(unused)}")

    # 4) 세션별 피처 (창 경계는 파일 전체 기준으로 동일하게 맞춤)
    df["real_ip"] = df["client_ip"]
    df["client_ip"] = df["session"]  # extract_window_features 가 client_ip 로 묶으므로 세션 이름을 넣음
    feat = pre.extract_window_features(df.drop(columns=["session"]), "x", window_seconds=args.window)
    ip_map = df.groupby("session")["real_ip"].first()
    feat["client_ip"] = feat["session_id"].str.split("__", n=1).str[1].map(ip_map)
    feat["session_id"] = feat["session_id"].str.split("__", n=1).str[1] + "__" + feat["client_ip"]

    out.parent.mkdir(parents=True, exist_ok=True)
    feat.to_csv(out, index=False, encoding="utf-8-sig")

    # 5) 요약
    tz = parse_tz(args.tz)
    print("\n[세션 요약]")
    print(f"   {'session_id':<36}{'label':>6}{'창':>5}{'요청':>6}   구간(KST)")
    for sid, g in feat.groupby("session_id", sort=False):
        ts = pd.to_datetime(g.window_start)
        print(f"   {sid:<36}{int(g.label.iloc[0]):>6}{len(g):>5}{int(g.req_count.sum()):>6}"
              f"   {(ts.min() + tz):%H:%M}~{(ts.max() + tz):%H:%M}")
    n_s = feat.groupby("label")["session_id"].nunique().to_dict()
    n_w = feat["label"].value_counts().to_dict()
    print(f"\n -> 정상 세션 {n_s.get(0, 0)}개 / 창 {n_w.get(0, 0)}개,  공격 세션 {n_s.get(1, 0)}개 / 창 {n_w.get(1, 0)}개")
    print(f" -> 저장: {out}")
    print("=" * 72)


if __name__ == "__main__":
    main()
