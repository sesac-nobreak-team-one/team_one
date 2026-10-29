"""
build_label_rules.py — 원본 로그 + 공격 실행 기록 + 정상 manifest 를 보고 01b 규칙표를 자동으로 만든다

손으로 규칙표(labels/*_rules.csv)를 쓰지 않아도 되도록, 아래 순서로 판단합니다.

[공격] attack_runs.csv 에 적힌 IP 의 요청
  1) User-Agent 별로 묶고, 각 UA 의 요청이 어느 도구의 실행 시간 안에 가장 많이 들어가는지 보고 UA -> 도구 를 정함
     (같은 PC 에서 kali-claude 와 ARTEX 를 겹치게 돌려도 UA 로 분리: curl/8.8.0 -> claude, norma/0.4 -> artex)
     - 어느 실행 시간에도 안 들어가는 UA (1회성 curl 등) -> 제외
     - 도구들이 겹치는 시간에만 나온 UA -> 지난번 판단 기록(labels/ua_tool_map.json)을 사용,
       기록도 없으면 제외하고 경고 (attack_runs.csv 의 ua 칸에 UA 일부를 적으면 해결)
     - 확실하게 판단한 UA(단독 실행 구간 80% 이상, 5건 이상) 는 ua_tool_map.json 에 기록해 다음에 재사용
  2) 도구의 실행마다 세션 1개: <도구>_<MMDD>_r<번호>  (실행 시간 앞뒤 --buffer-min 분 여유)
  3) 그 UA 의 요청인데 실행 기록 밖에 있으면 '기록에 없는 실행'으로 따로 세션: <도구>_<MMDD>_x<번호> (경고 출력)
     --drop-unlogged 를 주면 대신 제외

[정상] 공격 IP 가 아닌 IP 의 요청
  1) (IP, UA) 별로 묶고, --gap-min 분 넘게 끊기면 다른 실행으로 나눔 (생성기 이탈 시간은 최대 90초)
  2) 브라우저 UA(Mozilla) 가 아닌 요청, --exclude-ua 에 걸리는 UA (Claude 앱 브라우저 등) -> 제외
  3) 요청이 --min-requests 건 미만인 조각 (서버 점검 요청 등), 5xx 비율이 --max-5xx 이상인 조각 (서버 장애 중) -> 제외
  4) manifest 와 IP·시간이 겹치면 이름을 benign_m<팀원>_<기기> 로, 없으면 benign_ip<끝자리>_<기기>

attack_runs.csv 형식 (시각은 KST, 날짜+시간 필수)
  tool,ip,start,end,result,ua,note
  #도구(소문자: claude/artex/pentagi),공격PC IP,YYYY-MM-DD HH:MM (KST),YYYY-MM-DD HH:MM (KST),...   <- '#' 줄은 무시
  claude,192.168.0.27,2026-10-29 13:10,2026-10-29 14:22,,,kali-claude
  artex,192.168.0.27,2026-10-29 14:19,2026-10-29 14:36,fail,,
  - tool : 공격 계열 이름. 소문자/숫자만 (pentagi, artex, claude ...). 03_train_eval.py 의 '처음 보는 도구' 평가 단위
  - ua   : (선택) 이 실행의 UA 에 포함된 문자열. 자동 판단이 애매할 때만 적음

실행 예시 (ml/data 폴더에서)
  python ../src/원유찬/build_label_rules.py --raw raw_logs/mixed_1029_1309-1517.csv
  -> labels/mixed_1029_1309-1517_rules.csv  (확인 후 01b_label_sessions.py 로 피처 추출)
"""

import argparse
import datetime
import json
import importlib.util
import pathlib
import re
import sys
import tempfile

import pandas as pd

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = pathlib.Path(__file__).resolve().parent
TOOL_RE = re.compile(r"^[a-z0-9]+$")
DATETIME_RE = re.compile(r"^\d{4}[-/.]\d{1,2}[-/.]\d{1,2}\s+\d{1,2}:\d{2}(:\d{2})?$")


def load_preprocess():
    spec = importlib.util.spec_from_file_location("preprocess01", HERE / "01_preprocess.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def tz_offset(text):
    sign = 1 if text[0] == "+" else -1
    t = text[1:].replace(":", "")
    return datetime.timedelta(hours=sign * int(t[:2]), minutes=sign * int(t[2:4]))


def load_requests(raw_path, tz):
    """01_preprocess 와 같은 방식으로 파싱 (중복 행 제거, 소스 하나만). timestamp 는 KST(naive) 로 변환"""
    pre = load_preprocess()
    src = pd.read_csv(raw_path, low_memory=False).drop_duplicates()
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as tmp:
        src.to_csv(tmp.name, index=False)
        tmp_path = tmp.name
    records = pre.parse_wazuh_csv(tmp_path)
    records, _, chosen = pre.select_single_source(records)
    pathlib.Path(tmp_path).unlink(missing_ok=True)
    df = pd.DataFrame(records)
    if df.empty:
        sys.exit(f"[ERROR] {raw_path} 에서 요청을 하나도 읽지 못했습니다.")
    df["ts"] = pd.to_datetime(df["timestamp"]) + tz
    df["user_agent"] = df["user_agent"].fillna("")
    return df.sort_values("ts").reset_index(drop=True), chosen


def load_attack_runs(path):
    p = pathlib.Path(path)
    cols = ["tool", "ip", "start", "end", "result", "ua", "note"]
    if not p.is_file():
        print(f"[주의] 공격 기록 파일이 없습니다: {p}  -> 모든 IP 를 정상 후보로 처리합니다.")
        return pd.DataFrame(columns=cols)
    # 엑셀 저장 형식(CP949, 탭 구분, 빈 행)도 읽도록 pipeline_core 의 관대한 읽기 사용
    sys.path.insert(0, str(HERE))
    import pipeline_core as pc
    try:
        table = pc.read_attack_table(p)
    except pc.PipelineError as e:
        sys.exit(f"[ERROR] {e}")
    if not table:
        return pd.DataFrame(columns=cols)
    runs = pd.DataFrame([{c: row.get(c, "") for c in cols} for _, row in table],
                        index=[lineno for lineno, _ in table]).fillna("")
    runs["tool"] = runs["tool"].str.strip().str.lower()
    bad = runs[~runs["tool"].str.match(TOOL_RE)]
    if len(bad):
        sys.exit(f"[ERROR] tool 이름은 소문자/숫자만 가능합니다 (밑줄 X): "
                 + ", ".join(f"{i}줄 '{v}'" for i, v in bad["tool"].items()))
    runs["ip"] = runs["ip"].str.strip()
    # 날짜 없이 시간만 쓰면 pandas 가 '오늘 날짜'로 해석해 라벨이 조용히 틀어지므로 날짜+시간을 강제
    for col in ["start", "end"]:
        runs[col] = runs[col].str.strip()
        bad = runs[~runs[col].str.match(DATETIME_RE)]
        if len(bad):
            rows = ", ".join(f"{i}줄 '{v}'" for i, v in bad[col].items())
            sys.exit(f"[ERROR] {p.name} 의 {col} 에 날짜+시간이 필요합니다 (예: 2026-10-29 13:10): {rows}")
    runs["start"] = pd.to_datetime(runs["start"].str.replace(r"[/.]", "-", regex=True))
    runs["end"] = pd.to_datetime(runs["end"].str.replace(r"[/.]", "-", regex=True))
    if (runs["end"] <= runs["start"]).any():
        sys.exit(f"[ERROR] end 가 start 보다 빠른 실행이 있습니다:\n{runs[runs.end <= runs.start]}")
    n0 = len(runs)
    runs = runs.drop_duplicates(subset=["tool", "ip", "start", "end", "ua"])
    if len(runs) < n0:
        print(f"[주의] {p.name} 에 똑같은 공격 기록이 {n0 - len(runs)}줄 중복돼 있어 한 번만 사용합니다.")
    return runs.sort_values(["tool", "start"]).reset_index(drop=True)


def load_manifests(folder, tz):
    rows = []
    for f in sorted(pathlib.Path(folder).glob("*.csv")) if pathlib.Path(folder).is_dir() else []:
        try:
            m = pd.read_csv(f, encoding="utf-8-sig")
        except Exception:
            continue
        if m.empty or "start_utc" not in m.columns:
            continue
        rows.append({
            "file": f.name, "member": str(m["member"].iloc[0]) if "member" in m.columns else "?",
            "ip": str(m["local_ip"].iloc[0]) if "local_ip" in m.columns else "",
            "device": str(m["device"].iloc[0]) if "device" in m.columns else "",
            "start": pd.to_datetime(m["start_utc"]).min() + tz,
            "end": pd.to_datetime(m["end_utc"]).max() + tz,
            "requests": int(m["requests"].sum()) if "requests" in m.columns else None,
        })
    return pd.DataFrame(rows)


def ua_short(ua):
    u = ua.lower()
    for key, name in [("iphone", "iphone"), ("android", "android"), ("edg/", "edge"), ("macintosh", "mac"),
                      ("firefox", "firefox"), ("chrome", "chrome"), ("safari", "safari")]:
        if key in u:
            return name
    return re.sub(r"[^a-z0-9]", "", u.split("/")[0])[:10] or "ua"


def split_by_gap(ts, gap):
    """시각 배열을 gap 보다 긴 공백에서 나눈 (시작 인덱스, 끝 인덱스) 목록"""
    seg, start = [], 0
    for i in range(1, len(ts)):
        if ts[i] - ts[i - 1] > gap:
            seg.append((start, i - 1))
            start = i
    seg.append((start, len(ts) - 1))
    return seg


def fmt(t):
    return pd.Timestamp(t).strftime("%Y-%m-%d %H:%M:%S")


def build(df, runs, manifests, args, ua_map=None, learned=None):
    ua_map = ua_map or {}
    learned = learned if learned is not None else {}
    buf = pd.Timedelta(minutes=args.buffer_min)
    gap = pd.Timedelta(minutes=args.gap_min)
    one = pd.Timedelta(seconds=1)
    rules, excluded, warnings = [], [], []

    def exclude(ip, ua, g, why):
        excluded.append({"ip": ip, "ua": ua[:60], "n": len(g), "from": g.ts.min(), "to": g.ts.max(), "why": why})

    # ---------------- 공격 ----------------
    attack_ips = sorted(runs["ip"].unique())
    for ip in attack_ips:
        r_ip = runs[runs.ip == ip].copy()
        # 같은 도구의 실행끼리 여유 시간이 겹치지 않도록 잘라서 유효 구간 계산
        r_ip["s_eff"], r_ip["e_eff"] = r_ip["start"] - buf, r_ip["end"] + buf
        for tool, g in r_ip.groupby("tool"):
            idx = g.sort_values("start").index.tolist()
            for a, b in zip(idx, idx[1:]):
                mid = r_ip.at[a, "end"] + (r_ip.at[b, "start"] - r_ip.at[a, "end"]) / 2
                if r_ip.at[a, "e_eff"] > r_ip.at[b, "s_eff"]:
                    r_ip.at[a, "e_eff"] = r_ip.at[b, "s_eff"] = max(mid, r_ip.at[a, "end"])
        # 실행 번호(r1, r2 ...)는 main 에서 attack_runs.csv 전체 기준으로 매김 (로그를 잘라 뽑아도 같은 실행 = 같은 이름)

        req = df[df.client_ip == ip]
        if req.empty:
            warnings.append(f"공격 IP {ip} 의 요청이 이 로그에 없습니다.")
            continue
        for ua, g in req.groupby("user_agent"):
            # 실행에 ua 힌트가 있으면 그 실행만 후보
            cand = r_ip[(r_ip.ua == "") | r_ip.ua.apply(lambda h: bool(h) and h in ua)]
            # 요청마다 '그 시각에 실행 중이던 도구' 집합을 구하고,
            # 도구가 하나뿐인 시각(겹치지 않는 구간)의 요청 수로 UA -> 도구 판단
            active = pd.DataFrame({t: pd.Series(False, index=g.index) for t in cand.tool.unique()})
            for _, run in cand.iterrows():
                active[run.tool] |= (g.ts >= run.s_eff) & (g.ts < run.e_eff)
            n_active = active.sum(axis=1)
            solo = {t: int((active[t] & (n_active == 1)).sum()) for t in active.columns}
            total = {t: int(active[t].sum()) for t in active.columns}
            solo = {k: v for k, v in solo.items() if v > 0}
            total = {k: v for k, v in total.items() if v > 0}
            if not total:
                exclude(ip, ua, g, "공격 IP 지만 어느 실행 시간에도 없음")
                continue
            hinted = len(cand) < len(r_ip) and cand.ua.ne("").any()
            known = ua_map.get(ua)
            tool = None
            # 판단 순서: attack_runs.csv 의 ua 힌트 > 도구 단독 실행 구간 > 지난번 판단 기록(ua_tool_map) > 판단 불가
            if hinted and len(total) == 1:
                tool = next(iter(total))
            elif solo:
                best = max(solo.values())
                tops = [k for k, v in solo.items() if v == best]
                if len(tops) == 1:
                    tool = tops[0]
                    share = best / sum(solo.values())
                    if share < 0.8:
                        warnings.append(f"{ip} UA '{ua[:40]}' 는 도구 단독 실행 구간에서 {solo} 로 나뉩니다. "
                                        f"'{tool}' 로 판단했지만 확인하세요 (attack_runs.csv 의 ua 칸으로 지정 가능).")
                    elif best >= 5 and "mozilla" not in ua.lower():
                        if known and known != tool:
                            warnings.append(f"UA '{ua[:40]}' 를 이번엔 '{tool}' 로 판단했는데 지난 기록은 '{known}' 입니다. 확인하세요.")
                        elif not known:
                            learned[ua] = tool
            if tool is None and known in total:
                tool = known
                warnings.append(f"{ip} UA '{ua[:40]}' 는 이 로그에서 도구들이 겹쳐 구분이 안 돼, "
                                f"지난 판단 기록(ua_tool_map.json)대로 '{tool}' 로 넣었습니다.")
            if tool is None:
                exclude(ip, ua, g, f"두 도구가 겹치는 시간에만 있음 {total} -> attack_runs.csv 의 ua 칸에 UA 일부를 적어 지정")
                continue
            if "mozilla" in ua.lower():
                warnings.append(f"{ip} 의 브라우저 UA '{ua[:50]}' 를 공격({tool})으로 넣었습니다. "
                                "공격 PC 에서 사람이 브라우저를 쓴 거라면 attack_runs.csv 의 ua 칸으로 도구 UA 를 지정하세요.")
            covered = pd.Series(False, index=g.index)
            for _, run in r_ip[r_ip.tool == tool].iterrows():
                m = (g.ts >= run.s_eff) & (g.ts < run.e_eff)
                if not m.any():
                    continue
                covered |= m
                rules.append({"ip": ip, "ua_contains": ua, "start": fmt(run.s_eff), "end": fmt(run.e_eff),
                              "label": 1, "session": f"{tool}_{run.mmdd}_r{run.rnum}",
                              "note": f"{tool} {run.start:%H:%M}-{run.end:%H:%M} {run.result}".strip()
                                      + f" / {int(m.sum())}건"})
            rest = g[~covered]
            if len(rest):
                if args.drop_unlogged:
                    exclude(ip, ua, rest, f"{tool} UA 지만 실행 기록 밖 (--drop-unlogged)")
                else:
                    ts = rest.ts.tolist()
                    for k, (i, j) in enumerate(split_by_gap(ts, gap), 1):
                        seg = rest.iloc[i:j + 1]
                        mmdd = seg.ts.min().strftime("%m%d")
                        name = f"{tool}_{mmdd}_x{k}"
                        rules.append({"ip": ip, "ua_contains": ua, "start": fmt(seg.ts.min() - one),
                                      "end": fmt(seg.ts.max() + one), "label": 1, "session": name,
                                      "note": f"실행 기록에 없음 / {len(seg)}건"})
                        warnings.append(f"{tool} UA 요청 {len(seg)}건이 실행 기록 밖에 있습니다 "
                                        f"({seg.ts.min():%H:%M}~{seg.ts.max():%H:%M}) -> {name} 로 넣음. "
                                        "기록이 빠진 거면 attack_runs.csv 에 추가하세요.")

        if not manifests.empty and (manifests.ip == ip).any():
            warnings.append(f"공격 IP {ip} 에서 정상 생성기도 돌렸습니다 (manifest 있음). 같은 IP 라 구분이 어려울 수 있습니다.")

    # ---------------- 정상 ----------------
    used = {}
    for (ip, ua), g in df[~df.client_ip.isin(attack_ips)].groupby(["client_ip", "user_agent"]):
        if "mozilla" not in ua.lower():
            exclude(ip, ua, g, "브라우저 UA 아님 (수동 curl/스크립트)")
            continue
        hit = next((p for p in args.exclude_ua if p in ua), None)
        if hit:
            exclude(ip, ua, g, f"제외 UA ({hit})")
            continue
        # 공백으로 조각을 나눠 이상한 조각(점검 요청, 서버 장애 중)만 걸러내고,
        # 남은 조각은 '같은 사람·같은 기기' = 세션 하나로 묶음 (같은 사람이 학습/검증에 동시에 들어가지 않도록)
        keep = []
        for i, j in split_by_gap(g.ts.tolist(), gap):
            seg = g.iloc[i:j + 1]
            if len(seg) < args.min_requests:
                exclude(ip, ua, seg, f"요청 {len(seg)}건 < {args.min_requests} (점검 요청/잠깐 접속)")
                continue
            r5 = float((seg.status >= 500).mean())
            if r5 >= args.max_5xx:
                exclude(ip, ua, seg, f"5xx 비율 {r5:.0%} (서버 장애 중 수집)")
                continue
            keep.append(seg)
        if not keep:
            continue
        s_all, e_all = min(k.ts.min() for k in keep), max(k.ts.max() for k in keep)
        man = manifests[(manifests.ip == ip) & (manifests.start <= e_all + buf) & (manifests.end >= s_all - buf)] \
            if not manifests.empty else manifests
        if len(man):
            base = f"benign_m{man.iloc[0].member}_{ua_short(ua)}"
            mnote = "manifest " + ", ".join(f"{r.start:%H:%M}~{r.end:%H:%M}(기록 {r.requests}건)" for r in man.itertuples())
        else:
            base = f"benign_ip{ip.split('.')[-1]}_{ua_short(ua)}"
            mnote = "manifest 없음"
        used[base] = used.get(base, 0) + 1
        name = base if used[base] == 1 else f"{base}{used[base]}"
        for seg in keep:
            rules.append({"ip": ip, "ua_contains": ua, "start": fmt(seg.ts.min() - one), "end": fmt(seg.ts.max() + one),
                          "label": 0, "session": name, "note": f"{mnote} / 로그 {len(seg)}건"})

    return pd.DataFrame(rules), pd.DataFrame(excluded), warnings


def main():
    ap = argparse.ArgumentParser(description="공격 기록 + manifest 로 01b 규칙표 자동 생성")
    ap.add_argument("--raw", required=True, help="00_export_archives.py 로 뽑은 원본 CSV")
    ap.add_argument("--attack-runs", default=str(pathlib.Path.cwd() / "attack_runs.csv"),
                    help="공격 실행 기록 CSV (기본: ./attack_runs.csv)")
    ap.add_argument("--manifests", default=str(pathlib.Path.cwd() / "manifests"),
                    help="정상 생성기 manifest 폴더 (기본: ./manifests)")
    ap.add_argument("--out", default=None, help="규칙표 저장 경로 (기본: ./labels/<원본이름>_rules.csv)")
    ap.add_argument("--tz", default="+09:00", help="공격 기록/규칙표 시각의 타임존 (기본 KST)")
    ap.add_argument("--buffer-min", type=float, default=1.0, help="공격 실행 시간 앞뒤 여유(분)")
    ap.add_argument("--gap-min", type=float, default=10.0, help="이 시간(분) 넘게 끊기면 다른 실행으로 나눔")
    ap.add_argument("--min-requests", type=int, default=5, help="정상 세션 최소 요청 수")
    ap.add_argument("--max-5xx", type=float, default=0.2, help="이 비율 이상 5xx 인 정상 조각은 제외")
    ap.add_argument("--exclude-ua", nargs="*", default=["Claude/", "HeadlessChrome", "python-requests"],
                    help="정상에서 제외할 UA 문자열 (기본: Claude 앱 브라우저, 헤드리스)")
    ap.add_argument("--drop-unlogged", action="store_true", help="실행 기록 밖의 공격 UA 요청을 세션으로 넣지 않고 제외")
    ap.add_argument("--ua-map", default=None,
                    help="UA -> 도구 판단 기록 (기본: 규칙표 폴더의 ua_tool_map.json). "
                         "도구가 겹쳐 실행된 짧은 로그에서 지난번 판단을 재사용")
    args = ap.parse_args()

    tz = tz_offset(args.tz)
    raw = pathlib.Path(args.raw)
    out = pathlib.Path(args.out) if args.out else pathlib.Path.cwd() / "labels" / f"{raw.stem}_rules.csv"

    df, chosen = load_requests(raw, tz)
    runs = load_attack_runs(args.attack_runs)
    # 실행 번호: 도구 + 날짜별로 attack_runs.csv 전체에서 시작 시각 순서 (r1, r2 ...)
    runs["mmdd"] = runs["start"].dt.strftime("%m%d")
    runs = runs.sort_values(["tool", "start"]).reset_index(drop=True)
    runs["rnum"] = runs.groupby(["tool", "mmdd"]).cumcount() + 1
    # 이 로그 시간대와 겹치는 실행만 사용
    lo, hi = df.ts.min(), df.ts.max()
    runs = runs[(runs.end + pd.Timedelta(minutes=args.buffer_min) >= lo) &
                (runs.start - pd.Timedelta(minutes=args.buffer_min) <= hi)].reset_index(drop=True)
    manifests = load_manifests(args.manifests, tz)

    print("=" * 76)
    print(" [규칙표 자동 생성]")
    print("=" * 76)
    print(f" * 원본       : {raw.name}  ({len(df)}건, {lo:%m-%d %H:%M:%S} ~ {hi:%H:%M:%S} KST, 소스 {chosen})")
    print(f" * 공격 기록  : {pathlib.Path(args.attack_runs).name} 중 이 시간대 {len(runs)}건")
    for _, r in runs.iterrows():
        print(f"     - {r.tool:<8} {r.ip:<15} {r.start:%H:%M}~{r.end:%H:%M} {r.result} {('UA~' + r.ua) if r.ua else ''}")
    print(f" * manifest   : {len(manifests)}개 ({pathlib.Path(args.manifests)})")

    ua_map_path = pathlib.Path(args.ua_map) if args.ua_map else out.parent / "ua_tool_map.json"
    try:
        ua_map = json.loads(ua_map_path.read_text(encoding="utf-8"))
    except Exception:
        ua_map = {}
    learned = {}
    rules, excluded, warnings = build(df, runs, manifests, args, ua_map=ua_map, learned=learned)
    if rules.empty:
        sys.exit("[ERROR] 만들어진 규칙이 없습니다.")

    print("\n[세션 규칙]")
    for _, r in rules.iterrows():
        print(f"   {'공격' if r.label else '정상'}  {r.session:<24} {r.ip:<15} {r.start[11:16]}~{r.end[11:16]}"
              f"  UA={r.ua_contains[:28]:<28} {r.note}")
    if len(excluded):
        print("\n[제외]")
        for _, e in excluded.iterrows():
            print(f"   {e.ip:<15} {e.n:>4}건 {e['from']:%H:%M:%S}~{e['to']:%H:%M:%S}  {e.why}  UA={e.ua}")
    if warnings:
        print("\n[확인 필요]")
        for w in warnings:
            print(f"   - {w}")

    out.parent.mkdir(parents=True, exist_ok=True)
    rules[["ip", "ua_contains", "start", "end", "label", "session", "note"]].to_csv(out, index=False, encoding="utf-8-sig")
    if learned:
        ua_map.update(learned)
        ua_map_path.parent.mkdir(parents=True, exist_ok=True)
        ua_map_path.write_text(json.dumps(ua_map, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f" -> UA 판단 기록 추가 ({ua_map_path.name}): " + ", ".join(f"{u[:30]} = {t}" for u, t in learned.items()))
    n_a = rules.loc[rules.label == 1, "session"].nunique()
    n_b = rules.loc[rules.label == 0, "session"].nunique()
    print(f"\n -> 공격 세션 {n_a}개, 정상 세션 {n_b}개 ({len(rules)}줄) 규칙 저장: {out}")
    print("=" * 76)


if __name__ == "__main__":
    main()
