"""
run_pipeline.py — Wazuh 로그 추출부터 학습/평가까지 한 번에 (PowerShell 화면)

[대화형] 옵션 없이 실행하면 필요한 값을 하나씩 물어봅니다.
  cd D:\\project\\team_one\\ml\\data
  python ..\\src\\원유찬\\run_pipeline.py

  추출 시간 -> 공격 기록(도구, IP, 시작~종료) -> 확인 -> attack_runs.csv 에 저장 -> 추출 -> 규칙표(확인) -> 피처 -> 학습/평가
  - 공격 시각은 '14:03' 처럼 시간만 쳐도 추출 날짜가 자동으로 붙음
  - 공격 PC IP, Wazuh 계정 등은 지난번 값을 기본값으로 보여줌 (Enter = 그대로)

[옵션 실행] 자동화/재실행용 (기존 방식 그대로)
  python ..\\src\\원유찬\\run_pipeline.py --start "2026-10-30 14:00" --end "2026-10-30 14:40"
  python ..\\src\\원유찬\\run_pipeline.py --raw raw_logs\\mixed_1029_1309-1517.csv
  python ..\\src\\원유찬\\run_pipeline.py --raw ... --rules labels\\..._rules.csv
  python ..\\src\\원유찬\\run_pipeline.py --train-only

모든 입출력은 '실행한 현재 폴더'(또는 --workdir) 아래:
  attack_runs.csv, manifests/, raw_logs/, labels/, features/, models/

실제 기능은 pipeline_core.py 에 있고, 이 파일은 입력/출력 화면만 담당합니다 (웹페이지도 같은 core 사용).

SSH 준비 (한 번만)
  ssh-keygen -t ed25519
  type $env:USERPROFILE\\.ssh\\id_ed25519.pub | ssh -p 8822 dongyoung@192.168.0.141 "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
"""

import argparse
import datetime
import getpass
import os
import pathlib
import shlex
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
if hasattr(sys.stdin, "reconfigure"):
    try:
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pipeline_core as pc  # noqa: E402

KNOWN_TOOLS = ["claude", "artex", "pentagi"]
STEP_TITLES = {"export": "Wazuh 로그 추출", "rules": "라벨링 규칙표 자동 생성",
               "features": "30초 창 피처 추출", "train": "학습 / 평가 (./features 전체)"}


def banner(title):
    print("\n" + "=" * 76)
    print(f" {title}")
    print("=" * 76, flush=True)


# =============================================================
# 입력 도우미
# =============================================================
def ask(prompt, default=None, allow_empty=False):
    suffix = f" [{default}]" if default not in (None, "") else ""
    while True:
        try:
            v = input(f"{prompt}{suffix}: ").strip()
        except EOFError:
            print()
            raise SystemExit("\n입력이 끝나 중단합니다.")
        if v:
            return v
        if default not in (None, ""):
            return str(default)
        if allow_empty:
            return ""
        print("  값을 입력하세요.")


def ask_yes(prompt, default=True):
    d = "Y/n" if default else "y/N"
    v = ask(f"{prompt} ({d})", allow_empty=True).lower()
    return default if not v else v in ("y", "yes", "ㅛ", "네", "예", "응")


def ask_time(prompt, base=None, default=None, rng=None):
    """시각 입력. base 가 있으면 시간만 쳐도 그 날짜를 붙임. rng=(s, e) 면 범위 안인지 확인"""
    while True:
        text = ask(prompt, default=default)
        try:
            dt = pc.parse_when(text, base)
        except pc.PipelineError as e:
            print(f"  {e}")
            continue
        if rng:
            fit = pc.fit_into_range(dt, *rng, slack_min=1)
            if fit is None:
                print(f"  추출 범위({rng[0]:%m-%d %H:%M} ~ {rng[1]:%H:%M}) 밖입니다. 다시 입력하세요.")
                continue
            dt = fit
        return dt


# =============================================================
# 대화형
# =============================================================
def interactive(workdir):
    p = pc.paths(workdir)
    st = pc.load_settings(workdir)
    print("=" * 76)
    print(" [AI SIEM] ML 파이프라인 - 대화형 실행")
    print("=" * 76)
    print(f" * 작업 폴더 : {p['workdir']}")
    if not p["manifests"].is_dir():
        print(" * [주의] manifests 폴더가 없습니다. ml/data 폴더에서 실행했는지 확인하세요.")
    print(" * 입력 중 Ctrl+C 를 누르면 중단합니다.\n")

    # ---------- 추출 시간 ----------
    print("[1] 추출 시간 (KST)  예) 2026-10-30 14:00   / 오늘이면 14:00 만")
    today = datetime.date.today()
    start = ask_time("  추출 시작", base=today)
    while True:
        end = ask_time("  추출 종료", base=start)
        if end <= start and end.date() == start.date():
            end += datetime.timedelta(days=1)  # 23:50 ~ 00:20 처럼 자정을 넘는 경우
        if end > start:
            break
        print("  종료가 시작보다 늦어야 합니다.")
    print(f"  -> {start:%Y-%m-%d %H:%M} ~ {end:%Y-%m-%d %H:%M}  ({(end - start).seconds // 60}분)")

    # ---------- 공격 기록 ----------
    try:
        existing = pc.runs_in_range(pc.load_attack_runs(p["attack_runs"]), start, end)
    except pc.PipelineError as e:
        raise SystemExit(f"\n[중단] attack_runs.csv 를 읽을 수 없습니다: {e}")
    print("\n[2] 공격 기록")
    if existing:
        print("  attack_runs.csv 에 이미 이 시간대 기록이 있습니다:")
        for r in existing:
            print(f"    - {r.tool:<8} {r.ip:<15} {r.start:%m-%d %H:%M}~{r.end:%H:%M} {r.result}")
    print("  추가할 공격을 입력하세요. 도구 칸에서 Enter 만 누르면 입력을 끝냅니다.")
    print("  시각은 시간만 (예: 14:03) 쳐도 추출 날짜가 붙습니다.")
    new_runs = []
    last_ip = st.get("attack_ip", "")
    tools_hint = "/".join(dict.fromkeys(KNOWN_TOOLS + [r.tool for r in existing]))
    while True:
        print(f"\n  - 공격 #{len(new_runs) + 1}")
        tool = ask(f"    도구 ({tools_hint})", allow_empty=True).lower()
        if not tool:
            break
        if not pc.TOOL_RE.match(tool):
            print("    도구 이름은 소문자/숫자만 가능합니다 (예: claude, artex, pentagi)")
            continue
        if tool not in tools_hint.split("/") and not ask_yes(f"    '{tool}' 은(는) 처음 쓰는 도구 이름입니다. 맞나요?", True):
            continue
        ip = ask("    공격 PC IP", default=last_ip)
        rs = ask_time("    시작", base=start, rng=(start, end))
        while True:
            re_ = ask_time("    종료", base=rs, rng=(start, end))
            if re_ > rs:
                break
            print("    종료가 시작보다 늦어야 합니다.")
        result = ask("    결과 (success/fail, Enter=생략)", allow_empty=True)
        try:
            run = pc.AttackRun(tool, ip, rs, re_, result=result).validate()
        except pc.PipelineError as e:
            print(f"    {e} -> 이 공격은 다시 입력하세요.")
            continue
        dup = [r for r in existing + new_runs if r.tool == tool and r.ip == ip and r.start < re_ and rs < r.end]
        if dup:
            print("    같은 도구·IP 의 기록과 시간이 겹칩니다: "
                  + ", ".join(f"{r.start:%H:%M}~{r.end:%H:%M}" for r in dup))
            if not ask_yes("    그래도 추가할까요? (이미 기록된 실행이면 n)", False):
                continue
        new_runs.append(run)
        last_ip = ip
        tools_hint = "/".join(dict.fromkeys(tools_hint.split("/") + [tool]))

    if not new_runs and not existing:
        print("\n  [주의] 공격 기록이 없습니다. 모든 IP 를 정상으로 처리합니다 (정상 데이터만 수집한 경우).")

    # ---------- Wazuh 접속 ----------
    print("\n[3] Wazuh 접속 (Enter = 기본값)")
    wz = pc.WazuhConfig(host=ask("  주소", st.get("host", "192.168.0.141")),
                        port=ask("  SSH 포트", st.get("port", "8822")),
                        user=ask("  계정", st.get("user", "dongyoung")))

    # ---------- 확인 ----------
    name = pc.default_raw_name(start, end)
    banner("확인")
    print(f"  추출     : {start:%Y-%m-%d %H:%M} ~ {end:%Y-%m-%d %H:%M}  ->  raw_logs\\{name}.csv")
    print(f"  Wazuh    : {wz.user}@{wz.host}:{wz.port}")
    print("  공격 기록:")
    for r in existing:
        print(f"    (기존) {r.tool:<8} {r.ip:<15} {r.start:%H:%M}~{r.end:%H:%M} {r.result}")
    for r in new_runs:
        print(f"    (추가) {r.tool:<8} {r.ip:<15} {r.start:%H:%M}~{r.end:%H:%M} {r.result}")
    if (p["raw_logs"] / f"{name}.csv").exists():
        print(f"  [주의] raw_logs\\{name}.csv 가 이미 있어 덮어씁니다.")
    if not ask_yes("\n  이대로 진행할까요?", True):
        raise SystemExit("취소했습니다.")

    # ---------- 저장 ----------
    if new_runs:
        while True:
            try:
                pc.append_attack_runs(p["attack_runs"], new_runs)
                print(f"  -> attack_runs.csv 에 {len(new_runs)}줄 추가")
                break
            except pc.PipelineError as e:
                print(f"  {e}")
                if not ask_yes("  다시 시도할까요?", True):
                    raise SystemExit("중단했습니다. (입력한 공격 기록은 저장되지 않았습니다)")
    pc.save_settings(workdir, host=wz.host, port=wz.port, user=wz.user,
                     attack_ip=new_runs[-1].ip if new_runs else st.get("attack_ip"))

    wz.sudo_password = getpass.getpass(f"\n  [sudo] {wz.user}@{wz.host} 의 sudo 비밀번호 (NOPASSWD 면 Enter): ")

    # ---------- 실행: 추출 -> 규칙표 (확인) -> 피처 -> 학습 ----------
    try:
        banner(f"[1/4] {STEP_TITLES['export']}")
        raw = pc.export_logs(workdir, start, end, wazuh=wz, name=name)
        banner(f"[2/4] {STEP_TITLES['rules']}")
        rules = pc.build_rules(workdir, raw)
        if not ask_yes("\n  위 규칙표로 계속 진행할까요? (n = 여기서 멈추고 규칙표를 직접 수정)", True):
            print(f"\n  규칙표: {rules}\n  수정한 뒤 이어서 실행:\n"
                  f"    python {pathlib.Path(__file__).resolve()} --raw \"{raw}\" --rules \"{rules}\"")
            return
        finish(workdir, raw, rules, train_args=())
    except pc.PipelineError as e:
        raise SystemExit(f"\n[중단] {e}")


def finish(workdir, raw, rules, train_args):
    banner(f"[3/4] {STEP_TITLES['features']}")
    pc.extract_features(workdir, raw, rules)
    banner(f"[4/4] {STEP_TITLES['train']}")
    rep = pc.train_eval(workdir, extra_args=train_args)
    summarize(workdir, rep)


def summarize(workdir, rep):
    if not rep:
        return
    banner("요약")
    rf = rep.get("cv", {}).get("rf", {})
    ses = rep.get("session", {})
    if rf:
        print(f"  창 단위   재현율 {rf.get('recall', 0):.1%}  오탐률 {rf.get('fpr', 0):.1%}  PR-AUC {rf.get('pr_auc') or 0:.3f}")
    if ses:
        print(f"  세션 단위 공격 탐지 {ses.get('attack_detect', 0):.0%}  TTD 중앙값 {ses.get('ttd_median_sec', 0):.0f}초"
              f"  정상 오경보 {ses.get('benign_false_alarm', 0):.0%}")
    for w in rep.get("warnings") or []:
        print(f"  [경고] {w.splitlines()[0]}")
    print(f"\n  결과 폴더: {pc.paths(workdir)['models']}")


# =============================================================
# 옵션 실행
# =============================================================
def main():
    if len(sys.argv) == 1:
        try:
            interactive(pathlib.Path.cwd())
        except KeyboardInterrupt:
            print("\n중단했습니다.")
        return

    ap = argparse.ArgumentParser(description="Wazuh 추출 -> 라벨링 -> 피처 -> 학습/평가 (옵션 없이 실행하면 대화형)")
    ap.add_argument("--interactive", action="store_true", help="대화형으로 실행 (--workdir 와 함께 쓸 때)")
    ap.add_argument("--start", help='추출 시작 (KST) "YYYY-MM-DD HH:MM"')
    ap.add_argument("--end", help='추출 종료 (KST) "YYYY-MM-DD HH:MM" (시간만 쓰면 시작 날짜)')
    ap.add_argument("--name", default=None, help="원본 파일 이름 (기본: mixed_MMDD_HHMM-HHMM)")
    ap.add_argument("--raw", default=None, help="이미 받은 원본 CSV 로 시작 (추출 생략)")
    ap.add_argument("--rules", default=None, help="자동 생성 대신 이 규칙표 사용")
    ap.add_argument("--train-only", action="store_true", help="./features 로 학습/평가만")
    ap.add_argument("--stop-after", choices=pc.STEPS[:-1], default=None, help="이 단계까지만 실행")
    ap.add_argument("--workdir", default=None, help="작업 폴더 (기본: 현재 폴더)")
    ap.add_argument("--host", default=None, help="Wazuh SSH 주소 (기본: 지난번 값 또는 192.168.0.141)")
    ap.add_argument("--port", default=None, help="SSH 포트 (기본: 지난번 값 또는 8822)")
    ap.add_argument("--user", default=None, help="Wazuh 계정 (기본: 지난번 값 또는 dongyoung)")
    ap.add_argument("--identity", default=None, help="SSH 개인키 경로")
    ap.add_argument("--train-args", default="", help='03_train_eval.py 옵션 (예: "--target-fpr 0.02 --alert-k 3")')
    args = ap.parse_args()

    workdir = pathlib.Path(args.workdir).resolve() if args.workdir else pathlib.Path.cwd()
    workdir.mkdir(parents=True, exist_ok=True)
    if args.interactive:
        try:
            interactive(workdir)
        except KeyboardInterrupt:
            print("\n중단했습니다.")
        return

    print(f" * 작업 폴더 : {workdir}")
    train_args = shlex.split(args.train_args)
    try:
        if args.train_only:
            banner(f"[4/4] {STEP_TITLES['train']}")
            summarize(workdir, pc.train_eval(workdir, extra_args=train_args))
            return
        st = pc.load_settings(workdir)
        wz = pc.WazuhConfig(host=args.host or st.get("host", "192.168.0.141"),
                            port=args.port or st.get("port", "8822"),
                            user=args.user or st.get("user", "dongyoung"), identity=args.identity)
        start = end = None
        if not args.raw:
            if not (args.start and args.end):
                raise SystemExit("[ERROR] --start/--end (추출 시간) 또는 --raw (이미 받은 파일) 가 필요합니다. "
                                 "옵션 없이 실행하면 대화형으로 물어봅니다.")
            start = pc.parse_when(args.start)
            end = pc.parse_when(args.end, start)
            if os.environ.get("WAZUH_SUDO_PASSWORD") is None:
                wz.sudo_password = getpass.getpass(f"[sudo] {wz.user}@{wz.host} 의 sudo 비밀번호 (NOPASSWD 면 Enter): ")

        def on_step(step, path):
            nxt = {"export": "rules", "rules": "features", "features": "train"}.get(step)
            if nxt and args.stop_after != step:
                banner(f"[{pc.STEPS.index(nxt) + 1}/4] {STEP_TITLES[nxt]}")

        if not args.raw:
            banner(f"[1/4] {STEP_TITLES['export']}")
        out = pc.run_all(workdir, start=start, end=end,
                         raw=pathlib.Path(args.raw).resolve() if args.raw else None,
                         rules=pathlib.Path(args.rules).resolve() if args.rules else None,
                         wazuh=wz, name=args.name, stop_after=args.stop_after, train_args=train_args,
                         on_step=on_step)
        pc.save_settings(workdir, host=wz.host, port=wz.port, user=wz.user)
        if args.stop_after == "rules":
            print(f"\n규칙표를 확인/수정한 뒤 이어서 실행:\n"
                  f"  python {pathlib.Path(__file__).resolve()} --raw \"{out['raw']}\" --rules \"{out['rules']}\"")
        summarize(workdir, out.get("report"))
    except pc.PipelineError as e:
        raise SystemExit(f"\n[중단] {e}")


if __name__ == "__main__":
    main()
