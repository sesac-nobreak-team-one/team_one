"""
pipeline_core.py — ML 파이프라인 핵심 기능 (화면/입력 방식과 분리)

PowerShell 대화형(run_pipeline.py) 과 나중에 만들 웹페이지가 같은 함수를 호출하도록 분리한 모듈입니다.
여기 함수들은 input()/print()/sys.exit() 를 쓰지 않습니다.
  - 진행 로그는 log 콜백으로 한 줄씩 넘김 (CLI: print, 웹: 화면/웹소켓으로 전송)
  - 실패는 PipelineError 예외로 알림

단계
  export_logs()      Wazuh 서버에서 로그 추출 (SSH 로 00_export_archives.py 실행 -> scp 다운로드)
  build_rules()      공격 기록 + manifest 로 라벨링 규칙표 자동 생성 (build_label_rules.py)
  extract_features() 규칙표대로 30초 창 피처 추출 (01b_label_sessions.py)
  train_eval()       학습/평가 (03_train_eval.py), eval_report.json 을 dict 로 반환
  run_all()          위 단계를 순서대로

공격 기록
  load_attack_runs() / append_attack_runs() / parse_when()  -- attack_runs.csv 읽기·추가, 시각 해석

웹페이지 예시 (나중에)
  import pipeline_core as pc
  runs = [pc.AttackRun("claude", "192.168.0.27", pc.parse_when("14:03", base), pc.parse_when("14:15", base))]
  pc.append_attack_runs(workdir / "attack_runs.csv", runs)
  report = pc.run_all(workdir, start, end, wazuh=pc.WazuhConfig(sudo_password=...), log=send_to_browser)
"""

import dataclasses
import datetime
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
TOOL_RE = re.compile(r"^[a-z0-9]+$")
IP_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
ATTACK_RUNS_HEADER = "tool,ip,start,end,result,ua,note"
ATTACK_RUNS_FORMAT = ("#도구(소문자: claude/artex/pentagi),공격PC IP,YYYY-MM-DD HH:MM (KST 날짜+시간),"
                      "YYYY-MM-DD HH:MM (KST 날짜+시간),success/fail (선택),UA 일부 (선택),메모 (선택)")
SETTINGS_FILE = ".pipeline_settings.json"


class PipelineError(Exception):
    """파이프라인 단계 실패 (사용자에게 그대로 보여줄 메시지)"""


@dataclasses.dataclass
class AttackRun:
    tool: str
    ip: str
    start: datetime.datetime
    end: datetime.datetime
    result: str = ""
    ua: str = ""
    note: str = ""

    def validate(self):
        if not TOOL_RE.match(self.tool or ""):
            raise PipelineError(f"도구 이름은 소문자/숫자만 가능합니다 (예: claude, artex, pentagi): '{self.tool}'")
        m = IP_RE.match(self.ip or "")
        if not m or any(int(x) > 255 for x in m.groups()):
            raise PipelineError(f"IP 형식이 아닙니다: '{self.ip}'")
        if self.end <= self.start:
            raise PipelineError(f"종료 시각이 시작보다 빠릅니다: {self.start:%m-%d %H:%M} ~ {self.end:%m-%d %H:%M}")
        for v in (self.result, self.ua, self.note):
            if "," in (v or ""):
                raise PipelineError(f"쉼표(,)는 쓸 수 없습니다: '{v}'")
        return self


@dataclasses.dataclass
class WazuhConfig:
    host: str = "192.168.0.141"      # FortiGate VIP
    port: str = "8822"               # -> Wazuh 22
    user: str = "dongyoung"
    identity: str = None             # SSH 개인키 경로 (None: ssh 기본 키)
    remote_out: str = "/tmp/wazuh_export"
    sudo_password: str = None        # None 이면 환경변수 WAZUH_SUDO_PASSWORD, 그것도 없으면 빈 값(NOPASSWD)


# =============================================================
# 경로 / 설정
# =============================================================
def paths(workdir):
    w = pathlib.Path(workdir).resolve()
    return {
        "workdir": w,
        "attack_runs": w / "attack_runs.csv",
        "manifests": w / "manifests",
        "raw_logs": w / "raw_logs",
        "labels": w / "labels",
        "features": w / "features",
        "models": w / "models",
    }


def load_settings(workdir):
    """지난번 입력값(SSH 계정, 공격 PC IP 등) - 다음 입력 때 기본값으로 사용"""
    p = pathlib.Path(workdir) / SETTINGS_FILE
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_settings(workdir, **kw):
    s = load_settings(workdir)
    s.update({k: v for k, v in kw.items() if v is not None})
    try:
        (pathlib.Path(workdir) / SETTINGS_FILE).write_text(json.dumps(s, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass


# =============================================================
# 시각 해석
# =============================================================
_FULL = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"]
_MD = ["%m-%d %H:%M:%S", "%m-%d %H:%M"]
_HM = ["%H:%M:%S", "%H:%M"]


def parse_when(text, base_date=None):
    """
    '2026-10-30 14:03' / '10-30 14:03' / '14:03' / '1403' 모두 허용 (구분자 / . 도 허용)
    날짜가 없으면 base_date(날짜) 를 붙임. base_date 도 없으면 PipelineError
    """
    t = (text or "").strip()
    if not t:
        raise PipelineError("시각이 비어 있습니다.")
    t = re.sub(r"(\d)[/.](\d)", r"\1-\2", t)
    t = re.sub(r"\s+", " ", t)
    if re.fullmatch(r"\d{3,4}", t):  # 1403 -> 14:03
        t = f"{t[:-2]}:{t[-2:]}"
    for f in _FULL:
        try:
            return datetime.datetime.strptime(t, f)
        except ValueError:
            pass
    for f in _MD:
        try:
            d = datetime.datetime.strptime(t, f)
            year = base_date.year if base_date else datetime.date.today().year
            return d.replace(year=year)
        except ValueError:
            pass
    for f in _HM:
        try:
            tm = datetime.datetime.strptime(t, f).time()
        except ValueError:
            continue
        if base_date is None:
            raise PipelineError(f"날짜가 필요합니다: '{text}' (예: 2026-10-30 14:03)")
        bd = base_date.date() if isinstance(base_date, datetime.datetime) else base_date
        return datetime.datetime.combine(bd, tm)
    raise PipelineError(f"시각 형식을 알 수 없습니다: '{text}' (예: 2026-10-30 14:03 또는 14:03)")


def fit_into_range(dt, start, end, slack_min=60):
    """
    날짜를 추출 범위 기준으로 붙인 시각이 범위 밖이면 하루 앞뒤로 옮겨 범위에 맞춤 (자정 넘김 대비)
    범위(±slack) 안에 들어가지 않으면 None
    """
    slack = datetime.timedelta(minutes=slack_min)
    for cand in (dt, dt + datetime.timedelta(days=1), dt - datetime.timedelta(days=1)):
        if start - slack <= cand <= end + slack:
            return cand
    return None


# =============================================================
# 공격 기록 (attack_runs.csv)
# =============================================================
def _detect_encoding(p):
    raw = p.read_bytes()
    try:
        raw.decode("utf-8")
        return "utf-8-sig" if raw.startswith(b"\xef\xbb\xbf") else "utf-8"
    except UnicodeDecodeError:
        return "cp949"  # 엑셀 '다른 이름으로 저장 > CSV'


def _decode(raw):
    for enc in ("utf-8-sig", "cp949"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            pass
    return raw.decode("utf-8", errors="replace"), "utf-8"


def _split_line(line, header_delim):
    """한 줄을 칸으로 나눔. 엑셀이 탭으로 저장한 줄과 쉼표 줄이 섞여 있어도 줄마다 구분자를 판단"""
    import csv
    delim = "\t" if "\t" in line else ("," if "," in line else header_delim)
    return next(csv.reader([line], delimiter=delim))


def read_attack_table(path):
    """
    attack_runs.csv 를 관대하게 읽음 -> [(줄번호, {컬럼: 값})]
      - 인코딩: UTF-8(BOM 포함) / CP949(엑셀 저장)
      - 구분자: 쉼표 / 탭(엑셀 '텍스트(탭으로 분리)' 저장) / 둘이 섞여도 줄마다 판단
      - '#' 으로 시작하는 줄, 빈 줄, 모든 칸이 빈 줄(엑셀이 남긴 빈 행)은 건너뜀
    """
    p = pathlib.Path(path)
    if not p.is_file():
        return []
    text, _ = _decode(p.read_bytes())
    lines = text.splitlines()
    header, header_delim, rows = None, ",", []
    for lineno, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        if header is None:
            header_delim = "\t" if "\t" in line else ","
            header = [h.strip().lower() for h in _split_line(line, header_delim)]
            continue
        cells = [c.strip() for c in _split_line(line, header_delim)]
        if not any(cells) or cells[0].startswith("#"):
            continue
        rows.append((lineno, dict(zip(header, cells + [""] * (len(header) - len(cells))))))
    if header is not None:
        missing = [c for c in ("tool", "ip", "start", "end") if c not in header]
        if missing:
            raise PipelineError(f"{p.name} 첫 줄에 {missing} 컬럼이 없습니다. 첫 줄은 '{ATTACK_RUNS_HEADER}' 여야 합니다.")
    return rows


def ensure_attack_runs_file(path):
    p = pathlib.Path(path)
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(ATTACK_RUNS_HEADER + "\n" + ATTACK_RUNS_FORMAT + "\n", encoding="utf-8-sig")
    return p


def load_attack_runs(path):
    """attack_runs.csv -> [AttackRun]. '#' 줄/빈 줄 무시, 날짜 없는 시각은 오류, 완전히 같은 줄은 한 번만"""
    p = pathlib.Path(path)
    runs, seen = [], set()
    for lineno, row in read_attack_table(p):
        try:
            run = AttackRun(
                tool=row.get("tool", "").lower(), ip=row.get("ip", ""),
                start=parse_when(row.get("start")), end=parse_when(row.get("end")),
                result=row.get("result", ""), ua=row.get("ua", ""), note=row.get("note", "")).validate()
        except PipelineError as e:
            raise PipelineError(f"{p.name} {lineno}줄: {e}")
        key = (run.tool, run.ip, run.start, run.end, run.ua)
        if key not in seen:
            seen.add(key)
            runs.append(run)
    return runs


def append_attack_runs(path, runs):
    """공격 기록을 attack_runs.csv 끝에 추가 (파일 없으면 헤더+형식 안내 줄과 함께 생성)"""
    for r in runs:
        r.validate()
    p = ensure_attack_runs_file(path)
    raw = p.read_bytes()
    text, enc = _decode(raw)
    enc = "utf-8" if enc == "utf-8-sig" else enc  # 이어 쓰기에는 BOM 을 붙이지 않음
    first = next((ln for ln in text.splitlines() if ln.strip()), "")
    delim = "\t" if "\t" in first else ","          # 엑셀이 탭으로 저장했으면 탭으로 이어 씀
    eol = "\r\n" if "\r\n" in text else "\n"
    lines = [delim.join([r.tool, r.ip, f"{r.start:%Y-%m-%d %H:%M}", f"{r.end:%Y-%m-%d %H:%M}", r.result, r.ua, r.note])
             for r in runs]
    try:
        needs_nl = bool(raw) and not raw.endswith(b"\n")
        with open(p, "a", encoding=enc, newline="") as f:
            f.write((eol if needs_nl else "") + eol.join(lines) + eol)
    except PermissionError:
        raise PipelineError(f"{p.name} 이(가) 다른 프로그램(엑셀 등)에서 열려 있어 저장할 수 없습니다. 닫고 다시 시도하세요.")
    return p


def runs_in_range(runs, start, end, slack_min=1):
    s = datetime.timedelta(minutes=slack_min)
    return [r for r in runs if r.end + s >= start and r.start - s <= end]


# =============================================================
# 단계 실행
# =============================================================
def _stream(cmd, log, cwd=None, stdin_text=None, env=None, display=None):
    """명령을 실행하며 출력 한 줄씩 log 로 전달. 실패하면 PipelineError"""
    env = dict(os.environ if env is None else env)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"
    log("$ " + (display or " ".join(shlex.quote(str(c)) for c in cmd)))
    proc = subprocess.Popen([str(c) for c in cmd], cwd=cwd, env=env, text=True, encoding="utf-8", errors="replace",
                            stdin=subprocess.PIPE if stdin_text is not None else None,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1)
    if stdin_text is not None:
        proc.stdin.write(stdin_text)
        proc.stdin.close()
    for line in proc.stdout:
        log(line.rstrip("\n"))
    rc = proc.wait()
    if rc != 0:
        raise PipelineError(f"명령이 실패했습니다 (exit {rc}): {cmd[0] if isinstance(cmd[0], str) else pathlib.Path(cmd[0]).name}"
                            + (f" {pathlib.Path(cmd[1]).name}" if len(cmd) > 1 else ""))
    return rc


def _py(script, args, log, cwd):
    return _stream([sys.executable, HERE / script, *args], log, cwd=cwd)


def default_raw_name(start, end):
    return f"mixed_{start:%m%d_%H%M}-{end:%H%M}"


def export_logs(workdir, start, end, wazuh=None, name=None, log=print):
    """Wazuh 서버에서 [start, end) KST 로그를 추출해 ./raw_logs/<name>.csv 로 받아옴"""
    wazuh = wazuh or WazuhConfig()
    if end <= start:
        raise PipelineError("추출 종료가 시작보다 늦어야 합니다.")
    for tool in ("ssh", "scp"):
        if not shutil.which(tool):
            raise PipelineError(f"'{tool}' 명령이 없습니다. Windows: 설정 > 앱 > 선택적 기능 > OpenSSH 클라이언트 설치")
    name = name or default_raw_name(start, end)
    dest = f"{wazuh.user}@{wazuh.host}"
    opt = ["-o", "StrictHostKeyChecking=accept-new"] + (["-i", wazuh.identity] if wazuh.identity else [])

    _stream(["scp", "-P", wazuh.port, *opt, HERE / "00_export_archives.py", f"{dest}:00_export_archives.py"], log)
    pw = wazuh.sudo_password if wazuh.sudo_password is not None else os.environ.get("WAZUH_SUDO_PASSWORD", "")
    remote = (f"sudo -S -p '' python3 ~/00_export_archives.py"
              f" --start {shlex.quote(f'{start:%Y-%m-%d %H:%M:%S}')} --end {shlex.quote(f'{end:%Y-%m-%d %H:%M:%S}')}"
              f" --name {shlex.quote(name)} --out-dir {shlex.quote(wazuh.remote_out)}")
    try:
        _stream(["ssh", "-p", wazuh.port, *opt, dest, remote], log, stdin_text=pw + "\n",
                display=f"ssh -p {wazuh.port} {dest} \"sudo python3 ~/00_export_archives.py "
                        f"--start '{start:%Y-%m-%d %H:%M:%S}' --end '{end:%Y-%m-%d %H:%M:%S}' --name {name}\"")
    except PipelineError:
        raise PipelineError("서버에서 추출이 실패했습니다. sudo 비밀번호, 시간 범위, archives 설정(logall_json)을 확인하세요.")

    raw_dir = paths(workdir)["raw_logs"]
    raw_dir.mkdir(parents=True, exist_ok=True)
    local = raw_dir / f"{name}.csv"
    _stream(["scp", "-P", wazuh.port, *opt, f"{dest}:{wazuh.remote_out}/{name}.csv", local], log)
    if not local.is_file() or local.stat().st_size == 0:
        raise PipelineError(f"다운로드한 파일이 비어 있습니다: {local}")
    log(f" -> 원본 로그: {local} ({local.stat().st_size / 1024:.0f} KB)")
    return local


def rules_path_for(workdir, raw):
    return paths(workdir)["labels"] / f"{pathlib.Path(raw).stem}_rules.csv"


def features_path_for(workdir, raw):
    return paths(workdir)["features"] / (pathlib.Path(raw).stem.replace("mixed", "labeled") + "_features.csv")


def build_rules(workdir, raw, attack_runs=None, manifests=None, out=None, extra_args=(), log=print):
    p = paths(workdir)
    out = pathlib.Path(out) if out else rules_path_for(workdir, raw)
    _py("build_label_rules.py", ["--raw", raw, "--attack-runs", attack_runs or p["attack_runs"],
                                 "--manifests", manifests or p["manifests"], "--out", out, *extra_args],
        log, cwd=p["workdir"])
    return out


def extract_features(workdir, raw, rules, out=None, log=print):
    out = pathlib.Path(out) if out else features_path_for(workdir, raw)
    _py("01b_label_sessions.py", ["--raw", raw, "--rules", rules, "--out", out], log, cwd=paths(workdir)["workdir"])
    return out


def train_eval(workdir, extra_args=(), log=print):
    p = paths(workdir)
    if not list(p["features"].glob("*_features.csv")):
        raise PipelineError(f"피처 파일이 없습니다: {p['features']}")
    _py("03_train_eval.py", ["--features", p["features"], "--out-dir", p["models"], *extra_args], log, cwd=p["workdir"])
    rep = p["models"] / "eval_report.json"
    return json.loads(rep.read_text(encoding="utf-8")) if rep.is_file() else {}


STEPS = ["export", "rules", "features", "train"]


def run_all(workdir, start=None, end=None, raw=None, rules=None, wazuh=None, name=None,
            stop_after=None, train_args=(), log=print, on_step=None):
    """
    전체 실행. raw 를 주면 추출 생략, rules 를 주면 자동 규칙표 생략.
    on_step(step_name, result_path) : 단계가 끝날 때마다 호출 (웹 진행 표시용)
    반환: {"raw":..., "rules":..., "features":..., "report": dict}
    """
    on_step = on_step or (lambda *_: None)
    out = {}
    if raw is None:
        if start is None or end is None:
            raise PipelineError("추출 시간(start, end) 또는 원본 파일(raw) 이 필요합니다.")
        raw = export_logs(workdir, start, end, wazuh=wazuh, name=name, log=log)
    out["raw"] = pathlib.Path(raw)
    on_step("export", out["raw"])
    if stop_after == "export":
        return out
    out["rules"] = pathlib.Path(rules) if rules else build_rules(workdir, raw, log=log)
    on_step("rules", out["rules"])
    if stop_after == "rules":
        return out
    out["features"] = extract_features(workdir, raw, out["rules"], log=log)
    on_step("features", out["features"])
    if stop_after == "features":
        return out
    out["report"] = train_eval(workdir, extra_args=train_args, log=log)
    on_step("train", paths(workdir)["models"])
    return out
