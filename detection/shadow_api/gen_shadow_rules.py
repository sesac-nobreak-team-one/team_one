#!/usr/bin/env python3
"""
OpenAPI 명세 → Wazuh Shadow API 탐지 룰 생성기

웹서버가 공개한 openapi.yaml을 "허용 목록"으로 삼아, app.log의 /api/ 요청 중
명세에 없는 (메서드 + 경로)를 경보로 만드는 Wazuh 커스텀 룰 XML을 생성한다.

하위 명령
  build    명세를 읽어 룰 XML과 테스트 케이스를 만든다
  test     만든 룰 로직을 파이썬으로 재현해 테스트 케이스를 검증한다 (Wazuh 없이)
  replay   기존 app.log / archives.json을 룰 로직으로 다시 판정해 단계별로 집계한다
  logtest  Wazuh 서버에서 wazuh-logtest에 테스트 케이스를 넣어 실제 룰 ID를 대조한다

예시
  python3 gen_shadow_rules.py build --spec http://192.168.20.10/docs/openapi.yaml
  python3 gen_shadow_rules.py test
  python3 gen_shadow_rules.py replay /var/ossec/logs/archives/archives.json
  sudo python3 gen_shadow_rules.py logtest

필요 패키지: PyYAML (Ubuntu: sudo apt install python3-yaml)
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from xml.sax.saxutils import escape

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML이 필요합니다: pip install pyyaml  또는  sudo apt install python3-yaml")

HERE = Path(__file__).resolve().parent
DEFAULT_RULES = HERE / "shadow_api_rules.xml"
DEFAULT_CASES = HERE / "testcases.jsonl"
DEFAULT_META = HERE / "rules_meta.json"
DEFAULT_ALLOWLIST = HERE / "shadow_api_allowlist.yaml"

HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")

# 검사 대상: /api 로 시작하는 요청. //api 처럼 슬래시를 겹쳐 쓴 우회 시도도 포함한다.
API_SCOPE_REGEX = r"^/+api(?:/|\?|$)"

# 응답 코드 → 단계. 순서가 판정 우선순위다.
#   405: 명세 경로에 다른 메서드를 시도 (라우터가 경로는 알지만 메서드가 없음) → 탐색
#   401/403: 숨은 API가 "존재"하고 인증/권한에 막힘 (v1은 토큰이 없으면 어떤 경로든 401)
STAGES = [
    # key,       offset, level, status regex,  group,                 label
    ("L1",       10, 5,  r"^40[45]$",   "shadow_api_recon",     "L1 정찰"),
    ("L2",       11, 8,  r"^40[13]$",   "shadow_api_discovery", "L2 발견"),
    ("L3",       12, 12, r"^2\d\d$",    "shadow_api_exploit",   "L3 악용"),
    ("L3E",      13, 10, r"^5\d\d$",    "shadow_api_error",     "L3-E 서버 오류"),
]
OTHER_LEVEL = 6  # 명세 밖인데 위 상태 코드가 아닌 경우 (400, 422, 3xx 등)

# 빈도 룰 (같은 client_ip 기준). 임계값은 정상 세션 측정 후 조정한다.
BURSTS = [
    # key, offset, level, 대상 단계, 기본 건수, 기본 시간(초), group, label, mitre
    ("F1", 20, 10, "L1", 20, 30, "shadow_api_recon_burst", "F1 자동화 정찰", "T1595.003"),
    ("F2", 21, 14, "L3", 10, 60, "shadow_api_mass_exfil", "F2 대량 유출", "T1119"),
]
STAGE_MITRE = {"L3": "T1190"}


# ─────────────────────────────────────────────────────────────────────────────
# 명세 읽기
# ─────────────────────────────────────────────────────────────────────────────
def read_source(src: str) -> bytes:
    if re.match(r"^https?://", src):
        try:
            with urllib.request.urlopen(src, timeout=15) as resp:  # noqa: S310 (내부 랩 주소)
                return resp.read()
        except OSError as e:  # URLError, 타임아웃 모두 포함
            sys.exit(
                f"명세를 내려받지 못했습니다: {src}\n  원인: {e}\n"
                "  Wazuh 서버(LAN)에서 웹서버(DMZ)로 가는 HTTP는 방화벽에서 막혀 있을 수 있습니다.\n"
                "  openapi.yaml 파일을 이 서버로 복사한 뒤 --spec 에 파일 경로를 주세요."
            )
    try:
        return Path(src).read_bytes()
    except OSError as e:
        sys.exit(f"명세 파일을 읽지 못했습니다: {src}\n  원인: {e}")


def base_path(spec: dict) -> str:
    """servers[0].url 의 경로 부분. '/' 이면 빈 문자열."""
    servers = spec.get("servers") or [{"url": "/"}]
    url = str(servers[0].get("url", "/"))
    path = urllib.parse.urlparse(url).path if "://" in url else url
    return path.rstrip("/")


def collect_operations(spec: dict, allowlist: list[dict]) -> dict[str, list[dict]]:
    """메서드 → [{template, source, reason}] (메서드는 대문자)"""
    prefix = base_path(spec)
    ops: dict[str, list[dict]] = collections.defaultdict(list)
    for raw_path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method in HTTP_METHODS:
            if method in item:
                ops[method.upper()].append(
                    {"template": prefix + raw_path, "source": "openapi", "reason": ""}
                )
    for entry in allowlist:
        method = str(entry["method"]).upper()
        ops[method].append(
            {"template": entry["path"], "source": "allowlist", "reason": entry.get("reason", "")}
        )
    return {m: sorted(v, key=lambda o: o["template"]) for m, v in sorted(ops.items())}


def load_allowlist(path: Path) -> list[dict]:
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = data.get("allow") or []
    for e in entries:
        if not e.get("method") or not e.get("path"):
            sys.exit(f"{path}: 모든 예외 항목에는 method와 path가 필요합니다: {e}")
        if not e.get("reason"):
            sys.exit(f"{path}: 예외 항목에는 사유(reason)를 적어야 합니다: {e}")
    return entries


# ─────────────────────────────────────────────────────────────────────────────
# 경로 템플릿 → 정규식
# ─────────────────────────────────────────────────────────────────────────────
PARAM_RE = re.compile(r"\{[^/{}]+\}")


def template_to_regex(template: str) -> str:
    """/api/v2/products/{id} → /api/v2/products/[^/?]+

    서버 라우터(Router.php)와 같은 규칙을 따른다.
      - 경로 파라미터는 슬래시를 포함하지 않는 한 글자 이상
      - 끝 슬래시는 무시 (Request.php가 rtrim)
      - 쿼리스트링은 무시 (app.log path는 REQUEST_URI라 쿼리가 붙어 있음)
    """
    parts = PARAM_RE.split(template)
    params = PARAM_RE.findall(template)
    out = []
    for i, literal in enumerate(parts):
        out.append(re.escape(literal))
        if i < len(params):
            out.append(r"[^/?]+")
    return "".join(out)


def method_allow_regex(ops: list[dict]) -> str:
    alts = sorted({template_to_regex(o["template"]) for o in ops})
    return r"^(?:" + "|".join(alts) + r")/*(?:\?.*)?$"


def methods_regex(methods) -> str:
    return r"^(?:" + "|".join(sorted(methods)) + r")$"


# ─────────────────────────────────────────────────────────────────────────────
# 룰 ID 배치
# ─────────────────────────────────────────────────────────────────────────────
def rule_ids(base_id: int, methods: list[str]) -> dict:
    ids = {"base": base_id, "other_method": base_id + 1}
    for i, m in enumerate(methods):
        ids[f"undoc_{m}"] = base_id + 2 + i
    if 2 + len(methods) > 10:
        sys.exit("명세 메서드 종류가 너무 많아 룰 ID 블록(10칸)을 넘습니다. --base-id 배치를 늘리세요.")
    for key, offset, *_ in STAGES:
        ids[key] = base_id + offset
    for key, offset, *_ in BURSTS:
        ids[key] = base_id + offset
    return ids


# ─────────────────────────────────────────────────────────────────────────────
# XML 생성
# ─────────────────────────────────────────────────────────────────────────────
def x(text: str) -> str:
    return escape(text, {'"': "&quot;"})


def field(name: str, regex: str, negate: bool = False) -> str:
    neg = ' negate="yes"' if negate else ""
    return f'    <field name="{name}" type="pcre2"{neg}>{x(regex)}</field>'


def status_cond(regex: str, option: str) -> str:
    """응답 코드 조건.

    Wazuh JSON 디코더는 키 이름이 정적 필드 이름(srcip, status, url 등)과 같으면
    동적 필드가 아니라 정적 필드에 넣는 것으로 알려져 있다. app.log의 "status"가 여기에 해당한다.
    실제 동작은 Wazuh 버전에 따라 확인이 필요하므로 두 방식을 모두 지원한다.
      static: <status type="pcre2">   (기본값)
      field : <field name="status" type="pcre2">
    logtest 결과 단계 룰이 하나도 안 걸리면 다른 쪽으로 다시 build 한다.
    """
    if option == "field":
        return field("status", regex)
    return f'    <status type="pcre2">{x(regex)}</status>'


def build_xml(ops: dict[str, list[dict]], ids: dict, bursts: dict, meta: dict) -> str:
    methods = list(ops.keys())
    sopt = meta["status_option"]
    L: list[str] = []
    L.append("<!--")
    L.append("  Shadow API 탐지 룰 (자동 생성 파일: 직접 고치지 말고 gen_shadow_rules.py build 로 다시 만드세요)")
    L.append(f"  생성 시각 : {meta['generated_at']}")
    L.append(f"  명세 원본 : {meta['spec_source']}")
    L.append(f"  명세 SHA256: {meta['spec_sha256']}")
    L.append(f"  명세 작업 수: {meta['operation_count']} (예외 목록 {meta['allowlist_count']}건 포함)")
    L.append(f"  status 매칭: {meta['status_option']}")
    for m in methods:
        for o in ops[m]:
            tag = "  [예외] " + o["reason"] if o["source"] == "allowlist" else ""
            L.append(f"    {m:<7} {o['template']}{tag}")
    L.append("-->")
    L.append('<group name="shadow_api,">')
    L.append("")

    # 1. 기반 룰
    L.append("  <!-- 기반: app.log(JSON)의 /api 요청. 명세 안 요청은 여기서 끝난다 (레벨 0 = 경보 없음) -->")
    L.append(f'  <rule id="{ids["base"]}" level="0">')
    L.append("    <decoded_as>json</decoded_as>")
    L.append(field("method", r"^[A-Za-z]+$"))
    L.append(status_cond(r"^\d{3}$", sopt))
    L.append(field("path", API_SCOPE_REGEX))
    L.append("    <description>Shop API 요청</description>")
    L.append("  </rule>")
    L.append("")

    # 2. 명세 밖 판정
    L.append("  <!-- 명세 밖 판정: 명세에 아예 없는 메서드 -->")
    L.append(f'  <rule id="{ids["other_method"]}" level="{OTHER_LEVEL}">')
    L.append(f'    <if_sid>{ids["base"]}</if_sid>')
    L.append(field("method", methods_regex(methods), negate=True))
    L.append("    <description>[Shadow API] 명세 밖 호출: $(client_ip) $(method) $(path)</description>")
    L.append("    <group>shadow_api_undocumented,</group>")
    L.append("  </rule>")
    for m in methods:
        rid = ids[f"undoc_{m}"]
        L.append("")
        L.append(f"  <!-- 명세 밖 판정: {m} 인데 명세의 {m} 경로({len(ops[m])}개) 어디에도 맞지 않음 -->")
        L.append(f'  <rule id="{rid}" level="{OTHER_LEVEL}">')
        L.append(f'    <if_sid>{ids["base"]}</if_sid>')
        L.append(field("method", f"^{m}$"))
        L.append(field("path", method_allow_regex(ops[m]), negate=True))
        L.append("    <description>[Shadow API] 명세 밖 호출: $(client_ip) $(method) $(path)</description>")
        L.append("    <group>shadow_api_undocumented,</group>")
        L.append("  </rule>")
    L.append("")

    # 3. 응답 코드별 단계
    L.append("  <!-- 단계: 명세 밖 호출을 응답 코드로 분류 -->")
    for key, _off, level, status_re, group, label in STAGES:
        L.append(f'  <rule id="{ids[key]}" level="{level}">')
        L.append("    <if_group>shadow_api_undocumented</if_group>")
        L.append(status_cond(status_re, sopt))
        L.append(f"    <description>[Shadow API {label}] $(client_ip) $(method) $(path)</description>")
        if key in STAGE_MITRE:
            L.append(f"    <mitre><id>{STAGE_MITRE[key]}</id></mitre>")
        L.append(f"    <group>{group},</group>")
        L.append("  </rule>")
    L.append("")

    # 4. 빈도
    L.append("  <!-- 빈도: 같은 client_ip가 짧은 시간에 반복 -->")
    for key, _off, level, target, _n, _t, group, label, mitre in BURSTS:
        n, t, ign = bursts[key]
        ign_attr = f' ignore="{ign}"' if ign else ""
        L.append(f'  <rule id="{ids[key]}" level="{level}" frequency="{n}" timeframe="{t}"{ign_attr}>')
        L.append(f"    <if_matched_sid>{ids[target]}</if_matched_sid>")
        L.append("    <same_field>client_ip</same_field>")
        L.append(f"    <description>[Shadow API {label}] $(client_ip) {t}초 안에 {target} {n}회 이상</description>")
        L.append(f"    <mitre><id>{mitre}</id></mitre>")
        L.append(f"    <group>{group},</group>")
        L.append("  </rule>")
    L.append("")
    L.append("</group>")
    return "\n".join(L) + "\n"


# ─────────────────────────────────────────────────────────────────────────────
# 룰 로직 파이썬 재현 (test / replay 공용)
# ─────────────────────────────────────────────────────────────────────────────
class Classifier:
    def __init__(self, meta: dict):
        self.ids = meta["rule_ids"]
        self.scope = re.compile(API_SCOPE_REGEX)
        self.methods = set(meta["operations"].keys())
        self.allow = {m: re.compile(method_allow_regex(ops)) for m, ops in meta["operations"].items()}
        self.stages = [(k, re.compile(s), lvl) for k, _o, lvl, s, *_ in STAGES]
        self.bursts = meta["bursts"]
        self.burst_target = {k: tgt for k, _o, _l, tgt, *_ in BURSTS}
        self.burst_level = {k: lvl for k, _o, lvl, *_ in BURSTS}
        self.history: dict[tuple, collections.deque] = collections.defaultdict(collections.deque)
        self.last_fire: dict[str, float] = {}

    def is_undocumented(self, method: str, path: str) -> bool:
        if method not in self.methods:
            return True
        return not self.allow[method].search(path)

    def classify(self, ev: dict, ts: float | None = None) -> tuple[str | None, int]:
        """(단계 키 또는 None, 레벨). None = 경보 없음 또는 검사 대상 아님."""
        method, path, status = str(ev.get("method", "")), str(ev.get("path", "")), str(ev.get("status", ""))
        if not re.match(r"^[A-Za-z]+$", method) or not re.match(r"^\d{3}$", status):
            return None, 0
        if not self.scope.search(path) or not self.is_undocumented(method, path):
            return None, 0
        stage, level = "OTHER", OTHER_LEVEL
        for key, rx, lvl in self.stages:
            if rx.search(status):
                stage, level = key, lvl
                break
        if ts is not None:
            ip = str(ev.get("client_ip", ""))
            for bkey, target in self.burst_target.items():
                if stage != target:
                    continue
                n, window, ignore = self.bursts[bkey]
                q = self.history[(target, ip)]
                q.append(ts)
                while q and ts - q[0] > window:
                    q.popleft()
                if len(q) >= n and ts - self.last_fire.get(bkey, -1e18) >= ignore:
                    self.last_fire[bkey] = ts
                    return bkey, self.burst_level[bkey]
        return stage, level


# ─────────────────────────────────────────────────────────────────────────────
# 테스트 케이스
# ─────────────────────────────────────────────────────────────────────────────
def sample_path(template: str, value: str = "7") -> str:
    return PARAM_RE.sub(value, template)


def make_cases(ops: dict[str, list[dict]]) -> list[dict]:
    def ev(method, path, status, note, expect, ip="192.168.80.50", user_id=None):
        return {
            "note": note,
            "expect": expect,
            "log": {
                "timestamp": "2026-10-30T10:00:00+09:00",
                "request_id": "test",
                "client_ip": ip,
                "method": method,
                "path": path,
                "status": status,
                "response_bytes": 128,
                "user_id": user_id,
                "duration_ms": 3.1,
                "user_agent": "shadow-api-testcase",
            },
        }

    cases = []
    # 명세 안: 경보 없음
    for m, lst in ops.items():
        for o in lst:
            p = sample_path(o["template"])
            cases.append(ev(m, p, 200, f"명세 안 {m} {o['template']}", None))
    cases.append(ev("GET", "/api/v2/products?category=book&page=2", 200, "명세 안 + 쿼리스트링", None))
    cases.append(ev("GET", "/api/v2/products/", 200, "명세 안 + 끝 슬래시 (라우터가 무시)", None))
    cases.append(ev("GET", "/api/v2/orders/me?status=paid", 401, "명세 안 + 401 (명세 API의 인증 실패는 범위 밖)", None))
    cases.append(ev("GET", "/products.php", 200, "API 아님 (검사 대상 아님)", None))
    cases.append(ev("GET", "/docs/openapi.yaml", 200, "명세 파일 열람 (검사 대상 아님)", None))

    # 명세 밖
    cases += [
        ev("GET", "/api/v3/users/1", 404, "없는 버전 탐색", "L1"),
        ev("GET", "/api/v2/admin", 404, "없는 경로 탐색", "L1"),
        ev("GET", "/api/v2/products/1/reviews", 404, "명세 경로 하위의 없는 경로", "L1"),
        ev("DELETE", "/api/v2/users/me", 405, "명세 경로 + 명세 밖 메서드", "L1"),
        ev("PUT", "/api/v2/cart", 405, "명세에 아예 없는 메서드", "L1"),
        ev("HEAD", "/api/v2/products", 405, "HEAD (명세 밖 메서드)", "L1"),
        ev("GET", "/api/v1/users/1", 401, "Shadow API 존재 확인 (토큰 없음)", "L2"),
        ev("GET", "/api/v1/whatever", 401, "v1은 토큰 없으면 어떤 경로든 401", "L2"),
        ev("GET", "//api/v1/users/1", 401, "슬래시 겹치기 우회 시도", "L2"),
        ev("GET", "/api/v1/users/2", 200, "Shadow API IDOR 성공", "L3", user_id=31),
        ev("GET", "/api/v1/diagnostics/ping?host=127.0.0.1", 200, "Shadow API 진단 호출 성공", "L3", user_id=31),
        ev("GET", "/api/v1/diagnostics/ping?host=x;id", 500, "Shadow API 서버 오류", "L3E", user_id=31),
        ev("GET", "/api/v1/users/abc", 400, "명세 밖 + 기타 상태 코드", "OTHER", user_id=31),
    ]
    return cases


def burst_cases(meta: dict) -> list[dict]:
    """빈도 룰 시나리오 (시각 순서대로 넣어야 의미가 있다)."""
    seq = []
    n1, _, _ = meta["bursts"]["F1"]
    for i in range(n1):
        seq.append({"ts": i * 1.0, "log": {"client_ip": "192.168.80.66", "method": "GET",
                                           "path": f"/api/v2/fuzz{i}", "status": 404}})
    n2, _, _ = meta["bursts"]["F2"]
    for i in range(n2):
        seq.append({"ts": 100 + i * 2.0, "log": {"client_ip": "192.168.80.66", "method": "GET",
                                                 "path": f"/api/v1/users/{i + 1}", "status": 200}})
    return seq


# ─────────────────────────────────────────────────────────────────────────────
# 하위 명령
# ─────────────────────────────────────────────────────────────────────────────
def cmd_build(a) -> None:
    raw = read_source(a.spec)
    spec = yaml.safe_load(raw)
    if not isinstance(spec, dict) or "paths" not in spec:
        sys.exit(f"{a.spec}: OpenAPI 명세(paths)를 찾지 못했습니다")
    allowlist = load_allowlist(Path(a.allowlist))
    ops = collect_operations(spec, allowlist)
    ids = rule_ids(a.base_id, list(ops.keys()))
    bursts = {
        "F1": (a.f1_count, a.f1_window, a.burst_ignore),
        "F2": (a.f2_count, a.f2_window, a.burst_ignore),
    }
    meta = {
        "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "spec_source": a.spec,
        "spec_sha256": hashlib.sha256(raw).hexdigest(),
        "operation_count": sum(len(v) for v in ops.values()),
        "allowlist_count": len(allowlist),
        "status_option": a.status_option,
        "rule_ids": ids,
        "bursts": bursts,
        "operations": ops,
    }
    Path(a.out).write_text(build_xml(ops, ids, bursts, meta), encoding="utf-8")
    Path(a.meta).write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    cases = make_cases(ops)
    with open(a.cases, "w", encoding="utf-8") as f:
        for c in cases:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    print(f"명세 작업 {meta['operation_count']}개 (예외 {len(allowlist)}건) → {a.out}")
    for m, lst in ops.items():
        print(f"  {m:<7} {len(lst)}개  명세 밖 룰 ID {ids['undoc_' + m]}")
    print(f"  기타 메서드        명세 밖 룰 ID {ids['other_method']}")
    print("  단계 룰: " + ", ".join(f"{k}={ids[k]}" for k, *_ in STAGES))
    print("  빈도 룰: " + ", ".join(f"{k}={ids[k]} ({bursts[k][0]}회/{bursts[k][1]}초)" for k, *_ in BURSTS))
    print(f"테스트 케이스 {len(cases)}개 → {a.cases}")


def load_meta(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        sys.exit(f"{p} 가 없습니다. 먼저 build 를 실행하세요.")
    meta = json.loads(p.read_text(encoding="utf-8"))
    meta["bursts"] = {k: tuple(v) for k, v in meta["bursts"].items()}
    return meta


def cmd_test(a) -> None:
    meta = load_meta(a.meta)
    clf = Classifier(meta)
    fails = 0
    total = 0
    for line in Path(a.cases).read_text(encoding="utf-8").splitlines():
        c = json.loads(line)
        got, _ = clf.classify(c["log"])
        total += 1
        ok = got == c["expect"]
        fails += not ok
        if not ok or a.verbose:
            mark = "OK  " if ok else "FAIL"
            print(f"{mark} 기대={c['expect']!s:<5} 결과={got!s:<5} {c['log']['method']:<6} "
                  f"{c['log']['path']} -> {c['log']['status']}  ({c['note']})")

    # 빈도 시나리오
    clf = Classifier(meta)
    fired = collections.Counter()
    first = {}
    for i, s in enumerate(burst_cases(meta)):
        stage, _ = clf.classify(s["log"], ts=s["ts"])
        fired[stage] += 1
        first.setdefault(stage, i + 1)
    for key, *_ in BURSTS:
        total += 1
        n = meta["bursts"][key][0]
        if fired[key] >= 1 and first[key] == (n if key == "F1" else meta["bursts"]["F1"][0] + n):
            if a.verbose:
                print(f"OK   {key} 가 {n}번째 요청에서 발생")
        else:
            fails += 1
            print(f"FAIL {key} 기대: {n}번째 요청에서 발생 / 결과: {dict(fired)}")

    print(f"\n{total - fails}/{total} 통과")
    sys.exit(1 if fails else 0)


def iter_log_events(path: str):
    """app.log(한 줄 = 요청 JSON) 또는 Wazuh archives.json/alerts.json(data 안에 필드)을 읽는다."""
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ev = obj.get("data") if isinstance(obj.get("data"), dict) else obj
            if "path" in ev and "method" in ev:
                ts = ev.get("timestamp") or obj.get("timestamp")
                yield ev, ts


def parse_ts(s) -> float | None:
    if not s:
        return None
    s = str(s).replace("Z", "+00:00")
    s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)  # +0900 → +09:00
    try:
        return dt.datetime.fromisoformat(s).timestamp()
    except ValueError:
        return None


def endpoint_template(method: str, path: str) -> str:
    p = path.split("?", 1)[0]
    p = re.sub(r"/\d+(?=/|$)", "/{n}", p)
    return f"{method} {p}"


def cmd_replay(a) -> None:
    meta = load_meta(a.meta)
    clf = Classifier(meta)
    order = ["L1", "L2", "OTHER", "L3E", "L3", "F1", "F2"]
    rank = {k: i for i, k in enumerate(order)}
    total = scoped = undoc = 0
    by_stage = collections.Counter()
    first_seen: dict[str, str] = {}
    per_ip: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    top_ep = collections.Counter()

    events = list(iter_log_events(a.logfile))
    events.sort(key=lambda e: parse_ts(e[1]) or 0)
    for ev, ts in events:
        total += 1
        if not re.match(API_SCOPE_REGEX, str(ev.get("path", ""))):
            continue
        scoped += 1
        stage, _ = clf.classify(ev, ts=parse_ts(ts))
        if stage is None:
            continue
        undoc += 1
        by_stage[stage] += 1
        first_seen.setdefault(stage, str(ts))
        per_ip[str(ev.get("client_ip", "?"))][stage] += 1
        top_ep[endpoint_template(str(ev.get("method")), str(ev.get("path")))] += 1

    print(f"읽은 요청 {total}건, 검사 대상(/api) {scoped}건, 명세 밖 {undoc}건\n")
    print("※ 빈도 룰(F1/F2)이 울린 요청은 L1/L3 대신 F1/F2로 집계됩니다 (Wazuh에서도 그 요청은 F 룰 경보 하나로 기록됩니다)\n")
    print("단계별 경보 (첫 발생 시각)")
    for k in order:
        if by_stage[k]:
            print(f"  {k:<6} {by_stage[k]:>7}건   {first_seen[k]}")
    print("\nIP별 최고 단계")
    for ip, c in sorted(per_ip.items(), key=lambda kv: -max(rank[s] for s in kv[1])):
        top = max(c, key=lambda s: rank[s])
        print(f"  {ip:<18} 최고 {top:<5} " + ", ".join(f"{k}={c[k]}" for k in order if c[k]))
    print(f"\n명세 밖 엔드포인트 상위 {a.top}")
    for ep, n in top_ep.most_common(a.top):
        print(f"  {n:>7}  {ep}")


def cmd_logtest(a) -> None:
    """wazuh-logtest에 케이스를 넣고 실제로 매칭된 룰 ID를 기대값과 비교한다 (Wazuh 서버에서 실행)."""
    meta = load_meta(a.meta)
    ids = meta["rule_ids"]
    cases = [json.loads(l) for l in Path(a.cases).read_text(encoding="utf-8").splitlines()]
    stdin = "\n".join(json.dumps(c["log"], ensure_ascii=False) for c in cases) + "\n"
    proc = subprocess.run([a.logtest], input=stdin, capture_output=True, text=True, timeout=120)
    out = proc.stdout + proc.stderr
    Path(a.raw).write_text(out, encoding="utf-8")

    blocks = re.split(r"\*\*Phase 1", out)[1:]
    if len(blocks) != len(cases):
        print(f"wazuh-logtest 출력에서 결과 {len(blocks)}개를 찾았습니다 (케이스 {len(cases)}개).")
        print(f"원본 출력은 {a.raw} 에 저장했습니다. 직접 확인해 주세요.")
        sys.exit(2)

    undoc_ids = {v for k, v in ids.items() if k.startswith("undoc_") or k == "other_method"}
    undoc_label = f"{min(undoc_ids)}~{max(undoc_ids)}"
    fails = 0
    stuck_in_undoc = 0
    for c, blk in zip(cases, blocks):
        # 룰 ID는 Phase 3(룰 판정) 부분에서만 읽는다.
        # Phase 2(디코딩)에는 user_id: '31' 같은 필드가 찍혀서 그대로 찾으면 잘못 읽힌다.
        p3 = blk.split("**Phase 3", 1)
        m = re.search(r"^\s*id:\s*'(\d+)'", p3[1], re.M) if len(p3) == 2 else None
        got = int(m.group(1)) if m else None
        expect = c["expect"]
        if expect == "OTHER":
            exp_label = undoc_label
            ok = got in undoc_ids
        elif expect is None:
            # 명세 안 요청은 기반 룰(레벨 0)에서 끝난다. /api가 아니면 이 룰과 무관하다.
            in_scope = re.match(API_SCOPE_REGEX, c["log"]["path"])
            exp_label = str(ids["base"]) if in_scope else "이 룰과 무관"
            ok = got == ids["base"] if in_scope else (got is None or not (ids["base"] <= got < ids["base"] + 30))
        else:
            exp_label = str(ids[expect])
            ok = got == ids[expect]
            stuck_in_undoc += (not ok and got in undoc_ids)
        fails += not ok
        if not ok or a.verbose:
            print(f"{'OK  ' if ok else 'FAIL'} 기대={exp_label:<12} 결과={got!s:<7} "
                  f"{c['log']['method']} {c['log']['path']} -> {c['log']['status']} ({c['note']})")
    print(f"\n{len(cases) - fails}/{len(cases)} 통과  (원본 출력: {a.raw})")
    if stuck_in_undoc:
        other = "field" if meta.get("status_option", "static") == "static" else "static"
        print(f"\n단계 케이스 {stuck_in_undoc}개가 '명세 밖 판정' 룰({undoc_label})에서 멈췄습니다. 응답 코드 필드 해석 문제일 수 있습니다.")
        print(f"  python3 gen_shadow_rules.py build --spec openapi.yaml --base-id {ids['base']} --status-option {other}")
    sys.exit(1 if fails else 0)


def main() -> None:
    p = argparse.ArgumentParser(description="OpenAPI 명세 → Wazuh Shadow API 탐지 룰 생성기")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="룰 XML 생성")
    b.add_argument("--spec", required=True, help="openapi.yaml 경로 또는 URL (예: http://192.168.20.10/docs/openapi.yaml)")
    b.add_argument("--allowlist", default=str(DEFAULT_ALLOWLIST), help="명세 밖 예외 목록 YAML")
    b.add_argument("--out", default=str(DEFAULT_RULES))
    b.add_argument("--meta", default=str(DEFAULT_META))
    b.add_argument("--cases", default=str(DEFAULT_CASES))
    b.add_argument("--status-option", choices=["static", "field"], default="static",
                   help="응답 코드를 Wazuh 정적 필드(<status>)로 볼지 동적 필드(<field name=status>)로 볼지")
    b.add_argument("--base-id", type=int, default=100200, help="룰 ID 시작 번호 (100000~120000 사이, 30칸 사용)")
    b.add_argument("--f1-count", type=int, default=20)
    b.add_argument("--f1-window", type=int, default=30)
    b.add_argument("--f2-count", type=int, default=10)
    b.add_argument("--f2-window", type=int, default=60)
    b.add_argument("--burst-ignore", type=int, default=60,
                   help="빈도 룰이 한 번 울린 뒤 다시 울리지 않는 시간(초). 0이면 매번 울림")
    b.set_defaults(func=cmd_build)

    t = sub.add_parser("test", help="룰 로직을 파이썬으로 재현해 테스트 케이스 검증")
    t.add_argument("--meta", default=str(DEFAULT_META))
    t.add_argument("--cases", default=str(DEFAULT_CASES))
    t.add_argument("-v", "--verbose", action="store_true")
    t.set_defaults(func=cmd_test)

    r = sub.add_parser("replay", help="기존 로그를 룰 로직으로 다시 판정")
    r.add_argument("logfile", help="app.log 또는 archives.json")
    r.add_argument("--meta", default=str(DEFAULT_META))
    r.add_argument("--top", type=int, default=15)
    r.set_defaults(func=cmd_replay)

    lt = sub.add_parser("logtest", help="Wazuh 서버의 wazuh-logtest로 실제 룰 매칭 확인")
    lt.add_argument("--meta", default=str(DEFAULT_META))
    lt.add_argument("--cases", default=str(DEFAULT_CASES))
    lt.add_argument("--logtest", default="/var/ossec/bin/wazuh-logtest")
    lt.add_argument("--raw", default=str(HERE / "logtest_output.txt"))
    lt.add_argument("-v", "--verbose", action="store_true")
    lt.set_defaults(func=cmd_logtest)

    a = p.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
