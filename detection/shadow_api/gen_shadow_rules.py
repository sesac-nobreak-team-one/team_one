#!/usr/bin/env python3
"""
OpenAPI 명세 → Wazuh Shadow API 탐지 룰 생성기

openapi.yaml을 허용 목록(Allowlist)으로 삼아, JSON 액세스 로그의 API 요청 중
명세에 정의되지 않은 (메서드 + 경로) 호출을 탐지하는 Wazuh 커스텀 룰 XML을 생성한다.

하위 명령:
  build    명세를 읽어 Wazuh 룰 XML, 메타데이터, 테스트 케이스를 생성한다
  test     생성된 룰 로직을 파이썬으로 재현해 테스트 케이스를 검증한다 (Wazuh 불필요)
  replay   기존 로그(app.log / archives.json)를 룰 로직으로 판정해 단계별로 집계한다
  logtest  Wazuh 서버에서 wazuh-logtest에 테스트 케이스를 주입해 실제 룰 매칭을 검증한다

필요 패키지: PyYAML (pip install pyyaml)
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
except ImportError:
    sys.exit("PyYAML이 필요합니다: pip install pyyaml")

SCRIPT_DIR = Path(__file__).resolve().parent
RULES_FILENAME = "shadow_api_rules.xml"
CASES_FILENAME = "testcases.jsonl"
META_FILENAME = "rules_meta.json"
ALLOWLIST_FILENAME = "shadow_api_allowlist.yaml"
LOGTEST_RAW_FILENAME = "logtest_output.txt"

HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")

# 기본 API 검사 범위 정규식 (--scope-regex 미지정 및 자동 추론 불가 시 사용)
DEFAULT_SCOPE_REGEX = r"^/+api(?:/|\?|$)"

# 응답 상태 코드별 탐지 단계 (순서가 판정 우선순위)
#   L1 (404/405): 존재하지 않는 경로 탐색 또는 허용되지 않은 메서드 호출
#   L2 (401/403): 문서화되지 않은 API가 존재하나 인증/권한에 의해 차단됨
#   L3 (2xx)    : 문서화되지 않은 Shadow API 호출 성공
#   L3E (5xx)   : 문서화되지 않은 API 호출 중 서버 내부 오류 유발
STAGES = [
    # (키, ID 오프셋, 레벨, 상태 코드 정규식, 그룹명, 설명 라벨)
    ("L1",  10, 5,  r"^40[45]$", "shadow_api_recon",     "L1 정찰"),
    ("L2",  11, 8,  r"^40[13]$", "shadow_api_discovery", "L2 발견"),
    ("L3",  12, 12, r"^2\d\d$",  "shadow_api_exploit",   "L3 악용"),
    ("L3E", 13, 10, r"^5\d\d$",  "shadow_api_error",     "L3-E 서버 오류"),
]
OTHER_LEVEL = 6  # 명세 밖 요청 중 위 상태 코드에 해당하지 않는 경우 (400, 422, 3xx 등)

# 동일 client_ip 기준 단시간 반복 호출(Burst) 탐지 룰
BURSTS = [
    # (키, ID 오프셋, 레벨, 대상 단계, 기본 횟수, 기본 시간(초), 그룹명, 설명 라벨, MITRE ID)
    ("F1", 20, 10, "L1", 20, 30, "shadow_api_recon_burst", "F1 자동화 정찰", "T1595.003"),
    ("F2", 21, 14, "L3", 10, 60, "shadow_api_mass_exfil", "F2 대량 유출",   "T1119"),
]
STAGE_MITRE = {"L3": "T1190"}

PARAM_RE = re.compile(r"\{([^/{}]+)\}")


# ─────────────────────────────────────────────────────────────────────────────
# 1. OpenAPI 명세 파싱 및 경로 정규식 변환
# ─────────────────────────────────────────────────────────────────────────────
def read_source(src: str) -> bytes:
    """로컬 파일 경로 또는 HTTP(S) URL에서 OpenAPI 명세 원문을 읽는다."""
    if re.match(r"^https?://", src):
        try:
            with urllib.request.urlopen(src, timeout=15) as resp:  # noqa: S310
                return resp.read()
        except OSError as e:
            sys.exit(f"명세를 내려받지 못했습니다: {src}\n  원인: {e}")
    try:
        return Path(src).read_bytes()
    except OSError as e:
        sys.exit(f"명세 파일을 읽지 못했습니다: {src}\n  원인: {e}")


def resolve_ref(spec: dict, obj: dict) -> dict:
    """OpenAPI 문서 내부의 $ref 참조(#/components/... 등)를 찾아 반환한다."""
    if not isinstance(obj, dict) or "$ref" not in obj:
        return obj if isinstance(obj, dict) else {}
    ref = str(obj["$ref"])
    if not ref.startswith("#/"):
        return obj
    cur = spec
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return obj
    return cur if isinstance(cur, dict) else obj


def base_path(spec: dict) -> str:
    """OpenAPI 3.x servers[0].url 또는 Swagger 2.0 basePath에서 기본 경로 프리픽스를 추출한다."""
    if isinstance(spec.get("basePath"), str):
        return spec["basePath"].rstrip("/")
    servers = spec.get("servers") or [{"url": "/"}]
    srv = servers[0] if isinstance(servers[0], dict) else {"url": "/"}
    url = str(srv.get("url", "/"))
    variables = srv.get("variables")
    if isinstance(variables, dict):
        for var_name, var_def in variables.items():
            if isinstance(var_def, dict) and "default" in var_def:
                url = url.replace(f"{{{var_name}}}", str(var_def["default"]))
    path = urllib.parse.urlparse(url).path if "://" in url else url
    return path.rstrip("/")


def extract_param_regexes(spec: dict, path_item: dict, op_item: dict) -> dict[str, str]:
    """경로 및 메서드 정의의 parameters 항목에서 경로 파라미터별 타입 정규식을 추출한다."""
    params: list = []
    if isinstance(path_item.get("parameters"), list):
        params.extend(path_item["parameters"])
    if isinstance(op_item.get("parameters"), list):
        params.extend(op_item["parameters"])

    regexes: dict[str, str] = {}
    for raw_p in params:
        p = resolve_ref(spec, raw_p)
        if p.get("in") != "path" or not p.get("name"):
            continue
        name = str(p["name"])
        schema = resolve_ref(spec, p.get("schema", p))
        ptype = str(schema.get("type", "string")).lower()
        pformat = str(schema.get("format", "")).lower()
        pattern = schema.get("pattern")

        if isinstance(pattern, str) and pattern:
            regexes[name] = f"(?:{pattern.lstrip('^').rstrip('$')})"
        elif ptype == "integer":
            regexes[name] = r"[0-9]+"
        elif ptype == "number":
            regexes[name] = r"[0-9]+(?:\.[0-9]+)?"
        elif pformat == "uuid":
            regexes[name] = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        else:
            regexes[name] = r"[^/?]+"
    return regexes


def collect_operations(
    spec: dict,
    allowlist: list[dict],
    strict_param_types: bool = False,
) -> dict[str, list[dict]]:
    """명세와 예외 목록(allowlist)에서 허용된 HTTP 메서드별 경로 템플릿 목록을 수집한다."""
    prefix = base_path(spec)
    ops: dict[str, list[dict]] = collections.defaultdict(list)
    for raw_path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        norm_path = str(raw_path) if str(raw_path).startswith("/") else f"/{raw_path}"
        full_template = prefix + norm_path
        for method in HTTP_METHODS:
            if method in item and isinstance(item[method], dict):
                param_regexes = extract_param_regexes(spec, item, item[method]) if strict_param_types else {}
                ops[method.upper()].append(
                    {
                        "template": full_template,
                        "source": "openapi",
                        "reason": "",
                        "param_regexes": param_regexes,
                    }
                )
    for entry in allowlist:
        method = str(entry["method"]).upper()
        ops[method].append(
            {
                "template": entry["path"],
                "source": "allowlist",
                "reason": entry.get("reason", ""),
                "param_regexes": {},
            }
        )
    return {m: sorted(v, key=lambda o: o["template"]) for m, v in sorted(ops.items())}


def infer_scope(ops: dict[str, list[dict]]) -> tuple[str, str]:
    """등록된 경로들의 첫 번째 세그먼트에서 API 검사 범위 정규식과 대표 프리픽스를 추론한다."""
    first_segments: set[str] = set()
    for lst in ops.values():
        for o in lst:
            tmpl = str(o["template"]).strip("/")
            if not tmpl:
                return r"^/+(?:[^?]|$)", "/api"
            seg = tmpl.split("/", 1)[0]
            if PARAM_RE.search(seg):
                return r"^/+(?:[^?]|$)", "/api"
            first_segments.add(seg)

    if not first_segments:
        return DEFAULT_SCOPE_REGEX, "/api"

    sorted_segs = sorted(first_segments)
    primary_prefix = "/" + sorted_segs[0]
    if len(sorted_segs) == 1:
        seg_expr = re.escape(sorted_segs[0])
    else:
        seg_expr = "(?:" + "|".join(re.escape(s) for s in sorted_segs) + ")"
    return rf"^/+{seg_expr}(?:/|\?|$)", primary_prefix


def load_allowlist(path: Path) -> list[dict]:
    """명세 외 정상 예외 API 목록(YAML)을 읽는다."""
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


def template_to_regex(template: str, param_regexes: dict[str, str] | None = None) -> str:
    """경로 템플릿(/api/v2/products/{id})을 PCRE2 정규식으로 변환한다."""
    param_regexes = param_regexes or {}
    out: list[str] = []
    last = 0
    for m in PARAM_RE.finditer(template):
        out.append(re.escape(template[last:m.start()]))
        out.append(param_regexes.get(m.group(1), r"[^/?]+"))
        last = m.end()
    out.append(re.escape(template[last:]))
    return "".join(out)


def method_allow_regex(ops: list[dict]) -> str:
    """단일 HTTP 메서드에 허용된 모든 경로를 하나의 정규식으로 결합한다 (끝 슬래시 및 쿼리스트링 허용)."""
    alts = sorted({template_to_regex(o["template"], o.get("param_regexes")) for o in ops})
    return r"^(?:" + "|".join(alts) + r")/*(?:\?.*)?$"


def methods_regex(methods) -> str:
    return r"^(?:" + "|".join(sorted(methods)) + r")$"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Wazuh 룰 ID 배치 및 XML 생성
# ─────────────────────────────────────────────────────────────────────────────
def rule_ids(base_id: int, methods: list[str]) -> dict:
    ids = {"base": base_id, "other_method": base_id + 1}
    for i, m in enumerate(methods):
        ids[f"undoc_{m}"] = base_id + 2 + i
    if 2 + len(methods) > 10:
        sys.exit("명세 메서드 종류가 너무 많아 룰 ID 블록(10칸)을 넘습니다.")
    for key, offset, *_ in STAGES:
        ids[key] = base_id + offset
    for key, offset, *_ in BURSTS:
        ids[key] = base_id + offset
    return ids


def x(text: str) -> str:
    return escape(text, {'"': "&quot;"})


def field(name: str, regex: str, negate: bool = False) -> str:
    neg = ' negate="yes"' if negate else ""
    return f'    <field name="{name}" type="pcre2"{neg}>{x(regex)}</field>'


def status_cond(regex: str, option: str) -> str:
    """응답 상태 코드 매칭 태그 생성 (static: <status>, field: <field name="status">)."""
    if option == "field":
        return field("status", regex)
    return f'    <status type="pcre2">{x(regex)}</status>'


def build_xml(ops: dict[str, list[dict]], ids: dict, bursts: dict, meta: dict) -> str:
    methods = list(ops.keys())
    sopt = meta["status_option"]
    scope_regex = meta.get("scope_regex", DEFAULT_SCOPE_REGEX)
    L: list[str] = []
    L.append("<!--")
    L.append("  Shadow API 탐지 룰 (자동 생성 파일: 직접 수정하지 말고 gen_shadow_rules.py build 로 재생성하세요)")
    L.append(f"  생성 시각 : {meta['generated_at']}")
    L.append(f"  명세 원본 : {meta['spec_source']}")
    L.append(f"  명세 SHA256: {meta['spec_sha256']}")
    L.append(f"  명세 작업 수: {meta['operation_count']} (예외 목록 {meta['allowlist_count']}건 포함)")
    L.append(f"  검사 범위 : {scope_regex}")
    L.append(f"  파라미터 타입 검증: {'strict' if meta.get('strict_param_types') else 'any ([^/?]+)'}")
    L.append(f"  status 매칭: {meta['status_option']}")
    for m in methods:
        for o in ops[m]:
            tag = "  [예외] " + o["reason"] if o["source"] == "allowlist" else ""
            L.append(f"    {m:<7} {o['template']}{tag}")
    L.append("-->")
    L.append('<group name="shadow_api,">')
    L.append("")

    # 1. 기반 룰: 검사 범위 내 JSON API 요청 필터링 (명세 내 정상 요청은 레벨 0으로 종료)
    L.append("  <!-- 기반: API 범위 내 요청. 명세에 등록된 정상 요청은 여기서 끝난다 (레벨 0 = 경보 없음) -->")
    L.append(f'  <rule id="{ids["base"]}" level="0">')
    L.append("    <decoded_as>json</decoded_as>")
    L.append(field("method", r"^[A-Za-z]+$"))
    L.append(status_cond(r"^\d{3}$", sopt))
    L.append(field("path", scope_regex))
    L.append("    <description>API 요청</description>")
    L.append("  </rule>")
    L.append("")

    # 2. 명세 밖 판정: 미정의 HTTP 메서드 및 메서드별 미정의 경로
    L.append("  <!-- 명세 밖 판정: 명세에 정의되지 않은 HTTP 메서드 -->")
    L.append(f'  <rule id="{ids["other_method"]}" level="{OTHER_LEVEL}">')
    L.append(f'    <if_sid>{ids["base"]}</if_sid>')
    L.append(field("method", methods_regex(methods), negate=True))
    L.append("    <description>[Shadow API] 명세 밖 호출: $(client_ip) $(method) $(path)</description>")
    L.append("    <group>shadow_api_undocumented,</group>")
    L.append("  </rule>")
    for m in methods:
        rid = ids[f"undoc_{m}"]
        L.append("")
        L.append(f"  <!-- 명세 밖 판정: {m} 요청이나 허용된 {m} 경로({len(ops[m])}개)에 매칭되지 않음 -->")
        L.append(f'  <rule id="{rid}" level="{OTHER_LEVEL}">')
        L.append(f'    <if_sid>{ids["base"]}</if_sid>')
        L.append(field("method", f"^{m}$"))
        L.append(field("path", method_allow_regex(ops[m]), negate=True))
        L.append("    <description>[Shadow API] 명세 밖 호출: $(client_ip) $(method) $(path)</description>")
        L.append("    <group>shadow_api_undocumented,</group>")
        L.append("  </rule>")
    L.append("")

    # 3. 응답 상태 코드별 공격 단계 분류
    L.append("  <!-- 단계: 명세 밖 호출을 응답 상태 코드로 분류 -->")
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

    # 4. 동일 IP 단시간 반복 호출(Burst) 탐지
    L.append("  <!-- 빈도: 동일 client_ip의 단시간 반복 호출 -->")
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
# 3. 룰 판정 파이썬 시뮬레이터 (test / replay 공용)
# ─────────────────────────────────────────────────────────────────────────────
class Classifier:
    def __init__(self, meta: dict):
        self.ids = meta["rule_ids"]
        self.scope = re.compile(meta.get("scope_regex", DEFAULT_SCOPE_REGEX))
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
        """이벤트를 판정해 (단계 키 또는 None, 경보 레벨)을 반환한다."""
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
# 4. 명세 기반 동적 테스트 케이스 생성
# ─────────────────────────────────────────────────────────────────────────────
def sample_path(template: str, param_regexes: dict[str, str] | None = None, value: str = "7") -> str:
    """경로 템플릿의 {param} 자리에 타입에 맞는 샘플 값을 채운다."""
    param_regexes = param_regexes or {}

    def _repl(m: re.Match) -> str:
        preg = param_regexes.get(m.group(1), "")
        if "0-9a-fA-F" in preg:
            return "550e8400-e29b-41d4-a716-446655440000"
        return value

    return PARAM_RE.sub(_repl, template)


def _pick_undoc_method_for_path(ops: dict[str, list[dict]]) -> tuple[str, str]:
    """명세에 존재하는 메서드이지만 해당 경로에는 허용되지 않은 (method, path) 조합을 찾는다."""
    allow_compiled = {m: re.compile(method_allow_regex(lst)) for m, lst in ops.items()}
    for m_cand in sorted(ops.keys()):
        for m_other, lst in ops.items():
            if m_cand == m_other:
                continue
            for o in lst:
                p = sample_path(o["template"], o.get("param_regexes"))
                if not allow_compiled[m_cand].search(p):
                    return m_cand, p
    undoc_m = next((m.upper() for m in HTTP_METHODS if m.upper() not in ops), "OPTIONS")
    first_m = next(iter(ops))
    first_p = sample_path(ops[first_m][0]["template"], ops[first_m][0].get("param_regexes"))
    return undoc_m, first_p


def make_cases(
    ops: dict[str, list[dict]],
    scope_regex: str = DEFAULT_SCOPE_REGEX,
    scope_prefix: str = "/api",
) -> list[dict]:
    """입력된 OpenAPI 명세에서 정상/비정상 테스트 케이스를 동적으로 생성한다."""
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
    # 명세 내 정상 요청 (경보 없음)
    for m, lst in ops.items():
        for o in lst:
            p = sample_path(o["template"], o.get("param_regexes"))
            cases.append(ev(m, p, 200, f"명세 안 {m} {o['template']}", None))

    primary_method = "GET" if "GET" in ops else next(iter(ops))
    primary_op = ops[primary_method][0]
    primary_path = sample_path(primary_op["template"], primary_op.get("param_regexes"))

    cases.append(ev(primary_method, f"{primary_path}?limit=20&offset=0", 200, "명세 안 + 쿼리스트링", None))
    cases.append(ev(primary_method, f"{primary_path.rstrip('/')}/", 200, "명세 안 + 끝 슬래시", None))
    cases.append(ev(primary_method, f"{primary_path}?status=paid", 401, "명세 안 + 401 (정상 API의 인증 실패는 범위 밖)", None))

    scope_re = re.compile(scope_regex)
    if not scope_re.search("/products.php"):
        cases.append(ev("GET", "/products.php", 200, "API 범위 밖 정적 페이지", None))
    if not scope_re.search("/docs/openapi.yaml"):
        cases.append(ev("GET", "/docs/openapi.yaml", 200, "API 범위 밖 명세 파일", None))

    # 명세 밖 비정상/Shadow API 요청 (단계별 경보 검증)
    undoc_methods = [m.upper() for m in HTTP_METHODS if m.upper() not in ops]
    undoc_m1 = undoc_methods[0] if len(undoc_methods) >= 1 else "OPTIONS"
    undoc_m2 = undoc_methods[1] if len(undoc_methods) >= 2 else undoc_m1
    mismatch_m, mismatch_path = _pick_undoc_method_for_path(ops)
    pref = scope_prefix.rstrip("/")

    cases += [
        ev(primary_method, f"{pref}/v999/__undoc_probe__/1", 404, "없는 버전 탐색", "L1"),
        ev(primary_method, f"{pref}/__undoc_admin__", 404, "없는 경로 탐색", "L1"),
        ev(primary_method, f"{primary_path}/__undoc_subpath__", 404, "명세 경로 하위의 없는 경로", "L1"),
        ev(mismatch_m, mismatch_path, 405, "명세 경로 + 허용되지 않은 메서드", "L1"),
        ev(undoc_m1, primary_path, 405, f"명세에 없는 메서드 ({undoc_m1})", "L1"),
        ev(undoc_m2, primary_path, 405, f"명세에 없는 메서드 ({undoc_m2})", "L1"),
        ev(primary_method, f"{pref}/v1/__shadow_users__/1", 401, "Shadow API 존재 확인 (401)", "L2"),
        ev(primary_method, f"{pref}/v1/__shadow_any__", 401, "숨은 API 인증 차단 (401)", "L2"),
        ev(primary_method, f"/{pref}/v1/__shadow_users__/1", 401, "슬래시 중복 우회 시도", "L2"),
        ev(primary_method, f"{pref}/v1/__shadow_users__/2", 200, "Shadow API 호출 성공 (200)", "L3", user_id=31),
        ev(primary_method, f"{pref}/v1/__shadow_diag__/ping?host=127.0.0.1", 200, "Shadow API 진단 호출 성공", "L3", user_id=31),
        ev(primary_method, f"{pref}/v1/__shadow_diag__/ping?host=x;id", 500, "Shadow API 서버 오류 (500)", "L3E", user_id=31),
        ev(primary_method, f"{pref}/v1/__shadow_users__/abc", 400, "명세 밖 + 기타 상태 코드 (400)", "OTHER", user_id=31),
    ]
    return cases


def burst_cases(meta: dict) -> list[dict]:
    """빈도(Burst) 룰 검증용 연속 호출 시나리오를 생성한다."""
    seq = []
    pref = meta.get("scope_prefix", "/api").rstrip("/")
    ops = meta.get("operations", {})
    method = "GET" if "GET" in ops else next(iter(ops), "GET")
    n1, _, _ = meta["bursts"]["F1"]
    for i in range(n1):
        seq.append({"ts": i * 1.0, "log": {"client_ip": "192.168.80.66", "method": method,
                                           "path": f"{pref}/__fuzz_{i}__", "status": 404}})
    n2, _, _ = meta["bursts"]["F2"]
    for i in range(n2):
        seq.append({"ts": 100 + i * 2.0, "log": {"client_ip": "192.168.80.66", "method": method,
                                                 "path": f"{pref}/v1/__shadow_users__/{i + 1}", "status": 200}})
    return seq


# ─────────────────────────────────────────────────────────────────────────────
# 5. CLI 하위 명령 (build / test / replay / logtest)
# ─────────────────────────────────────────────────────────────────────────────
def resolve_allowlist_path(out_dir: Path, explicit: str | None) -> Path:
    """예외 목록(allowlist) 경로를 결정한다 (명시 경로 -> 출력 디렉토리 -> 스크립트 디렉토리 순)."""
    if explicit:
        return Path(explicit)
    in_out_dir = out_dir / ALLOWLIST_FILENAME
    if in_out_dir.exists():
        return in_out_dir
    return SCRIPT_DIR / ALLOWLIST_FILENAME


def cmd_build(a) -> None:
    out_dir = Path(a.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = Path(a.out) if a.out else out_dir / RULES_FILENAME
    meta_path = Path(a.meta) if a.meta else out_dir / META_FILENAME
    cases_path = Path(a.cases) if a.cases else out_dir / CASES_FILENAME
    allowlist_path = resolve_allowlist_path(out_dir, a.allowlist)

    for p in (out_path, meta_path, cases_path):
        p.parent.mkdir(parents=True, exist_ok=True)

    raw = read_source(a.spec)
    spec = yaml.safe_load(raw)
    if not isinstance(spec, dict) or "paths" not in spec:
        sys.exit(f"{a.spec}: OpenAPI 명세(paths)를 찾지 못했습니다.")
    allowlist = load_allowlist(allowlist_path)
    ops = collect_operations(spec, allowlist, strict_param_types=a.strict_param_types)
    if not ops:
        sys.exit(f"{a.spec}: 명세에서 등록된 HTTP 메서드/경로를 찾지 못했습니다.")

    inferred_regex, inferred_prefix = infer_scope(ops)
    scope_regex = a.scope_regex or inferred_regex
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
        "scope_regex": scope_regex,
        "scope_prefix": inferred_prefix,
        "strict_param_types": bool(a.strict_param_types),
        "status_option": a.status_option,
        "rule_ids": ids,
        "bursts": bursts,
        "operations": ops,
    }
    out_path.write_text(build_xml(ops, ids, bursts, meta), encoding="utf-8")
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    cases = make_cases(ops, scope_regex=scope_regex, scope_prefix=inferred_prefix)
    with open(cases_path, "w", encoding="utf-8") as f:
        for c in cases:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    print(f"명세 작업 {meta['operation_count']}개 (예외 {len(allowlist)}건) → {out_path}")
    print(f"  검사 범위 정규식 : {scope_regex}")
    for m, lst in ops.items():
        print(f"  {m:<7} {len(lst)}개  명세 밖 룰 ID {ids['undoc_' + m]}")
    print(f"  기타 메서드        명세 밖 룰 ID {ids['other_method']}")
    print("  단계 룰: " + ", ".join(f"{k}={ids[k]}" for k, *_ in STAGES))
    print("  빈도 룰: " + ", ".join(f"{k}={ids[k]} ({bursts[k][0]}회/{bursts[k][1]}초)" for k, *_ in BURSTS))
    print(f"메타데이터       → {meta_path}")
    print(f"테스트 케이스 {len(cases)}개 → {cases_path}")


def pause_if_interactive() -> None:
    """독립 콘솔 창(탐색기 주소창, 실행 창 등)에서 실행 시 창이 바로 닫히지 않도록 대기한다."""
    if sys.stdin is not None and sys.stdin.isatty():
        try:
            input("\n종료하려면 Enter 키를 누르세요...")
        except EOFError:
            pass


def fail_exit(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    pause_if_interactive()
    sys.exit(code)


def load_meta(path: Path) -> dict:
    if not path.exists():
        fail_exit(f"[오류] 현재 실행 위치에 {path.name} 파일이 없습니다: {path}\n먼저 해당 폴더에서 build 명령을 실행하거나 -d 옵션으로 폴더를 지정하세요.")
    meta = json.loads(path.read_text(encoding="utf-8"))
    meta["bursts"] = {k: tuple(v) for k, v in meta["bursts"].items()}
    return meta


def cmd_test(a) -> None:
    out_dir = Path(a.out_dir).resolve()
    meta_path = Path(a.meta).resolve() if a.meta else out_dir / META_FILENAME
    cases_path = Path(a.cases).resolve() if a.cases else out_dir / CASES_FILENAME

    meta = load_meta(meta_path)
    if not cases_path.exists():
        fail_exit(f"[오류] 현재 실행 위치에 {cases_path.name} 파일이 없습니다: {cases_path}")

    print(f"테스트 기준 폴더: {out_dir}")
    print(f"  - 메타데이터  : {meta_path.name}")
    print(f"  - 테스트케이스: {cases_path.name}\n")

    clf = Classifier(meta)
    fails = 0
    total = 0
    for line in cases_path.read_text(encoding="utf-8").splitlines():
        c = json.loads(line)
        got, _ = clf.classify(c["log"])
        total += 1
        ok = got == c["expect"]
        fails += not ok
        if not ok or a.verbose:
            mark = "OK  " if ok else "FAIL"
            print(f"{mark} 기대={c['expect']!s:<5} 결과={got!s:<5} {c['log']['method']:<6} "
                  f"{c['log']['path']} -> {c['log']['status']}  ({c['note']})")

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
    pause_if_interactive()
    if fails:
        sys.exit(1)


def iter_log_events(path: str):
    """JSON 액세스 로그(app.log) 또는 Wazuh 아카이브(archives.json)에서 요청 이벤트를 읽는다."""
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
    s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)
    try:
        return dt.datetime.fromisoformat(s).timestamp()
    except ValueError:
        return None


def endpoint_template(method: str, path: str) -> str:
    p = path.split("?", 1)[0]
    p = re.sub(r"/\d+(?=/|$)", "/{n}", p)
    return f"{method} {p}"


def cmd_replay(a) -> None:
    out_dir = Path(a.out_dir).resolve()
    meta_path = Path(a.meta) if a.meta else out_dir / META_FILENAME
    meta = load_meta(meta_path)
    clf = Classifier(meta)
    scope_re = re.compile(meta.get("scope_regex", DEFAULT_SCOPE_REGEX))
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
        if not scope_re.search(str(ev.get("path", ""))):
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

    print(f"읽은 요청 {total}건, 검사 대상 {scoped}건, 명세 밖 {undoc}건\n")
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
    """Wazuh 서버의 wazuh-logtest 바이너리에 테스트 케이스를 주입해 실제 매칭된 룰 ID를 검증한다."""
    out_dir = Path(a.out_dir).resolve()
    meta_path = Path(a.meta) if a.meta else out_dir / META_FILENAME
    cases_path = Path(a.cases) if a.cases else out_dir / CASES_FILENAME
    raw_path = Path(a.raw) if a.raw else out_dir / LOGTEST_RAW_FILENAME

    meta = load_meta(meta_path)
    ids = meta["rule_ids"]
    scope_re = re.compile(meta.get("scope_regex", DEFAULT_SCOPE_REGEX))
    cases = [json.loads(l) for l in cases_path.read_text(encoding="utf-8").splitlines()]
    stdin = "\n".join(json.dumps(c["log"], ensure_ascii=False) for c in cases) + "\n"
    proc = subprocess.run([a.logtest], input=stdin, capture_output=True, text=True, timeout=120)
    out = proc.stdout + proc.stderr
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text(out, encoding="utf-8")

    blocks = re.split(r"\*\*Phase 1", out)[1:]
    if len(blocks) != len(cases):
        print(f"wazuh-logtest 출력에서 결과 {len(blocks)}개를 찾았습니다 (케이스 {len(cases)}개).")
        print(f"원본 출력은 {raw_path} 에 저장했습니다.")
        sys.exit(2)

    undoc_ids = {v for k, v in ids.items() if k.startswith("undoc_") or k == "other_method"}
    undoc_label = f"{min(undoc_ids)}~{max(undoc_ids)}"
    fails = 0
    stuck_in_undoc = 0
    for c, blk in zip(cases, blocks):
        p3 = blk.split("**Phase 3", 1)
        m = re.search(r"^\s*id:\s*'(\d+)'", p3[1], re.M) if len(p3) == 2 else None
        got = int(m.group(1)) if m else None
        expect = c["expect"]
        if expect == "OTHER":
            exp_label = undoc_label
            ok = got in undoc_ids
        elif expect is None:
            in_scope = scope_re.search(c["log"]["path"])
            exp_label = str(ids["base"]) if in_scope else "범위 밖"
            ok = got == ids["base"] if in_scope else (got is None or not (ids["base"] <= got < ids["base"] + 30))
        else:
            exp_label = str(ids[expect])
            ok = got == ids[expect]
            stuck_in_undoc += (not ok and got in undoc_ids)
        fails += not ok
        if not ok or a.verbose:
            print(f"{'OK  ' if ok else 'FAIL'} 기대={exp_label:<12} 결과={got!s:<7} "
                  f"{c['log']['method']} {c['log']['path']} -> {c['log']['status']} ({c['note']})")
    print(f"\n{len(cases) - fails}/{len(cases)} 통과  (원본 출력: {raw_path})")
    if stuck_in_undoc:
        other = "field" if meta.get("status_option", "static") == "static" else "static"
        print(f"\n단계 케이스 {stuck_in_undoc}개가 '명세 밖 판정' 룰({undoc_label})에서 멈췄습니다.")
        print(f"  python3 gen_shadow_rules.py build --spec openapi.yaml --base-id {ids['base']} --status-option {other}")
    sys.exit(1 if fails else 0)


def main() -> None:
    p = argparse.ArgumentParser(description="OpenAPI 명세 → Wazuh Shadow API 탐지 룰 생성기")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="Wazuh 룰 XML 생성")
    b.add_argument("--spec", required=True, help="openapi.yaml 파일 경로 또는 URL")
    b.add_argument("-d", "--out-dir", default=".",
                   help="생성 파일들이 저장될 디렉토리 (기본값: 현재 실행 디렉토리 '.')")
    b.add_argument("--allowlist", default=None, help="명세 외 예외 허용 목록 YAML 경로")
    b.add_argument("--out", default=None, help=f"생성할 Wazuh 룰 XML 파일 경로 (기본값: <out-dir>/{RULES_FILENAME})")
    b.add_argument("--meta", default=None, help=f"생성할 메타데이터 JSON 경로 (기본값: <out-dir>/{META_FILENAME})")
    b.add_argument("--cases", default=None, help=f"생성할 테스트 케이스 JSONL 경로 (기본값: <out-dir>/{CASES_FILENAME})")
    b.add_argument("--scope-regex", default=None,
                   help="API 검사 범위 정규식 (생략 시 openapi.yaml 경로 프리픽스에서 자동 추론)")
    b.add_argument("--strict-param-types", action="store_true",
                   help="경로 파라미터의 OpenAPI schema.type(integer, number, uuid 등)을 정규식에 반영")
    b.add_argument("--status-option", choices=["static", "field"], default="static",
                   help="응답 코드 필드 매칭 방식 (static: <status>, field: <field name=status>)")
    b.add_argument("--base-id", type=int, default=100200, help="룰 ID 시작 번호 (기본값: 100200, 30칸 사용)")
    b.add_argument("--f1-count", type=int, default=20)
    b.add_argument("--f1-window", type=int, default=30)
    b.add_argument("--f2-count", type=int, default=10)
    b.add_argument("--f2-window", type=int, default=60)
    b.add_argument("--burst-ignore", type=int, default=60,
                   help="빈도 룰 발화 후 재발화 억제 시간(초)")
    b.set_defaults(func=cmd_build)

    t = sub.add_parser("test", help="생성된 룰 로직으로 테스트 케이스 검증")
    t.add_argument("-d", "--out-dir", default=".", help="메타데이터 및 테스트 케이스가 위치한 디렉토리 (기본값: '.')")
    t.add_argument("--meta", default=None)
    t.add_argument("--cases", default=None)
    t.add_argument("-v", "--verbose", action="store_true")
    t.set_defaults(func=cmd_test)

    r = sub.add_parser("replay", help="기존 로그를 룰 로직으로 판정 및 집계")
    r.add_argument("logfile", help="app.log 또는 archives.json 경로")
    r.add_argument("-d", "--out-dir", default=".", help="메타데이터(rules_meta.json)가 위치한 디렉토리 (기본값: '.')")
    r.add_argument("--meta", default=None)
    r.add_argument("--top", type=int, default=15)
    r.set_defaults(func=cmd_replay)

    lt = sub.add_parser("logtest", help="Wazuh 서버의 wazuh-logtest로 실제 매칭 검증")
    lt.add_argument("-d", "--out-dir", default=".", help="메타데이터 및 테스트 케이스가 위치한 디렉토리 (기본값: '.')")
    lt.add_argument("--meta", default=None)
    lt.add_argument("--cases", default=None)
    lt.add_argument("--logtest", default="/var/ossec/bin/wazuh-logtest")
    lt.add_argument("--raw", default=None)
    lt.add_argument("-v", "--verbose", action="store_true")
    lt.set_defaults(func=cmd_logtest)

    a = p.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
