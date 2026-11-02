#!/usr/bin/env python3
"""
미등록 API 접근 탐지 Grafana 대시보드 생성기

    python3 build_dashboard.py                           # -> shadow_api_dashboard.json
    python3 build_dashboard.py --ds-type elasticsearch   # 내장 Elasticsearch 데이터 소스를 쓸 때

화면 구성 (위에서 아래로)
    범례     위험도 4등급 한 줄
    개요     최고 위험도, 핵심 수치, 보안 계층별 탐지 현황
    탐지 현황 위험도별 건수, 미등록 API 호출 순위, 계정별 조회 리소스
    의심 IP  IP 목록 (IP를 누르면 아래 'IP 상세'가 그 IP로 바뀜)
    IP 상세  선택한 IP 하나의 위험도 변화, 요청 빈도와 판정 기준선, 호출한 API, 경보 원본
    수집 상태 로그 수신 시각, 전체 API 요청, 미등록 비율, 탐지 기준 버전

설계 원칙
- 판정은 Wazuh 룰이 이미 했으므로 대시보드는 rule.groups 와 rule.level 만 씁니다.
  경로 접두어(/api/v2 등)로 다시 판정하지 않습니다.
- 위험도는 rule.level 범위로 나누고, 이름은 국가 사이버위기 경보 단계를 씁니다:
  경보 없음 = 정상, 관심 ≤6, 주의 7~11, 경계 12~13, 심각 ≥14.
  탐지 룰의 레벨이 바뀌어도 이 범위만 맞으면 그대로 동작합니다.
- 화면 문구는 특정 환경 이름(제품명, 공격 도구명, 로그 파일명)을 쓰지 않습니다.
  환경에 따라 달라지는 값은 아래 '환경 설정' 상수에 모았습니다.
- Wazuh 인덱스의 data.* 필드는 keyword 라 합계 대신 count, cardinality, terms 를 쓰고,
  max/min 은 rule.level(숫자)과 timestamp(날짜)에만 씁니다.
"""
import argparse
import json
import re
from urllib.parse import quote
from pathlib import Path

HERE = Path(__file__).resolve().parent
META_PATH = HERE.parent / "rules_meta.json"

TF = "timestamp"
UID = "shadow-api-detect"

# ---------------------------------------------------------------------------
# 환경 설정: 다른 환경에 옮길 때 이 부분만 고칩니다
# ---------------------------------------------------------------------------
Q_API_LOG = "location:*app.log*"                       # 애플리케이션 API 로그 (archives)
Q_API_REQ = Q_API_LOG + " AND (data.path:\\/api* OR data.path:\\/\\/*)"
Q_IDS = "rule.groups:suricata AND rule.level:>=3"                         # IDS/IPS 경보
Q_WAF = "(rule.groups:modsecurity OR rule.description:*ModSecurity*) AND rule.level:>=3"   # WAF 경보
Q_SIEM_BASE = "rule.groups:web AND rule.level:>=3 AND NOT rule.groups:(shadow_api OR suricata OR modsecurity)"
Q_BLOCK = "rule.groups:active_response"                # 자동 차단 기록

# ---------------------------------------------------------------------------
# 탐지 룰 그룹 (gen_shadow_rules.py 가 붙이는 이름)
# ---------------------------------------------------------------------------
G_ALL = "rule.groups:shadow_api AND rule.level:>0"   # 레벨 0 = 명세 안 요청 (archives 에만 있음)
G_PERREQ = "rule.groups:shadow_api AND rule.level:>0 AND NOT rule.groups:(shadow_api_recon_burst OR shadow_api_mass_exfil)"
G_RESP = "rule.groups:shadow_api_exploit"              # 미등록 API가 2xx로 응답
G_PROBE = "rule.groups:shadow_api_recon"               # 미등록 경로 탐색 (404/405)
G_BURST_PROBE = "rule.groups:shadow_api_recon_burst"   # 대량 탐색
G_BURST_RESP = "rule.groups:shadow_api_mass_exfil"     # 대량 데이터 응답
IPV = 'data.client_ip:"$ip"'

# ---------------------------------------------------------------------------
# 위험도 (rule.level 범위) - 순서형 상태 색. 항상 등급 이름과 함께 표시
# ---------------------------------------------------------------------------
SEV = [  # (이름, from, to, 색, 한 줄 의미)
    ("관심", 1, 6, "#5794f2", "미등록 경로 탐색"),
    ("주의", 7, 11, "#fade2a", "접근 거부 · 서버 오류 · 대량 탐색"),
    ("경계", 12, 13, "#ff9830", "미등록 API 데이터 응답"),
    ("심각", 14, 99, "#f2495c", "대량 데이터 응답"),
]
C_OK = "#73bf69"
C_TEXT = "#d8d9da"
C_TEXT2 = "#9fa3ab"
C_MUTED = "#5a5f6b"
C_OURS = "#e6e6e6"
C_TILE = "#2b2f38"       # 보안 계층 타일 배경


# 계층 상세에서 고를 수 있는 보안 계층 (키, 표시 이름, 경보 쿼리)
LAYERS = [
    ("spec", "API 명세 대조", G_ALL),
    ("waf", "WAF", Q_WAF),
    ("siem", "SIEM 기본 룰", Q_SIEM_BASE),
    ("ids", "IDS/IPS", Q_IDS),
]
Q_LAYER = "${layer:raw}"   # raw: 루씬 특수문자를 이스케이프하지 않고 쿼리 그대로 넣음
KEEP_VARS = "${ds_alerts:queryparam}&${ds_archives:queryparam}"


def layer_url(query):
    return ("/d/${__dashboard.uid}?" + KEEP_VARS + "&${ip:queryparam}&var-layer=" + quote(query, safe="")
            + "&${__url_time_range}")


def layer_links(title, query):
    return [{"title": f"{title} 경보 상세 보기", "url": layer_url(query), "targetBlank": False, "oneClick": True}]


def sev_mappings(with_null=False):
    out = [{"type": "range", "options": {"from": lo, "to": hi, "result": {"text": name, "color": color, "index": i}}}
           for i, (name, lo, hi, color, _) in enumerate(SEV)]
    if with_null:
        out.append({"type": "special", "options": {"match": "null+nan",
                                                   "result": {"text": "정상", "color": C_OK, "index": len(SEV)}}})
    return out


def sev_query(lo, hi):
    return f"{G_ALL} AND rule.level:[{lo} TO {hi}]"


# ---------------------------------------------------------------------------
# 쿼리 빌더 (OpenSearch / Elasticsearch 데이터 소스 공통 모델)
# ---------------------------------------------------------------------------
class DS:
    type = "grafana-opensearch-datasource"

    @classmethod
    def alerts(cls):
        return {"type": cls.type, "uid": "${ds_alerts}"}

    @classmethod
    def archives(cls):
        return {"type": cls.type, "uid": "${ds_archives}"}


MIXED = {"type": "datasource", "uid": "-- Mixed --"}
EXPR = {"type": "__expr__", "uid": "__expr__"}


def target(ref, ds, query, metrics, buckets, alias=None, hide=False):
    t = {"refId": ref, "datasource": ds, "query": query, "queryType": "lucene", "luceneQueryType": "Metric",
         "metrics": metrics, "bucketAggs": buckets, "timeField": TF}
    if alias:
        t["alias"] = alias
    if hide:
        t["hide"] = True
    return t


def raw_target(ref, ds, query, size=300):
    return {"refId": ref, "datasource": ds, "query": query, "queryType": "lucene", "luceneQueryType": "RawData",
            "metrics": [{"id": "1", "type": "raw_data", "settings": {"size": str(size)}}],
            "bucketAggs": [], "timeField": TF}


def m_count(i="1"):
    return {"id": i, "type": "count"}


def m_field(kind, field, i):
    return {"id": i, "type": kind, "field": field}


def b_date(i="9", interval="auto"):
    return {"id": i, "type": "date_histogram", "field": TF,
            "settings": {"interval": interval, "min_doc_count": "0", "trimEdges": "0"}}


def b_terms(i, field, size, order_by="_count"):
    return {"id": i, "type": "terms", "field": field,
            "settings": {"size": str(size), "order": "desc", "orderBy": order_by, "min_doc_count": "1"}}


def b_filters(i, items):
    return {"id": i, "type": "filters",
            "settings": {"filters": [{"query": q, "label": label} for label, q in items]}}


def one_bucket():
    """전체 범위에 대해 값 1개를 얻기 위한 단일 버킷 (경보에 항상 있는 manager.name)"""
    return [b_terms("2", "manager.name", 1)]


def color_override(name, color):
    return {"matcher": {"id": "byName", "options": name},
            "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": color}}]}


def col(name, display, *props):
    return {"matcher": {"id": "byName", "options": name},
            "properties": [{"id": "displayName", "value": display}, *props]}


def width(px):
    return {"id": "custom.width", "value": px}


def sev_cell():
    return [{"id": "mappings", "value": sev_mappings()},
            {"id": "custom.cellOptions", "value": {"type": "color-background", "mode": "basic"}},
            {"id": "custom.align", "value": "center"}, width(90)]


def gauge_cell(color):
    return [{"id": "custom.cellOptions", "value": {"type": "gauge", "mode": "gradient", "valueDisplayMode": "text"}},
            {"id": "color", "value": {"mode": "fixed", "fixedColor": color}},
            {"id": "min", "value": 0}, {"id": "fieldMinMax", "value": True}]


def ip_link():
    return [{"title": "이 IP 상세 보기", "targetBlank": False,
             "url": "/d/${__dashboard.uid}?" + KEEP_VARS + "&${layer:queryparam}"
                    "&var-ip=${__value.raw}&${__url_time_range}"}]


def thresholds(*steps):
    return {"mode": "absolute", "steps": [{"color": c, "value": v} for v, c in steps]}


TABLE_OPTS = {"showHeader": True, "cellHeight": "md", "frameIndex": 0}
TABLE_DEFAULTS = {"custom": {"align": "auto", "cellOptions": {"type": "auto"}, "inspect": False}}

# ---------------------------------------------------------------------------
# 패널
# ---------------------------------------------------------------------------
_pid = [0]


def panel(kind, title, grid, *, ds=None, targets=None, desc="", options=None,
          field_config=None, transformations=None, **extra):
    _pid[0] += 1
    p = {"id": _pid[0], "type": kind, "title": title, "gridPos": dict(zip("xywh", grid))}
    if desc:
        p["description"] = desc
    if ds is not None:
        p["datasource"] = ds
    if targets is not None:
        p["targets"] = targets
    p["options"] = options or {}
    p["fieldConfig"] = field_config or {"defaults": {}, "overrides": []}
    if transformations:
        p["transformations"] = transformations
    p.update(extra)
    return p


def row(title, y):
    _pid[0] += 1
    return {"id": _pid[0], "type": "row", "title": title, "collapsed": False,
            "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": []}


def stat(title, grid, ds, targets, desc, *, calc="sum", steps=None, unit="none", graph="area",
         mappings=None, no_value="0", text_size=None, color_mode="value", decimals=0):
    opts = {"reduceOptions": {"calcs": [calc], "fields": "", "values": False},
            "colorMode": color_mode, "graphMode": graph, "justifyMode": "center", "textMode": "value",
            "orientation": "auto", "wideLayout": True, "showPercentChange": False,
            "percentChangeColorMode": "standard"}
    if text_size:
        opts["text"] = {"valueSize": text_size}
    defaults = {"unit": unit, "decimals": decimals, "noValue": no_value, "color": {"mode": "thresholds"},
                "thresholds": thresholds(*(steps or [(None, C_TEXT)]))}
    if mappings:
        defaults["mappings"] = mappings
    return panel("stat", title, grid, ds=ds, targets=targets, desc=desc, options=opts,
                 field_config={"defaults": defaults, "overrides": []})


def legend_html():
    chips = "".join(
        f'<span style="display:inline-flex;align-items:center;gap:6px;margin-right:18px;white-space:nowrap">'
        f'<span style="width:12px;height:12px;border-radius:3px;background:{c}"></span>'
        f'<b style="color:{C_TEXT}">{n}</b><span style="color:{C_TEXT2}">{d}</span></span>'
        for n, _, _, c, d in SEV)
    return f'<div style="font-size:14px;line-height:20px;padding-left:2px">{chips}</div>'


def meta_html(meta):
    sha = meta.get("spec_sha256", "?")[:12]
    ids = meta.get("rule_ids", {})
    f1 = meta.get("bursts", {}).get("F1", [20, 30, 60])
    f2 = meta.get("bursts", {}).get("F2", [10, 60, 60])
    rows = [
        ("API 명세", f"<code>{sha}</code> · 등록 API {meta.get('operation_count', '?')}개 · 예외 {meta.get('allowlist_count', 0)}건"),
        ("탐지 규칙", f"ID {ids.get('base', '?')}~{ids.get('F2', '?')} · 생성 {meta.get('generated_at', '?')[:16].replace('T', ' ')}"),
        ("대량 판정", f"탐색 {f1[0]}회/{f1[1]}초 · 데이터 응답 {f2[0]}회/{f2[1]}초"),
    ]
    body = "".join(f'<tr><td style="color:{C_TEXT2};padding:2px 12px 2px 0;white-space:nowrap">{k}</td>'
                   f'<td style="color:{C_TEXT}">{v}</td></tr>' for k, v in rows)
    return f'<table style="font-size:14px;line-height:1.7">{body}</table>'


def layer_detail(P, y):
    """보안 계층 타일에서 고른 계층(layer 변수)의 경보를 보여 주는 구역"""
    A = DS.alerts()
    P.append(row("계층 상세 — ${layer:text}", y)); y += 1

    P.append(panel(
        "timeseries", "위험도별 경보 추이", (0, y, 8, 8), ds=A,
        targets=[target(chr(65 + i), A, f"({Q_LAYER}) AND rule.level:[{lo} TO {hi}]", [m_count()], [b_date()], alias=n)
                 for i, (n, lo, hi, _, _) in enumerate(reversed(SEV))],
        desc="선택한 계층의 경보를 위험도(Wazuh 룰 레벨)별로 쌓아서 보여 줍니다.",
        options={"legend": {"showLegend": True, "displayMode": "list", "placement": "bottom", "calcs": ["sum"]},
                 "tooltip": {"mode": "multi", "sort": "desc"}},
        field_config={"defaults": {
            "unit": "none", "decimals": 0, "min": 0, "color": {"mode": "fixed", "fixedColor": C_TEXT2},
            "custom": {"drawStyle": "bars", "fillOpacity": 100, "lineWidth": 1, "showPoints": "never",
                       "stacking": {"mode": "normal", "group": "A"}, "axisSoftMin": 0}},
            "overrides": [color_override(n, c) for n, _, _, c, _ in SEV]}))

    P.append(panel(
        "table", "룰별 경보", (8, y, 9, 8), ds=A,
        targets=[target("A", A, Q_LAYER, [m_count(), m_field("max", "rule.level", "4")],
                        [b_terms("2", "rule.id", 20), b_terms("3", "rule.description", 1)])],
        desc="어떤 탐지 룰이 몇 번 울렸는지입니다. 설명은 그 룰의 경보 중 가장 흔한 문구 하나를 보여 줍니다.",
        options={**TABLE_OPTS, "sortBy": [{"displayName": "경보", "desc": True}]},
        field_config={"defaults": TABLE_DEFAULTS, "overrides": [
            col("rule.id", "룰 ID", width(80)),
            col("rule.description", "설명 (예시)"),
            col("Count", "경보", *gauge_cell(C_TEXT), width(130)),
            col("Max", "위험도", *sev_cell()),
        ]}))

    ip_fields = [("A", "data.srcip"), ("B", "data.src_ip"), ("C", "data.client_ip")]
    P.append(panel(
        "table", "출발지 IP", (17, y, 7, 8), ds=A,
        targets=[target(ref, A, f"({Q_LAYER}) AND _exists_:{f}", [m_count(), m_field("max", "rule.level", "4")],
                        [b_terms("2", f, 15)]) for ref, f in ip_fields],
        transformations=[
            *[{"id": "organize", "filter": {"id": "byRefId", "options": ref},
               "options": {"renameByName": {f: "IP", "Count": "경보", "Max": "위험도"}}} for ref, f in ip_fields],
            {"id": "merge", "options": {}},
            {"id": "sortBy", "options": {"sort": [{"field": "경보", "desc": True}]}},
        ],
        desc="선택한 계층의 경보를 출발지 IP별로 셉니다. 로그마다 IP 필드 이름이 달라서 웹 접근 로그(srcip), "
             "IDS(src_ip), API 로그(client_ip)를 합쳐 보여 줍니다. IP를 누르면 'IP 상세'가 그 IP로 바뀝니다.",
        options={**TABLE_OPTS},
        field_config={"defaults": TABLE_DEFAULTS, "overrides": [
            col("IP", "IP", {"id": "links", "value": [{"title": "이 IP 상세 보기", "oneClick": True,
                                                      "url": "/d/${__dashboard.uid}?" + KEEP_VARS
                                                             + "&${layer:queryparam}&var-ip=${__value.raw}&${__url_time_range}"}]},
                width(120)),
            col("경보", "경보", *gauge_cell(C_TEXT), {"id": "custom.minWidth", "value": 80}),
            col("위험도", "위험도", *sev_cell()),
        ]}))
    y += 8

    cols = ["timestamp", "rule.level", "rule.id", "rule.description", "data.srcip", "data.src_ip", "data.client_ip",
            "data.url", "data.path", "data.id", "data.status"]
    names = ["시각", "위험도", "룰 ID", "설명", "출발지", "출발지 (IDS)", "출발지 (API)", "요청 URL", "API 경로",
             "응답 (웹)", "응답 (API)"]
    P.append(panel(
        "table", "경보 원본 (최근 200건)", (0, y, 24, 8), ds=A,
        targets=[raw_target("A", A, Q_LAYER, 200)],
        desc="선택한 계층의 경보 원본입니다. 로그 종류에 따라 있는 열만 보입니다.",
        options={**TABLE_OPTS, "sortBy": [{"displayName": "시각", "desc": True}]},
        transformations=[
            {"id": "filterFieldsByName", "options": {"include": {"names": cols}}},
            {"id": "organize", "options": {"excludeByName": {}, "indexByName": {c: i for i, c in enumerate(cols)},
                                           "renameByName": dict(zip(cols, names))}},
        ],
        field_config={"defaults": TABLE_DEFAULTS, "overrides": [
            {"matcher": {"id": "byName", "options": "시각"},
             "properties": [{"id": "unit", "value": "dateTimeAsLocal"}, width(160)]},
            {"matcher": {"id": "byName", "options": "위험도"}, "properties": sev_cell()},
            {"matcher": {"id": "byName", "options": "룰 ID"}, "properties": [width(75)]},
            {"matcher": {"id": "byName", "options": "응답 (웹)"}, "properties": [width(75)]},
            {"matcher": {"id": "byName", "options": "응답 (API)"}, "properties": [width(75)]},
        ]}))
    y += 8
    return y


# ---------------------------------------------------------------------------
# 대시보드 조립
# ---------------------------------------------------------------------------
def build(meta, num=None):
    A, R = DS.alerts(), DS.archives()
    d = [b_date()]
    f1 = meta.get("bursts", {}).get("F1", [20, 30, 60])
    f2 = meta.get("bursts", {}).get("F2", [10, 60, 60])
    P = []
    y = 0

    P.append(panel("text", "", (0, y, 24, 1), options={"mode": "html", "content": legend_html()}, transparent=True))
    y += 1

    # 개요 --------------------------------------------------------------------
    P.append(row("개요", y)); y += 1
    # 최고 위험도: 화면 맨 위 전체 폭 띠 (사용자 요청)
    P.append(stat("최고 위험도", (0, y, 24, 7), A,
                  [target("A", A, G_ALL, [m_field("max", "rule.level", "1")], d)],
                  "선택한 기간에 발생한 미등록 API 경보 중 가장 높은 위험도입니다. 경보가 없으면 '정상'입니다.",
                  calc="max", graph="none", mappings=sev_mappings(True), no_value="정상",
                  color_mode="background_solid", steps=[(None, C_OK)], text_size=72))
    y += 7
    P.append(stat("미등록 API 호출", (0, y, 6, 6), A, [target("A", A, G_PERREQ, [m_count()], d)],
                  "API 명세(OpenAPI)에 등록되지 않은 메서드·경로로 들어온 요청 수입니다.", text_size=56))
    P.append(stat("미등록 API 데이터 응답", (6, y, 6, 6), A, [target("A", A, G_RESP, [m_count()], d)],
                  "미등록 API가 2xx로 응답해 실제 데이터가 나간 요청 수입니다. 0보다 크면 정보 노출이 발생한 것입니다.",
                  steps=[(None, C_TEXT), (1, SEV[2][3])], text_size=56))
    P.append(stat("노출 리소스 수", (12, y, 5, 6), A,
                  [target("A", A, G_RESP, [m_field("cardinality", "data.path", "1")], one_bucket())],
                  "미등록 API가 2xx로 응답한 서로 다른 경로 수입니다. /users/1, /users/2 처럼 ID를 바꿔 조회했다면 "
                  "노출된 레코드 수의 추정치(상한)가 됩니다.",
                  graph="none", steps=[(None, C_TEXT), (1, SEV[2][3]), (100, SEV[3][3])], text_size=56))
    # 의심 IP: 개수 대신 IP와 위험도를 바로 보여 줌 (누르면 IP 상세)
    P.append(panel(
        "table", "의심 IP — 누르면 IP 상세", (17, y, 7, 6), ds=A,
        targets=[target("A", A, G_ALL, [m_field("max", "rule.level", "1")],
                        [b_terms("2", "data.client_ip", 10, order_by="1")])],
        desc="미등록 API 경보를 낸 IP를 최고 위험도 순으로 보여 줍니다. IP를 누르면 지금 기간은 그대로 두고 "
             "아래 'IP 상세'가 그 IP로 바뀝니다. 경보 수 등 자세한 목록은 '의심 IP' 구역에 있습니다.",
        options={**TABLE_OPTS, "sortBy": [{"displayName": "위험도", "desc": True}]},
        field_config={"defaults": TABLE_DEFAULTS, "overrides": [
            col("data.client_ip", "IP", {"id": "links", "value": ip_link()}),
            col("Max", "위험도", *sev_cell()[:3], width(160)),
        ]}))
    y += 6

    # 보안 계층별 탐지: 계층마다 숫자 타일 1개. 타일을 누르면 layer 변수만 바뀐다.
    # (캔버스 상자 링크는 누를 때마다 화면 전체가 깜빡였다. 숫자 패널의 링크는 Grafana 화면 안에서 이동한다)
    layer_tiles = [("API 요청", DS.archives(), Q_API_REQ)] + [(t, DS.alerts(), q) for _, t, q in
                                                              [LAYERS[3], LAYERS[1], LAYERS[2], LAYERS[0]]]
    P.append(panel(
        "stat", "보안 계층별 탐지 — 상자를 누르면 계층 상세가 바뀝니다", (0, y, 24, 7), ds=MIXED,
        targets=[target(chr(65 + i), ds_, q, [m_count()], d, alias=t) for i, (t, ds_, q) in enumerate(layer_tiles)],
        desc="같은 기간에 각 보안 계층이 낸 경보 수입니다(API 요청은 전체 요청 수). IDS/IPS·WAF·SIEM 기본 룰·API 명세 대조 "
             "상자를 누르면 '계층 상세'가 그 계층의 경보로 바뀝니다. 각 숫자는 그 계층의 전체 경보 수라서 미등록 API 공격과 "
             "무관한 경보도 포함됩니다. 0은 미탐일 수도 있고 해당 장비 로그가 수집되지 않은 것일 수도 있으니 '수집 상태'와 함께 보세요.",
        options={"reduceOptions": {"calcs": ["sum"], "fields": "", "values": False},
                 "colorMode": "background_solid", "graphMode": "none", "justifyMode": "center",
                 "textMode": "value_and_name", "orientation": "vertical", "wideLayout": True,
                 "showPercentChange": False, "percentChangeColorMode": "standard",
                 "text": {"titleSize": 18, "valueSize": 40}},
        field_config={"defaults": {"unit": "none", "decimals": 0, "noValue": "0",
                                   "color": {"mode": "fixed", "fixedColor": C_TILE}},
                      "overrides": [{"matcher": {"id": "byName", "options": t},
                                     "properties": [{"id": "links", "value": layer_links(t, q)}]}
                                    for _, t, q in LAYERS]}))
    y += 7

    # 계층 상세 ---------------------------------------------------------------
    y = layer_detail(P, y)

    # 탐지 현황 ---------------------------------------------------------------
    P.append(row("탐지 현황", y)); y += 1
    P.append(panel(
        "piechart", "위험도별 경보", (0, y, 6, 9), ds=A,
        targets=[target(chr(65 + i), A, sev_query(lo, hi), [m_count()], d, alias=n)
                 for i, (n, lo, hi, _, _) in enumerate(reversed(SEV))],
        desc="미등록 API 경보를 위험도별로 셉니다. 조각 크기는 비율, 범례 숫자는 건수입니다.\n"
             "관심: 없는 경로 탐색(404·405)\n주의: 인증·권한 거부(401·403), 서버 오류(5xx), 같은 IP의 대량 탐색\n"
             "경계: 미등록 API가 데이터를 응답(2xx)\n심각: 같은 IP가 짧은 시간에 데이터 응답을 반복(대량 노출)",
        options={"reduceOptions": {"calcs": ["sum"], "fields": "", "values": False},
                 "pieType": "donut", "sort": "none", "displayLabels": ["percent"], "orientation": "auto",
                 "tooltip": {"mode": "single", "sort": "none"},
                 "legend": {"showLegend": True, "displayMode": "table", "placement": "right",
                            "values": ["value", "percent"], "calcs": []}},
        field_config={"defaults": {"unit": "none", "decimals": 0, "noValue": "0",
                                   "color": {"mode": "fixed", "fixedColor": C_TEXT2}},
                      "overrides": [color_override(n, c) for n, _, _, c, _ in SEV]}))

    P.append(panel(
        "table", "미등록 API 호출 순위", (6, y, 12, 9), ds=A,
        targets=[target("A", A, G_PERREQ,
                        [m_count(), m_field("max", "rule.level", "4"), m_field("cardinality", "data.client_ip", "5")],
                        [b_terms("2", "data.method", 10), b_terms("3", "data.path", 25)])],
        desc="명세에 없는데 호출된 메서드·경로를 호출 수 순으로 보여 줍니다. 위험도가 경계 이상인 경로는 실제로 데이터를 "
             "응답한 미등록 API이므로 차단하거나 명세에 등록해야 합니다. 경로의 ID 값이 다르면 다른 행으로 셉니다.",
        options={**TABLE_OPTS, "sortBy": [{"displayName": "호출 수", "desc": True}]},
        field_config={"defaults": TABLE_DEFAULTS, "overrides": [
            col("data.method", "메서드", width(75)),
            col("data.path", "경로"),
            col("Count", "호출 수", *gauge_cell(C_TEXT), width(200)),
            col("Max", "위험도", *sev_cell()),
            col("Unique Count", "호출 IP 수", width(90)),
        ]}))

    P.append(panel(
        "table", "계정별 조회 리소스", (18, y, 6, 9), ds=A,
        targets=[target("A", A, G_RESP, [m_field("cardinality", "data.path", "3"), m_count()],
                        [b_terms("2", "data.user_id", 10, order_by="3")])],
        desc="미등록 API에서 데이터를 응답받은 요청을 인증 계정(user_id)별로 묶어, 서로 다른 리소스를 몇 개 조회했는지 셉니다. "
             "계정 하나가 다른 사용자들의 리소스를 대량으로 조회했다면 객체 수준 권한 우회(BOLA/IDOR) 징후입니다.",
        options={**TABLE_OPTS, "sortBy": [{"displayName": "조회 리소스", "desc": True}]},
        field_config={"defaults": TABLE_DEFAULTS, "overrides": [
            col("data.user_id", "계정", width(80)),
            col("Unique Count", "조회 리소스", *gauge_cell(SEV[2][3])),
            col("Count", "요청", width(60)),
        ]}))
    y += 9

    # 의심 IP -----------------------------------------------------------------
    P.append(row("의심 IP", y)); y += 1
    P.append(panel(
        "table", "의심 IP 목록 — IP를 누르면 아래 상세가 그 IP로 바뀝니다", (0, y, 24, 8), ds=A,
        targets=[target("A", A, G_ALL,
                        [m_field("max", "rule.level", "3"), m_count(), m_field("cardinality", "data.path", "5")],
                        [b_terms("2", "data.client_ip", 50, order_by="3")]),
                 target("B", A, G_ALL,
                        [m_field("min", TF, "7"), m_field("max", TF, "8")],
                        [b_terms("2", "data.client_ip", 50, order_by="8")])],
        transformations=[
            {"id": "organize", "filter": {"id": "byRefId", "options": "A"},
             "options": {"renameByName": {"Max": "위험도", "Count": "경보", "Unique Count": "호출 경로 수"}}},
            {"id": "organize", "filter": {"id": "byRefId", "options": "B"},
             "options": {"renameByName": {"Min": "처음", "Max": "마지막"}}},
            {"id": "joinByField", "options": {"byField": "data.client_ip", "mode": "outer"}},
        ],
        desc="미등록 API 경보를 낸 IP를 최고 위험도 순으로 최대 50개 보여 줍니다. IP를 누르면 지금 기간은 그대로 두고 "
             "아래 'IP 상세' 구역이 그 IP 하나의 정보로 바뀝니다.",
        options={**TABLE_OPTS, "sortBy": [{"displayName": "위험도", "desc": True}]},
        field_config={"defaults": TABLE_DEFAULTS, "overrides": [
            col("data.client_ip", "IP", {"id": "links", "value": ip_link()}, width(160)),
            col("위험도", "위험도", *sev_cell()),
            col("경보", "경보", *gauge_cell(C_TEXT), width(360)),
            col("호출 경로 수", "호출 경로 수", width(110)),
            col("처음", "처음", {"id": "unit", "value": "time:YYYY-MM-DD HH:mm:ss"}, width(190)),
            col("마지막", "마지막", {"id": "unit", "value": "time:YYYY-MM-DD HH:mm:ss"})
        ]}))
    y += 8

    # IP 상세 -----------------------------------------------------------------
    P.append(row("IP 상세 — $ip", y)); y += 1
    P.append(panel(
        "state-timeline", "위험도 변화", (0, y, 24, 4), ds=A,
        targets=[target("A", A, f"{G_ALL} AND {IPV}", [m_field("max", "rule.level", "1")], d, alias="$ip")],
        desc="선택한 IP가 시간에 따라 어떤 위험도의 경보를 냈는지 보여 줍니다. 탐색(관심) → 접근 거부(주의) → "
             "데이터 응답(경계) → 대량 노출(심각)으로 올라가면 단계적인 공격으로 볼 수 있습니다. 빈칸은 경보가 없는 구간입니다.",
        options={"mergeValues": True, "showValue": "auto", "alignValue": "left", "rowHeight": 0.75,
                 "legend": {"showLegend": False, "displayMode": "list", "placement": "bottom", "calcs": []},
                 "tooltip": {"mode": "single", "sort": "none"}},
        field_config={"defaults": {"mappings": sev_mappings(), "color": {"mode": "fixed", "fixedColor": C_MUTED},
                                   "custom": {"fillOpacity": 100, "lineWidth": 0, "spanNulls": 300000}},
                      "overrides": []}))
    y += 4

    def rate(title, grid, query, sec, limit, color, desc, unit_label):
        return panel(
            "timeseries", title, grid, ds=A,
            targets=[target("A", A, f"{query} AND {IPV}", [m_count()], [b_date(interval=f"{sec}s")], alias=unit_label)],
            desc=desc,
            options={"legend": {"showLegend": False, "displayMode": "list", "placement": "bottom", "calcs": []},
                     "tooltip": {"mode": "single", "sort": "none"}},
            field_config={"defaults": {
                "unit": "none", "decimals": 0, "min": 0, "color": {"mode": "fixed", "fixedColor": color},
                "thresholds": thresholds((None, "transparent"), (limit, SEV[3][3])),
                "custom": {"drawStyle": "bars", "fillOpacity": 100, "lineWidth": 1, "showPoints": "never",
                           "thresholdsStyle": {"mode": "dashed"}, "axisSoftMin": 0, "axisSoftMax": limit + 2,
                           "axisLabel": f"{sec}초당"}}, "overrides": []})

    P.append(rate(f"탐색 빈도 (점선: 대량 탐색 기준 {f1[0]}회/{f1[1]}초)", (0, y, 12, 6), G_PROBE, f1[1], f1[0], SEV[0][3],
                  f"선택한 IP의 미등록 경로 탐색(404·405) 횟수를 {f1[1]}초 단위로 셉니다. 막대가 점선을 넘으면 사람이 아닌 "
                  "도구 속도로 경로를 훑는 것으로 보고 '대량 탐색'(주의)으로 판정합니다.", "탐색"))
    P.append(rate(f"데이터 응답 빈도 (점선: 대량 노출 기준 {f2[0]}회/{f2[1]}초)", (12, y, 12, 6), G_RESP, f2[1], f2[0], SEV[2][3],
                  f"선택한 IP가 미등록 API에서 데이터를 응답받은 횟수를 {f2[1]}초 단위로 셉니다. 점선을 넘으면 ID를 바꿔 가며 "
                  "데이터를 수집하는 것으로 보고 '대량 데이터 응답'(심각)으로 판정합니다.", "데이터 응답"))
    y += 6

    P.append(panel(
        "table", "호출한 미등록 API", (0, y, 10, 9), ds=A,
        targets=[target("A", A, f"{G_PERREQ} AND {IPV}", [m_count(), m_field("max", "rule.level", "5")],
                        [b_terms("2", "data.method", 10), b_terms("3", "data.path", 50), b_terms("4", "data.status", 5)])],
        desc="선택한 IP가 호출한 미등록 메서드·경로와 응답 코드입니다.",
        options={**TABLE_OPTS, "sortBy": [{"displayName": "위험도", "desc": True}]},
        field_config={"defaults": TABLE_DEFAULTS, "overrides": [
            col("data.method", "메서드", width(75)),
            col("data.path", "경로"),
            col("data.status", "응답", width(60)),
            col("Count", "횟수", width(60)),
            col("Max", "위험도", *sev_cell()),
        ]}))

    cols = ["timestamp", "rule.level", "data.method", "data.path", "data.status", "data.user_id",
            "data.user_agent"]
    names = ["시각", "위험도", "메서드", "경로", "응답", "계정", "User-Agent"]
    P.append(panel(
        "table", "경보 원본 (최근 300건)", (10, y, 14, 9), ds=A,
        targets=[raw_target("A", A, f"{G_ALL} AND {IPV}", 300)],
        desc="선택한 IP의 경보 원본입니다. 사고 보고나 차단 근거로 쓸 수 있습니다.",
        options={**TABLE_OPTS, "sortBy": [{"displayName": "시각", "desc": True}]},
        transformations=[
            {"id": "filterFieldsByName", "options": {"include": {"names": cols}}},
            {"id": "organize", "options": {"excludeByName": {}, "indexByName": {c: i for i, c in enumerate(cols)},
                                           "renameByName": dict(zip(cols, names))}},
        ],
        field_config={"defaults": TABLE_DEFAULTS, "overrides": [
            {"matcher": {"id": "byName", "options": "시각"},
             "properties": [{"id": "unit", "value": "dateTimeAsLocal"}, width(160)]},
            {"matcher": {"id": "byName", "options": "위험도"}, "properties": sev_cell()},
            {"matcher": {"id": "byName", "options": "메서드"}, "properties": [width(70)]},
            {"matcher": {"id": "byName", "options": "응답"}, "properties": [width(55)]},
            {"matcher": {"id": "byName", "options": "계정"},
             "properties": [width(60), {"id": "mappings", "value": [
                 {"type": "special", "options": {"match": "null", "result": {"text": "-", "index": 0}}},
                 {"type": "value", "options": {"null": {"text": "-", "index": 1}}}]}]},
        ]}))
    y += 9

    # 수집 상태 ---------------------------------------------------------------
    P.append(row("수집 상태", y)); y += 1
    P.append(stat("API 로그 마지막 수신", (0, y, 5, 4), R,
                  [target("A", R, Q_API_LOG, [m_field("max", TF, "1")], one_bucket())],
                  "애플리케이션 API 로그가 마지막으로 들어온 시각입니다. 오래됐다면 수집이 끊긴 것이므로 경보 0건을 "
                  "'공격 없음'으로 볼 수 없습니다.",
                  calc="max", graph="none", unit="dateTimeFromNow", no_value="수신 없음", text_size=22))
    P.append(stat("전체 API 요청", (5, y, 5, 4), R, [target("A", R, Q_API_REQ, [m_count()], d)],
                  "등록·미등록을 합친 전체 API 요청 수입니다."))
    P.append(panel(
        "stat", "미등록 API 비율", (10, y, 5, 4), ds=MIXED,
        targets=[
            target("A", R, Q_API_REQ, [m_count()], d, hide=True),
            target("B", A, G_PERREQ, [m_count()], d, hide=True),
            {"refId": "C", "datasource": EXPR, "type": "reduce", "expression": "A", "reducer": "sum", "hide": True},
            {"refId": "D", "datasource": EXPR, "type": "reduce", "expression": "B", "reducer": "sum", "hide": True},
            {"refId": "E", "datasource": EXPR, "type": "math", "expression": "$D / $C * 100"},
        ],
        desc="전체 API 요청 중 미등록 API 호출의 비율입니다. 평소에는 0%에 가까워야 하며, 평소보다 높으면 명세 누락이나 "
             "공격을 의심합니다.",
        options={"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                 "colorMode": "value", "graphMode": "none", "justifyMode": "center", "textMode": "value",
                 "orientation": "auto", "wideLayout": True, "showPercentChange": False,
                 "percentChangeColorMode": "standard"},
        field_config={"defaults": {"unit": "percent", "decimals": 1, "noValue": "-", "color": {"mode": "thresholds"},
                                   "thresholds": thresholds((None, C_TEXT), (5, SEV[1][3]), (30, SEV[2][3]))},
                      "overrides": []}))
    P.append(panel("text", "탐지 기준", (15, y, 9, 4), options={"mode": "html", "content": meta_html(meta)},
                   desc="현재 탐지 규칙이 어떤 API 명세로 만들어졌는지입니다. 명세가 바뀌면 규칙과 대시보드를 다시 만듭니다."))
    y += 4

    # 변수·주석 ---------------------------------------------------------------
    ip_q = json.dumps({"find": "terms", "field": "data.client_ip", "query": G_ALL, "size": 200,
                       "orderBy": "doc_count", "order": "desc"}, ensure_ascii=False)
    layer_q = ",".join(f"{t} : {q}" for _, t, q in LAYERS)
    templating = [
        {"type": "datasource", "name": "ds_alerts", "label": "경보 인덱스", "query": DS.type, "regex": "",
         "hide": 0, "includeAll": False, "multi": False, "refresh": 1, "options": [],
         },
        {"type": "datasource", "name": "ds_archives", "label": "전체 로그 인덱스", "query": DS.type, "regex": "",
         "hide": 0, "includeAll": False, "multi": False, "refresh": 1, "options": [],
         },
        {"type": "query", "name": "ip", "label": "상세 IP", "datasource": DS.alerts(), "query": ip_q,
         "definition": ip_q, "refresh": 2, "multi": False, "includeAll": False, "sort": 0, "hide": 0,
         "options": [], "description": "'IP 상세' 구역에 보여 줄 IP. 의심 IP 목록에서 IP를 누르면 바뀝니다."},
        {"type": "custom", "name": "layer", "label": "계층 상세", "query": layer_q,
         "multi": False, "includeAll": False, "hide": 0, "options": [],
         "current": {"selected": True, "text": LAYERS[0][1], "value": LAYERS[0][2]},
         "description": "'계층 상세' 구역에 보여 줄 보안 계층. 개요의 상자를 누르면 바뀝니다."},
    ]

    def ann(name, query, color):
        return {"name": name, "datasource": DS.alerts(), "enable": True, "hide": True, "iconColor": color,
                "query": query, "timeField": TF, "textField": "data.path", "tagsField": "data.client_ip"}

    annotations = {"list": [
        {"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"}, "enable": True, "hide": True,
         "iconColor": "rgba(0, 211, 255, 1)", "name": "Annotations & Alerts", "type": "dashboard"},
        ann("대량 데이터 응답", f"{G_BURST_RESP} AND {IPV}", SEV[3][3]),
        ann("대량 탐색", f"{G_BURST_PROBE} AND {IPV}", SEV[1][3]),
        ann("자동 차단", Q_BLOCK, C_TEXT2),
    ]}

    return {
        "uid": UID if num is None else f"{UID}-{num}",
        "title": "API 보안 관제 — 미등록 API 접근 탐지" + ("" if num is None else f" ({num})"),
        "description": "API 명세에 없는 호출(미등록 API)을 위험도별로 탐지하고 의심 IP를 조사하는 대시보드",
        "tags": ["api-security", "shadow-api", "wazuh"],
        "timezone": "browser", "editable": True, "graphTooltip": 1, "liveNow": False,
        "refresh": "30s", "time": {"from": "now-1h", "to": "now"},
        "timepicker": {"refresh_intervals": ["10s", "30s", "1m", "5m", "15m"]},
        "fiscalYearStartMonth": 0, "schemaVersion": 39, "version": 1, "weekStart": "", "links": [],
        "annotations": annotations, "templating": {"list": templating}, "panels": P,
    }


# ---------------------------------------------------------------------------
# 한 화면 배치 (관제 모니터 전체 화면용)
# ---------------------------------------------------------------------------
# 1920x1080 전체 화면(kiosk)에서 스크롤 없이 보이도록 24칸 x 27줄 안에 배치한다.
#   맨 위 띠  : 범례 / 최고 위험도 · 핵심 수치 3개 · 보안 계층별 탐지
#   가운데 3열: 탐지 현황 | 의심 IP → IP 상세 | 계층 상세
#   맨 아래 띠: 수집 상태
WIDE = {  # 원래 제목(앞부분) -> (x, y, w, h, 새 제목). 새 제목이 None 이면 원래 제목 유지
    "": (0, 0, 24, 1, None),
    # 왼쪽 열: 최고 위험도(크게) -> 탐지 현황
    "최고 위험도": (0, 1, 8, 10, None),
    "위험도별 경보": (0, 11, 8, 6, "탐지 현황 · 위험도별 경보"),
    "미등록 API 호출 순위": (0, 17, 8, 6, "탐지 현황 · 미등록 API 호출 순위"),
    # 위쪽 띠(가운데·오른쪽): 핵심 수치 3개 + 보안 계층 타일
    "미등록 API 호출": (8, 1, 4, 2, None),
    "미등록 API 데이터 응답": (8, 3, 4, 2, None),
    "노출 리소스 수": (8, 5, 4, 2, None),
    "보안 계층별 탐지": (12, 1, 12, 6, "보안 계층별 탐지 — 상자를 누르면 오른쪽 '계층 상세'가 바뀝니다"),
    # 가운데 열: 의심 IP -> IP 상세
    "의심 IP 목록": (8, 7, 8, 5, "의심 IP — IP를 누르면 아래 IP 상세가 바뀝니다"),
    "위험도 변화": (8, 12, 8, 3, "IP 상세 · $ip 위험도 변화"),
    "탐색 빈도": (8, 15, 4, 4, None),
    "데이터 응답 빈도": (12, 15, 4, 4, None),
    "호출한 미등록 API": (8, 19, 8, 4, "IP 상세 · $ip 호출한 미등록 API"),
    # 오른쪽 열: 계층 상세
    "위험도별 경보 추이": (16, 7, 8, 4, "계층 상세 · ${layer:text} 위험도별 추이"),
    "룰별 경보": (16, 11, 8, 4, "계층 상세 · ${layer:text} 룰별 경보"),
    "출발지 IP": (16, 15, 8, 4, "계층 상세 · ${layer:text} 출발지 IP"),
    "경보 원본 (최근 200건)": (16, 19, 8, 4, "계층 상세 · ${layer:text} 경보 원본"),
    # 맨 아래 띠
    "API 로그 마지막 수신": (0, 23, 4, 4, "수집 상태 · API 로그 마지막 수신"),
    "미등록 API 비율": (4, 23, 4, 4, "수집 상태 · 미등록 API 비율"),
    "계정별 조회 리소스": (8, 23, 8, 4, "탐지 현황 · 계정별 조회 리소스"),
    "탐지 기준": (16, 23, 8, 4, None),
}
# 한 화면에서는 겹치는 정보라 뺀다: 구역 줄(row), 개요의 의심 IP 요약표(아래 목록과 같음),
# IP 경보 원본(계층 상세 원본과 같음), 전체 API 요청(보안 계층 타일의 'API 요청'과 같음)
WIDE_DROP = ("의심 IP — 누르면 IP 상세", "경보 원본 (최근 300건)", "전체 API 요청")


def _wide_key(title):
    if title in WIDE:
        return title
    for k in sorted(WIDE, key=len, reverse=True):   # 긴 이름부터: '위험도별 경보 추이'가 '위험도별 경보'에 먹히지 않게
        if k and title.startswith(k):
            return k
    return None


def _override(p, name):
    for o in p["fieldConfig"]["overrides"]:
        if o["matcher"]["options"] == name:
            return o
    return None


def _set_prop(p, name, pid, value):
    o = _override(p, name)
    if o is None:
        return
    o["properties"] = [x for x in o["properties"] if x["id"] != pid] + [{"id": pid, "value": value}]


def apply_wide_layout(dash):
    out = []
    for p in dash["panels"]:
        if p["type"] == "row" or p["title"] in WIDE_DROP:
            continue
        key = _wide_key(p["title"])
        if key is None:
            raise SystemExit(f"한 화면 배치에 위치가 없는 패널: {p['title']}")
        x, y, w, h, title = WIDE[key]
        p["gridPos"] = {"x": x, "y": y, "w": w, "h": h}
        if title:
            p["title"] = title
        out.append(p)

        # 좁아진 칸에 맞춘 세부 조정
        if p["type"] == "stat" and key in ("미등록 API 호출", "미등록 API 데이터 응답", "노출 리소스 수"):
            p["options"]["text"] = {"titleSize": 13, "valueSize": 30}
            p["options"]["graphMode"] = "none"
        elif key == "최고 위험도":
            p["options"]["text"] = {"titleSize": 16, "valueSize": 150}
        elif key == "보안 계층별 탐지":
            p["options"]["text"] = {"titleSize": 17, "valueSize": 38}
        elif p["type"] == "stat" and key in ("API 로그 마지막 수신", "미등록 API 비율"):
            p["options"]["text"] = {"valueSize": 26}
            p["options"]["graphMode"] = "none"
        elif key in ("탐색 빈도", "데이터 응답 빈도"):
            p["title"] = p["title"].replace("(점선: 대량 탐색 기준 ", "· 기준 ").replace("(점선: 대량 노출 기준 ", "· 기준 ").rstrip(")")
            p["fieldConfig"]["defaults"]["custom"]["axisLabel"] = ""
        elif key == "의심 IP 목록":
            _set_prop(p, "처음", "custom.hidden", True)
            _set_prop(p, "경보", "custom.width", 150)
            _set_prop(p, "호출 경로 수", "displayName", "경로 수")
            _set_prop(p, "호출 경로 수", "custom.width", 70)
            _set_prop(p, "data.client_ip", "custom.width", 130)
            _set_prop(p, "마지막", "unit", "time:MM-DD HH:mm:ss")
        elif key == "미등록 API 호출 순위":
            _set_prop(p, "Count", "custom.width", 130)
            _set_prop(p, "Unique Count", "displayName", "IP")
            _set_prop(p, "Unique Count", "custom.width", 45)
        elif key == "룰별 경보":
            _set_prop(p, "Count", "custom.width", 110)
        elif key == "경보 원본 (최근 200건)":
            _set_prop(p, "시각", "unit", "time:MM-DD HH:mm:ss")
            _set_prop(p, "시각", "custom.width", 115)
        elif key == "탐지 기준":
            p["options"]["content"] = p["options"]["content"].replace("font-size:14px;line-height:1.7", "font-size:13px;line-height:1.45")
    dash["panels"] = out
    return dash


def next_output(folder: Path):
    """이전 파일을 덮어쓰지 않도록 shadow_api_dashboard_N.json 의 다음 번호를 고른다 (번호 없는 파일 = 1번)"""
    nums = [1] if (folder / "shadow_api_dashboard.json").exists() else []
    for f in folder.glob("shadow_api_dashboard_*.json"):
        m = re.fullmatch(r"shadow_api_dashboard_(\d+)\.json", f.name)
        if m:
            nums.append(int(m.group(1)))
    if not nums:
        return folder / "shadow_api_dashboard.json", None
    n = max(nums) + 1
    return folder / f"shadow_api_dashboard_{n}.json", n


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ds-type", default="grafana-opensearch-datasource",
                    help="데이터 소스 플러그인 ID (기본 grafana-opensearch-datasource, 내장 ES면 elasticsearch)")
    ap.add_argument("--meta", default=str(META_PATH), help="rules_meta.json 경로")
    ap.add_argument("-o", "--out", help="출력 파일 (생략하면 shadow_api_dashboard_N.json 다음 번호로 새로 만듦)")
    ap.add_argument("--layout", choices=["wide", "tall"], default="wide",
                    help="wide: 관제 모니터 한 화면 배치(기본), tall: 아래로 내려가는 이전 배치")
    args = ap.parse_args()

    DS.type = args.ds_type
    mp = Path(args.meta)
    meta = json.loads(mp.read_text(encoding="utf-8")) if mp.exists() else {}
    if not meta:
        print(f"[주의] {mp} 를 찾지 못해 기본 임계값으로 만듭니다.")
    if args.out:
        out = Path(args.out)
        m = re.fullmatch(r"shadow_api_dashboard_(\d+)\.json", out.name)
        num = int(m.group(1)) if m else None
    else:
        out, num = next_output(HERE)
    dash = build(meta, num)
    if args.layout == "wide":
        apply_wide_layout(dash)
    out.write_text(json.dumps(dash, ensure_ascii=False, indent=2), encoding="utf-8")
    kinds = {}
    for p in dash["panels"]:
        kinds[p["type"]] = kinds.get(p["type"], 0) + 1
    print(f"생성: {out}  (uid {dash['uid']}, 제목 '{dash['title']}')")
    print(f"패널 {sum(v for k, v in kinds.items() if k != 'row')}개 + 구역 {kinds.get('row', 0)}개: "
          + ", ".join(f"{k} {v}" for k, v in sorted(kinds.items()) if k != "row"))


if __name__ == "__main__":
    main()
