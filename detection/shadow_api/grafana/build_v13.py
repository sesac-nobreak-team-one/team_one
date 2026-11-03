#!/usr/bin/env python3
"""
13번: 새 디자인 (대시보드 하나, 한 화면, 필요한 정보만)

    python3 build_v13.py     # -> shadow_api_dashboard_13.json

참고한 설계 원칙 (API 보안 제품·SOC 대시보드에서 흔히 쓰는 방식)
- 핵심 숫자는 맨 위 한 줄. 숫자 옆에는 추이선만 두고 꾸밈(배너·그라데이션)은 뺀다.
- 색은 의미가 있을 때만 쓴다: 위험도와 '데이터가 나갔다'만 색, 나머지는 회색 계열.
- 전체 트래픽 대비 이상 트래픽을 한 그래프에 겹쳐 보여 준다 (all vs flagged).
- 표는 '누가(IP) → 무엇을(API) → 그 IP가 실제로 한 일(IP 상세)' 순서로 왼쪽에서 오른쪽으로.
- 맨 아래에 최신 경보 원본(라이브 피드). IP를 누르면 같은 화면의 IP 상세만 바뀐다.

화면 (24칸 x 27줄, 1920x1080)
    y0  h4  현재 위험도 | 전체 API 호출 | 미등록 API 호출 | 미등록 API 응답 | 의심 IP
    y4  h8  API 호출 추이 (전체 vs 미등록 vs 응답)          | 탐지 유형별 경보
    y12 h8  의심 IP · 위험도 | 미등록 API 호출 순위 | IP 상세 · 호출한 미등록 API
    y20 h7  경보 원본 (최신순)
"""
import argparse
import json
import re
from pathlib import Path

import build_dashboard as B

HERE = Path(__file__).resolve().parent
SEV = B.SEV
G_ALL, G_PERREQ, IPV = B.G_ALL, B.G_PERREQ, B.IPV
G_DATA = f"{G_ALL} AND rule.level:>=12"
C_NEUTRAL = "#c7d0d9"
C_UNDOC = "#8ab8ff"        # 미등록 API (강조색 하나)
C_LEAK = SEV[3][3]         # 데이터가 나감
C_OK = B.C_OK
panel, target, m_count, m_field, b_date, b_terms, col, width = (
    B.panel, B.target, B.m_count, B.m_field, B.b_date, B.b_terms, B.col, B.width)


def rule_names(meta):
    """룰 ID -> 탐지 유형 이름 (경보 설명 대신 짧고 일정한 이름을 보여 주려고)"""
    ids = meta.get("rule_ids", {})
    names = {"other_method": "허용되지 않은 메서드", "L1": "없는 경로 탐색 (404·405)",
             "L2": "인증·권한 거부 (401·403)", "L3": "미등록 API 데이터 응답 (2xx)", "L3E": "서버 오류 (5xx)",
             "F1": "대량 탐색", "F2": "대량 데이터 응답"}
    out = {str(ids[k]): v for k, v in names.items() if k in ids}
    for k, v in ids.items():
        if k.startswith("undoc_"):
            out[str(v)] = f"미등록 {k[6:]} 요청 (기타 응답)"
    return out


def rule_mapping(meta):
    return [{"type": "value", "options": {k: {"text": v, "index": i} for i, (k, v) in enumerate(rule_names(meta).items())}}]


def sev_text():
    """표 안 위험도: 칸 전체를 칠하지 않고 글자색만 (화면이 덜 무거움)"""
    return [{"id": "mappings", "value": B.sev_mappings()},
            {"id": "custom.cellOptions", "value": {"type": "color-text"}}, width(70)]


def bar(color):
    return [{"id": "custom.cellOptions", "value": {"type": "gauge", "mode": "basic", "valueDisplayMode": "text"}},
            {"id": "color", "value": {"mode": "fixed", "fixedColor": color}},
            {"id": "min", "value": 0}, {"id": "fieldMinMax", "value": True}]


def kpi(title, grid, ds, tg, desc, *, color=None, steps=None, graph="area", calc="sum", mappings=None,
        no_value="0", mode="value", size=40):
    c = {"mode": "fixed", "fixedColor": color} if color else {"mode": "thresholds"}
    dflt = {"unit": "none", "decimals": 0, "noValue": no_value, "color": c,
            "thresholds": B.thresholds(*(steps or [(None, color or C_NEUTRAL)]))}
    if mappings:
        dflt["mappings"] = mappings
    return panel("stat", title, grid, ds=ds, targets=tg, desc=desc,
                 options={"reduceOptions": {"calcs": [calc], "fields": "", "values": False},
                          "colorMode": mode, "graphMode": graph, "justifyMode": "center", "textMode": "value",
                          "orientation": "auto", "wideLayout": True, "showPercentChange": False,
                          "percentChangeColorMode": "standard", "text": {"titleSize": 14, "valueSize": size}},
                 field_config={"defaults": dflt, "overrides": []})


def build(meta, num):
    A, R = B.DS.alerts(), B.DS.archives()
    d = [b_date()]
    ip_link = [{"title": "IP 상세 보기", "targetBlank": False, "oneClick": True,
                "url": "/d/${__dashboard.uid}?" + B.KEEP_VARS + "&var-ip=${__value.raw}&${__url_time_range}"}]
    P = []

    # 맨 위: 핵심 숫자 -----------------------------------------------------------
    P.append(kpi("현재 위험도", (0, 0, 4, 4), A, [target("A", A, G_ALL, [m_field("max", "rule.level", "1")], d)],
                 "선택한 기간의 미등록 API 경보 중 가장 높은 위험도. 경보가 없으면 정상.\n"
                 "관심: 없는 경로 탐색 · 주의: 거부·오류·대량 탐색 · 경계: 데이터 응답 · 심각: 대량 데이터 응답",
                 calc="max", graph="none", mappings=B.sev_mappings(True), no_value="정상", steps=[(None, C_OK)],
                 mode="background_solid", size=44))
    P.append(kpi("전체 API 호출", (4, 0, 5, 4), R, [target("A", R, B.Q_API_REQ, [m_count()], d)],
                 "등록·미등록을 합친 전체 API 요청 수.", color=C_NEUTRAL))
    P.append(kpi("미등록 API 호출", (9, 0, 5, 4), A, [target("A", A, G_PERREQ, [m_count()], d)],
                 "API 명세(OpenAPI)에 없는 메서드·경로로 들어온 요청 수.", color=C_UNDOC))
    P.append(kpi("미등록 API 응답", (14, 0, 5, 4), A, [target("A", A, G_DATA, [m_count()], d)],
                 "미등록 API가 실제로 데이터를 돌려준(2xx) 요청 수. 0보다 크면 정보가 나간 것.",
                 steps=[(None, C_OK), (1, C_LEAK)]))
    P.append(kpi("의심 IP", (19, 0, 5, 4), A,
                 [target("A", A, G_ALL, [m_field("cardinality", "data.client_ip", "1")], B.one_bucket())],
                 "미등록 API 경보를 낸 서로 다른 IP 수.", graph="none", steps=[(None, C_OK), (1, SEV[2][3])]))

    # 추이 + 탐지 유형 -------------------------------------------------------------
    P.append(panel(
        "timeseries", "API 호출 추이 — 전체 대비 미등록", (0, 4, 16, 8), ds=B.MIXED,
        targets=[target("A", R, B.Q_API_REQ, [m_count()], d, alias="전체 API 호출"),
                 target("B", A, G_PERREQ, [m_count()], d, alias="미등록 API 호출"),
                 target("C", A, G_DATA, [m_count()], d, alias="미등록 API 응답")],
        desc="회색 선은 전체 API 호출(오른쪽 축), 막대는 미등록 API 호출과 그중 데이터가 나간 응답(왼쪽 축).",
        options={"legend": {"showLegend": True, "displayMode": "list", "placement": "bottom", "calcs": ["sum"]},
                 "tooltip": {"mode": "multi", "sort": "none"}},
        field_config={"defaults": {"unit": "none", "decimals": 0, "min": 0,
                                   "custom": {"drawStyle": "bars", "fillOpacity": 90, "lineWidth": 1,
                                              "showPoints": "never", "axisSoftMin": 0, "barAlignment": 0,
                                              "axisLabel": "미등록"}},
                      "overrides": [
                          {"matcher": {"id": "byName", "options": "전체 API 호출"}, "properties": [
                              {"id": "color", "value": {"mode": "fixed", "fixedColor": "#6e7580"}},
                              {"id": "custom.drawStyle", "value": "line"}, {"id": "custom.fillOpacity", "value": 8},
                              {"id": "custom.lineWidth", "value": 1}, {"id": "custom.axisPlacement", "value": "right"},
                              {"id": "custom.axisLabel", "value": "전체"}]},
                          B.color_override("미등록 API 호출", C_UNDOC),
                          B.color_override("미등록 API 응답", C_LEAK)]}))

    P.append(panel(
        "table", "API 명세 대조 · 탐지 유형별 경보", (16, 4, 8, 8), ds=A,
        targets=[target("A", A, G_ALL, [m_count(), m_field("max", "rule.level", "3")],
                        [b_terms("2", "rule.id", 20)])],
        desc="API 명세 대조 룰이 어떤 유형으로 몇 번 울렸는지.",
        options={**B.TABLE_OPTS, "cellHeight": "sm", "sortBy": [{"displayName": "위험도", "desc": True}]},
        field_config={"defaults": B.TABLE_DEFAULTS, "overrides": [
            col("rule.id", "탐지 유형", {"id": "mappings", "value": rule_mapping(meta)}),
            col("Count", "경보", *bar(C_NEUTRAL), width(130)),
            col("Max", "위험도", *sev_text()),
        ]}))

    # 누가 → 무엇을 → 그 IP가 한 일 ------------------------------------------------
    P.append(panel(
        "table", "의심 IP · 위험도 — 누르면 IP 상세", (0, 12, 8, 8), ds=A,
        targets=[target("A", A, G_ALL, [m_field("max", "rule.level", "3"), m_count()],
                        [b_terms("2", "data.client_ip", 50, order_by="3")]),
                 target("B", A, G_ALL, [m_field("max", B.TF, "3")], [b_terms("2", "data.client_ip", 50)])],
        transformations=[
            {"id": "organize", "filter": {"id": "byRefId", "options": "A"},
             "options": {"renameByName": {"Max": "위험도", "Count": "경보"}}},
            {"id": "organize", "filter": {"id": "byRefId", "options": "B"},
             "options": {"renameByName": {"Max": "마지막"}}},
            {"id": "joinByField", "options": {"byField": "data.client_ip", "mode": "outer"}},
        ],
        desc="미등록 API 경보를 낸 IP (API 명세 대조의 출발지 IP). IP를 누르면 오른쪽 'IP 상세'가 그 IP로 바뀝니다.",
        options={**B.TABLE_OPTS, "cellHeight": "sm", "sortBy": [{"displayName": "위험도", "desc": True}]},
        field_config={"defaults": B.TABLE_DEFAULTS, "overrides": [
            col("data.client_ip", "IP", {"id": "links", "value": ip_link}, width(125)),
            col("위험도", "위험도", *sev_text()),
            col("경보", "경보", *bar(C_UNDOC)),
            col("마지막", "마지막", {"id": "unit", "value": "time:MM-DD HH:mm"}, width(95)),
        ]}))

    P.append(panel(
        "table", "미등록 API 호출 순위", (8, 12, 8, 8), ds=A,
        targets=[target("A", A, G_PERREQ, [m_count(), m_field("max", "rule.level", "4")],
                        [b_terms("2", "data.method", 10), b_terms("3", "data.path", 30)])],
        desc="명세에 없는데 호출된 메서드·경로. 위험도가 경계 이상이면 데이터를 응답한 미등록 API입니다.",
        options={**B.TABLE_OPTS, "cellHeight": "sm", "sortBy": [{"displayName": "호출", "desc": True}]},
        field_config={"defaults": B.TABLE_DEFAULTS, "overrides": [
            col("data.method", "메서드", width(70)),
            col("data.path", "경로"),
            col("Count", "호출", *bar(C_UNDOC), width(110)),
            col("Max", "위험도", *sev_text()),
        ]}))

    P.append(panel(
        "table", "IP 상세 · $ip 호출한 미등록 API", (16, 12, 8, 8), ds=A,
        targets=[target("A", A, f"{G_PERREQ} AND {IPV}", [m_count(), m_field("max", "rule.level", "5")],
                        [b_terms("2", "data.method", 10), b_terms("3", "data.path", 50), b_terms("4", "data.status", 5)])],
        desc="'의심 IP'나 '경보 원본'에서 고른 IP가 호출한 미등록 API와 응답 코드.",
        options={**B.TABLE_OPTS, "cellHeight": "sm", "sortBy": [{"displayName": "위험도", "desc": True}]},
        field_config={"defaults": B.TABLE_DEFAULTS, "overrides": [
            col("data.method", "메서드", width(70)),
            col("data.path", "경로"),
            col("data.status", "응답", width(55)),
            col("Count", "횟수", width(55)),
            col("Max", "위험도", *sev_text()),
        ]}))

    # 경보 원본 ------------------------------------------------------------------
    cols = ["timestamp", "rule.level", "rule.id", "data.client_ip", "data.method", "data.path", "data.status",
            "data.user_id", "data.user_agent"]
    names = ["시각", "위험도", "탐지 유형", "IP", "메서드", "경로", "응답", "계정", "User-Agent"]
    P.append(panel(
        "table", "API 명세 대조 · 경보 원본 (최신 200건)", (0, 20, 24, 7), ds=A,
        targets=[B.raw_target("A", A, G_ALL, 200)],
        desc="가장 최근 경보부터. IP를 누르면 'IP 상세'가 그 IP로 바뀝니다.",
        options={**B.TABLE_OPTS, "cellHeight": "sm", "sortBy": [{"displayName": "시각", "desc": True}]},
        transformations=[
            {"id": "filterFieldsByName", "options": {"include": {"names": cols}}},
            {"id": "organize", "options": {"excludeByName": {}, "indexByName": {c: i for i, c in enumerate(cols)},
                                           "renameByName": dict(zip(cols, names))}},
        ],
        field_config={"defaults": B.TABLE_DEFAULTS, "overrides": [
            col("시각", "시각", {"id": "unit", "value": "time:MM-DD HH:mm:ss"}, width(120)),
            col("위험도", "위험도", *sev_text()),
            col("탐지 유형", "탐지 유형", {"id": "mappings", "value": rule_mapping(meta)}, width(200)),
            col("IP", "IP", {"id": "links", "value": ip_link}, width(120)),
            col("메서드", "메서드", width(70)),
            col("응답", "응답", width(55)),
            col("계정", "계정", width(60), {"id": "noValue", "value": "-"}),
        ]}))

    ip_q = json.dumps({"find": "terms", "field": "data.client_ip", "query": G_ALL, "size": 200,
                       "orderBy": "doc_count", "order": "desc"}, ensure_ascii=False)
    templating = [
        {"type": "datasource", "name": "ds_alerts", "label": "경보 인덱스", "query": B.DS.type, "regex": "",
         "hide": 2, "includeAll": False, "multi": False, "refresh": 1, "options": []},
        {"type": "datasource", "name": "ds_archives", "label": "전체 로그 인덱스", "query": B.DS.type, "regex": "",
         "hide": 2, "includeAll": False, "multi": False, "refresh": 1, "options": []},
        {"type": "query", "name": "ip", "label": "IP 상세", "datasource": B.DS.alerts(), "query": ip_q,
         "definition": ip_q, "refresh": 2, "multi": False, "includeAll": False, "sort": 0, "hide": 0, "options": [],
         "description": "'IP 상세' 표에 보여 줄 IP. 의심 IP나 경보 원본에서 IP를 누르면 바뀝니다."},
    ]
    return {
        "uid": f"shadow-api-detect-{num}", "title": f"API 보안 관제 — 미등록 API 탐지 ({num})",
        "description": "API 명세에 없는 호출(미등록 API)을 탐지해 한 화면에 보여 주는 관제 대시보드",
        "tags": ["api-security", "shadow-api", "wazuh"],
        "timezone": "browser", "editable": True, "graphTooltip": 1, "liveNow": False,
        "refresh": "10s", "time": {"from": "now-3h", "to": "now"},
        "timepicker": {"refresh_intervals": ["5s", "10s", "30s", "1m", "5m"]},
        "fiscalYearStartMonth": 0, "schemaVersion": 39, "version": 1, "weekStart": "", "links": [],
        "annotations": {"list": [{"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                                  "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
                                  "name": "Annotations & Alerts", "type": "dashboard"}]},
        "templating": {"list": templating}, "panels": P,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ds-type", default="grafana-opensearch-datasource")
    ap.add_argument("--meta", default=str(B.META_PATH))
    args = ap.parse_args()
    B.DS.type = args.ds_type
    mp = Path(args.meta)
    meta = json.loads(mp.read_text(encoding="utf-8")) if mp.exists() else {}
    nums = [1]
    for f in HERE.glob("shadow_api_*_*.json"):
        m = re.fullmatch(r"shadow_api_(?:dashboard|investigate)_(\d+)\.json", f.name)
        if m:
            nums.append(int(m.group(1)))
    n = max(nums) + 1
    out = HERE / f"shadow_api_dashboard_{n}.json"
    dash = build(meta, n)
    out.write_text(json.dumps(dash, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"생성: {out.name}  uid {dash['uid']}  패널 {len(dash['panels'])}개")


if __name__ == "__main__":
    main()
