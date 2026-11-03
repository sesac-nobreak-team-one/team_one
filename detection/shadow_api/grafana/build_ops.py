#!/usr/bin/env python3
"""
관제 화면 + 조사 화면 두 대시보드 생성기 (12번부터)

    python3 build_ops.py            # -> shadow_api_dashboard_N.json (관제), shadow_api_investigate_N.json (조사)

관제 화면: 보안 담당자가 한눈에 판단·조치할 정보만 둔다 (1920x1080 한 화면, 패널 9개)
    1. 지금 위험한가        현재 상태
    2. 데이터가 나갔나      미등록 API 호출 · 데이터 응답 · 노출 리소스 · 공격 IP
    3. 언제부터             시간대별 경보
    4. 누가                 공격 IP (누르면 조사 화면)
    5. 어디가 뚫렸나        미등록 API 현황 (결과별로 묶음, 펼치면 경로)
    + 보안 계층별 경보 · 로그 수신 상태 (맨 아래 한 줄)

조사 화면: 관제 화면에서 IP를 누르면 열린다. 그 IP의 활동 전체와, 관제 화면에서 뺀 참고 정보(접힌 구역).

쿼리·판정 기준은 build_dashboard.py 와 같다 (그 파일의 상수와 함수를 가져다 씀).
"""
import argparse
import json
import re
from pathlib import Path

import build_dashboard as B

HERE = Path(__file__).resolve().parent
OV_UID = "shadow-api-ops"
INV_UID = "shadow-api-investigate"

SEV, C_OK, C_TEXT, C_TEXT2 = B.SEV, B.C_OK, B.C_TEXT, B.C_TEXT2
G_ALL, G_PERREQ, IPV = B.G_ALL, B.G_PERREQ, B.IPV
G_DATA = f"{G_ALL} AND rule.level:>=12"                       # 미등록 API가 데이터를 돌려준 요청 (대량 포함)
G_API_ROWS = f"{G_ALL} AND NOT rule.groups:shadow_api_recon_burst"   # 경로별 표: 대량 탐색 요약 경보는 제외
C_CALLS = B.LAYER_COLOR["API 명세 대조"]
panel, target, m_count, m_field, b_date, b_terms, col, width = (
    B.panel, B.target, B.m_count, B.m_field, B.b_date, B.b_terms, B.col, B.width)


# ---------------------------------------------------------------------------
# 공통
# ---------------------------------------------------------------------------
def banner(title, sub, right_html=""):
    chips = "".join(
        f'<span style="display:inline-flex;align-items:center;gap:5px">'
        f'<span style="width:11px;height:11px;border-radius:3px;background:{c}"></span>'
        f'<span style="color:#e2e8f0">{n}</span></span>'
        for n, c in [("정상", C_OK)] + [(s[0], s[3]) for s in SEV])
    return (
        '<div style="height:100%;box-sizing:border-box;display:flex;align-items:center;justify-content:space-between;'
        'gap:20px;padding:0 18px;border-radius:10px;overflow:hidden;'
        'background:linear-gradient(90deg,#1e293b 0%,#312e81 55%,#7f1d1d 100%)">'
        f'<div style="white-space:nowrap"><span style="font-size:22px;font-weight:700;color:#fff;letter-spacing:-0.5px">{title}</span>'
        f'<span style="font-size:14px;color:#c7d2fe;margin-left:10px">{sub}</span></div>'
        f'<div style="display:flex;align-items:center;gap:14px;font-size:13px;white-space:nowrap">{right_html}{chips}'
        '<span style="color:#cbd5e1;margin-left:6px">${__from:date:MM/DD HH:mm} ~ ${__to:date:MM/DD HH:mm}</span>'
        '</div></div>')


def text_panel(html, grid):
    return panel("text", "", grid, options={"mode": "html", "content": html}, transparent=True)


def kpi(title, grid, ds, targets, desc, *, steps=None, fixed=None, graph="area", unit="none", text=None,
        calc="sum", mappings=None, no_value="0", color_mode="value"):
    color = {"mode": "fixed", "fixedColor": fixed} if fixed else {"mode": "thresholds"}
    defaults = {"unit": unit, "decimals": 0, "noValue": no_value, "color": color,
                "thresholds": B.thresholds(*(steps or [(None, fixed or C_TEXT)]))}
    if mappings:
        defaults["mappings"] = mappings
    return panel("stat", title, grid, ds=ds, targets=targets, desc=desc,
                 options={"reduceOptions": {"calcs": [calc], "fields": "", "values": False},
                          "colorMode": color_mode, "graphMode": graph, "justifyMode": "center", "textMode": "value",
                          "orientation": "auto", "wideLayout": True, "showPercentChange": False,
                          "percentChangeColorMode": "standard", "text": text or {"titleSize": 14, "valueSize": 48}},
                 field_config={"defaults": defaults, "overrides": []})


def ds_vars(hide):
    return [{"type": "datasource", "name": n, "label": l, "query": B.DS.type, "regex": "", "hide": hide,
             "includeAll": False, "multi": False, "refresh": 1, "options": []}
            for n, l in (("ds_alerts", "경보 인덱스"), ("ds_archives", "전체 로그 인덱스"))]


def dashboard(uid, title, desc, panels, templating, links, tags):
    return {"uid": uid, "title": title, "description": desc, "tags": tags,
            "timezone": "browser", "editable": True, "graphTooltip": 1, "liveNow": False,
            "refresh": "30s", "time": {"from": "now-3h", "to": "now"},
            "timepicker": {"refresh_intervals": ["10s", "30s", "1m", "5m", "15m"]},
            "fiscalYearStartMonth": 0, "schemaVersion": 39, "version": 1, "weekStart": "", "links": links,
            "annotations": {"list": [{"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                                      "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
                                      "name": "Annotations & Alerts", "type": "dashboard"}]},
            "templating": {"list": templating}, "panels": panels}


def dash_link(title, uid, icon):
    return {"title": title, "type": "link", "url": f"/d/{uid}", "icon": icon, "tooltip": "",
            "keepTime": True, "includeVars": False, "targetBlank": False, "asDropdown": False, "tags": []}


# ---------------------------------------------------------------------------
# 관제 화면
# ---------------------------------------------------------------------------
def build_ops(inv_uid):
    A, R = B.DS.alerts(), B.DS.archives()
    d = [b_date()]
    P = []

    P.append(text_panel(banner("API 보안 관제", "미등록 API 접근 탐지"), (0, 0, 24, 2)))

    # 1. 지금 위험한가 ---------------------------------------------------------
    P.append(kpi("현재 상태", (0, 2, 8, 6), A, [target("A", A, G_ALL, [m_field("max", "rule.level", "1")], d)],
                 "선택한 기간의 미등록 API 경보 중 가장 높은 위험도입니다. 경보가 없으면 정상입니다.\n"
                 "관심: 없는 경로 탐색 · 주의: 접근 거부·오류·대량 탐색 · 경계: 미등록 API가 데이터 응답 · 심각: 대량 데이터 응답",
                 calc="max", graph="none", mappings=B.sev_mappings(True), no_value="정상", steps=[(None, C_OK)],
                 color_mode="background_solid", text={"titleSize": 14, "valueSize": 110}))

    # 2. 데이터가 나갔나 -------------------------------------------------------
    P.append(kpi("미등록 API 호출", (8, 2, 4, 6), A, [target("A", A, G_PERREQ, [m_count()], d)],
                 "API 명세에 없는 메서드·경로로 들어온 요청 수입니다.", fixed=C_CALLS))
    P.append(kpi("데이터 응답", (12, 2, 4, 6), A, [target("A", A, G_DATA, [m_count()], d)],
                 "미등록 API가 실제로 데이터를 돌려준(2xx) 요청 수입니다. 0보다 크면 정보가 나간 것입니다.",
                 steps=[(None, C_OK), (1, SEV[2][3])]))
    P.append(kpi("노출 리소스", (16, 2, 4, 6), A,
                 [target("A", A, G_DATA, [m_field("cardinality", "data.path", "1")], B.one_bucket())],
                 "데이터가 나간 서로 다른 경로 수입니다. /users/1, /users/2 처럼 ID를 바꿔 조회했다면 "
                 "노출된 레코드 수의 추정치가 됩니다.",
                 graph="none", steps=[(None, C_OK), (1, SEV[2][3]), (100, SEV[3][3])]))
    P.append(kpi("공격 IP", (20, 2, 4, 6), A,
                 [target("A", A, G_ALL, [m_field("cardinality", "data.client_ip", "1")], B.one_bucket())],
                 "미등록 API 경보를 낸 서로 다른 IP 수입니다. 아래 '공격 IP'에서 IP를 누르면 조사 화면이 열립니다.",
                 graph="none", steps=[(None, C_OK), (1, SEV[1][3])]))

    # 3. 언제부터 -------------------------------------------------------------
    P.append(panel(
        "timeseries", "시간대별 경보", (0, 8, 24, 6), ds=A,
        targets=[target(chr(65 + i), A, B.sev_query(lo, hi), [m_count()], d, alias=n)
                 for i, (n, lo, hi, _, _) in enumerate(reversed(SEV))],
        desc="미등록 API 경보를 위험도별로 쌓아 보여 줍니다.",
        options={"legend": {"showLegend": True, "displayMode": "list", "placement": "right", "calcs": []},
                 "tooltip": {"mode": "multi", "sort": "desc"}},
        field_config={"defaults": {
            "unit": "none", "decimals": 0, "min": 0, "color": {"mode": "fixed", "fixedColor": C_TEXT2},
            "custom": {"drawStyle": "bars", "fillOpacity": 100, "lineWidth": 1, "showPoints": "never",
                       "stacking": {"mode": "normal", "group": "A"}, "axisSoftMin": 0, "barAlignment": 0}},
            "overrides": [B.color_override(n, c) for n, _, _, c, _ in SEV]}))

    # 4. 누가 -----------------------------------------------------------------
    inv_link = [{"title": "이 IP 조사", "targetBlank": False, "oneClick": True,
                 "url": f"/d/{inv_uid}?" + B.KEEP_VARS + "&var-ip=${__value.raw}&${__url_time_range}"}]
    P.append(panel(
        "table", "공격 IP — 누르면 조사 화면", (0, 14, 11, 10), ds=A,
        targets=[target("A", A, G_ALL, [m_field("max", "rule.level", "3"), m_count()],
                        [b_terms("2", "data.client_ip", 50, order_by="3")]),
                 target("B", A, G_ALL, [m_field("max", B.TF, "3")], [b_terms("2", "data.client_ip", 50, order_by="3")]),
                 target("C", A, G_DATA, [m_count()], [b_terms("2", "data.client_ip", 50)]),
                 target("D", A, B.Q_WAF_BLOCK, [m_count()], [b_terms("2", "data.srcip", 200)])],
        transformations=[
            {"id": "organize", "filter": {"id": "byRefId", "options": "A"},
             "options": {"renameByName": {"Max": "위험도", "Count": "미등록 호출"}}},
            {"id": "organize", "filter": {"id": "byRefId", "options": "B"},
             "options": {"renameByName": {"Max": "마지막 활동"}}},
            {"id": "organize", "filter": {"id": "byRefId", "options": "C"},
             "options": {"renameByName": {"Count": "데이터 응답"}}},
            {"id": "organize", "filter": {"id": "byRefId", "options": "D"},
             "options": {"renameByName": {"data.srcip": "data.client_ip", "Count": "WAF 차단"}}},
            {"id": "joinByField", "options": {"byField": "data.client_ip", "mode": "outer"}},
            {"id": "filterByValue", "options": {"type": "exclude", "match": "any", "filters": [
                {"fieldName": "위험도", "config": {"id": "isNull", "options": {}}}]}},
            {"id": "organize", "options": {"indexByName": {
                "data.client_ip": 0, "위험도": 1, "데이터 응답": 2, "미등록 호출": 3, "WAF 차단": 4, "마지막 활동": 5}}},
        ],
        desc="미등록 API 경보를 낸 IP입니다. IP를 누르면 그 IP의 조사 화면이 열립니다(기간 유지).\n"
             "· 데이터 응답: 미등록 API로 데이터를 받아 간 요청 수\n"
             "· WAF 차단: 같은 IP의 요청을 WAF가 막은 수. WAF가 막은 요청은 API까지 가지 않으므로, "
             "데이터 응답은 모두 WAF를 통과한 요청입니다.",
        options={**B.TABLE_OPTS, "sortBy": [{"displayName": "위험도", "desc": True}]},
        field_config={"defaults": B.TABLE_DEFAULTS, "overrides": [
            col("data.client_ip", "IP", {"id": "links", "value": inv_link}, width(135)),
            col("위험도", "위험도", *B.sev_cell()[:3], width(80)),
            col("데이터 응답", "데이터 응답", *B.count_cell(SEV[2][3]), width(95)),
            col("미등록 호출", "미등록 호출", {"id": "custom.align", "value": "right"}, width(95)),
            col("WAF 차단", "WAF 차단", *B.count_cell(B.LAYER_COLOR["WAF"]), width(90)),
            col("마지막 활동", "마지막 활동", {"id": "unit", "value": "time:MM-DD HH:mm:ss"}),
        ]}))

    # 5. 어디가 뚫렸나 ---------------------------------------------------------
    results = [("데이터 응답", "rule.level:>=12", SEV[2][3]), ("거부·오류", "rule.level:[7 TO 11]", SEV[1][3]),
               ("없는 경로", "rule.level:[1 TO 6]", SEV[0][3])]

    def calc(alias, field, op, right):
        r = {"matcher": {"id": "byName", "options": right}} if op == "/" else {"fixed": "1"}
        return {"id": "calculateField", "options": {"mode": "binary", "alias": alias, "replaceFields": False,
                "binary": {"left": {"matcher": {"id": "byName", "options": field}}, "operator": op, "right": r}}}

    P.append(panel(
        "table", "미등록 API 현황 — 결과별 (펼치면 경로)", (11, 14, 13, 10), ds=A,
        targets=[target("A", A, G_API_ROWS,
                        [m_count(), m_field("max", "rule.level", "4"), m_field("cardinality", "data.client_ip", "5"),
                         m_field("max", B.TF, "6")],
                        [{"id": "7", "type": "filters",
                          "settings": {"filters": [{"label": l, "query": q} for l, q, _ in results]}},
                         b_terms("2", "data.method", 10), b_terms("3", "data.path", 500)])],
        transformations=[
            {"id": "organize", "options": {"renameByName": {
                "filter": "결과", "data.method": "메서드", "data.path": "경로", "Count": "호출",
                "Unique Count": "IP 수", "Max timestamp": "마지막"}}},
            calc("경로 수", "호출", "/", "호출"),
            calc("호출 합계", "호출", "*", None),
            calc("위험", "Max rule.level", "*", None),
            calc("최근", "마지막", "*", None),
            {"id": "organize", "options": {"excludeByName": {"Max rule.level": True},
                                           "indexByName": {"메서드": 0, "경로": 1, "호출": 2, "IP 수": 3, "마지막": 4}}},
            {"id": "groupToNestedTable", "options": {"showSubframeHeaders": True, "fields": {
                "결과": {"operation": "groupby", "aggregations": []},
                "경로 수": {"operation": "aggregate", "aggregations": ["sum"]},
                "호출 합계": {"operation": "aggregate", "aggregations": ["sum"]},
                "위험": {"operation": "aggregate", "aggregations": ["max"]},
                "최근": {"operation": "aggregate", "aggregations": ["max"]}}}},
            {"id": "sortBy", "options": {"sort": [{"field": "위험 (max)", "desc": True}]}},
        ],
        desc="명세에 없는 메서드·경로로 들어온 요청을 결과별로 묶었습니다. 줄을 펼치면 경로가 나옵니다.\n"
             "· 데이터 응답: 미등록 API가 데이터를 돌려줌 → 차단하거나 명세에 등록해야 할 API\n"
             "· 거부·오류: 인증·권한 거부(401·403) 또는 서버 오류(5xx)\n"
             "· 없는 경로: 404·405 (탐색)\n"
             "경로의 ID 값이 다르면 다른 경로로 셉니다.",
        options={**B.TABLE_OPTS},
        field_config={"defaults": B.TABLE_DEFAULTS, "overrides": [
            col("결과", "결과", {"id": "mappings", "value": [
                {"type": "value", "options": {l: {"text": l, "color": c, "index": i}
                                              for i, (l, _, c) in enumerate(results)}}]},
                {"id": "custom.cellOptions", "value": {"type": "color-background", "mode": "basic"}},
                {"id": "custom.align", "value": "center"}, width(130)),
            col("경로 수 (sum)", "경로 수", {"id": "custom.align", "value": "right"}),
            col("호출 합계 (sum)", "호출", {"id": "custom.align", "value": "right"}),
            col("최근 (max)", "마지막", {"id": "unit", "value": "time:MM-DD HH:mm:ss"}),
            {"matcher": {"id": "byName", "options": "위험 (max)"}, "properties": [{"id": "custom.hidden", "value": True}]},
            col("메서드", "메서드", width(80)),
            col("호출", "호출", {"id": "custom.align", "value": "right"}, width(70)),
            col("IP 수", "IP 수", {"id": "custom.align", "value": "right"}, width(60)),
            col("마지막", "마지막", {"id": "unit", "value": "time:MM-DD HH:mm:ss"}, width(130)),
        ]}))

    # 맨 아래 한 줄 -----------------------------------------------------------
    tiles = [("API 요청", R, B.Q_API_REQ)] + [(t, A, q) for _, t, q in [B.LAYERS[3], B.LAYERS[1], B.LAYERS[2], B.LAYERS[0]]]
    P.append(panel(
        "stat", "같은 기간 보안 계층별 경보", (0, 24, 16, 3), ds=B.MIXED,
        targets=[target(chr(65 + i), ds_, q, [m_count()], d, alias=t) for i, (t, ds_, q) in enumerate(tiles)],
        desc="같은 기간에 각 보안 계층이 낸 경보 수입니다(API 요청은 전체 요청 수). 각 계층의 전체 경보라서 "
             "미등록 API 공격과 무관한 경보도 포함됩니다. 계층별 상세는 조사 화면 아래 '참고' 구역에 있습니다.",
        options={"reduceOptions": {"calcs": ["sum"], "fields": "", "values": False},
                 "colorMode": "value", "graphMode": "none", "justifyMode": "center", "textMode": "value_and_name",
                 "orientation": "vertical", "wideLayout": True, "showPercentChange": False,
                 "percentChangeColorMode": "standard", "text": {"titleSize": 14, "valueSize": 26}},
        field_config={"defaults": {"unit": "none", "decimals": 0, "noValue": "0",
                                   "color": {"mode": "fixed", "fixedColor": C_TEXT2}},
                      "overrides": [B.color_override(t, B.LAYER_COLOR[t]) for t, _, _ in tiles]}))
    P.append(kpi("API 로그 마지막 수신", (16, 24, 8, 3), R,
                 [target("A", R, B.Q_API_LOG, [m_field("max", B.TF, "1")], B.one_bucket())],
                 "애플리케이션 API 로그가 마지막으로 들어온 시각입니다. 오래됐다면 수집이 끊긴 것이므로 "
                 "경보 0건을 '공격 없음'으로 볼 수 없습니다.",
                 calc="max", graph="none", unit="dateTimeFromNow", no_value="수신 없음",
                 text={"titleSize": 14, "valueSize": 26}))
    return P


# ---------------------------------------------------------------------------
# 조사 화면
# ---------------------------------------------------------------------------
def build_investigate(meta, ops_uid):
    A, R = B.DS.alerts(), B.DS.archives()
    d = [b_date()]
    old = {p["title"]: p for p in B.build(meta)["panels"] if p["type"] != "row"}

    def take(prefix, grid, title=None):
        p = next(v for k, v in old.items() if k.startswith(prefix))
        p = json.loads(json.dumps(p))
        B._pid[0] += 1
        p["id"] = B._pid[0]
        p["gridPos"] = dict(zip("xywh", grid))
        if title:
            p["title"] = title
        return p

    P = []
    back = (f'<a href="/d/{ops_uid}?${{__url_time_range}}" style="color:#fff;background:rgba(255,255,255,.14);'
            'padding:3px 10px;border-radius:999px;text-decoration:none;font-weight:600">← 관제 화면</a>')
    P.append(text_panel(banner("IP 조사 · $ip", "미등록 API 접근 탐지", back), (0, 0, 24, 2)))

    # 이 IP 요약 --------------------------------------------------------------
    sm = {"titleSize": 13, "valueSize": 34}
    P.append(kpi("최고 위험도", (0, 2, 4, 4), A, [target("A", A, f"{G_ALL} AND {IPV}", [m_field("max", "rule.level", "1")], d)],
                 "이 IP가 낸 미등록 API 경보 중 가장 높은 위험도입니다.", calc="max", graph="none",
                 mappings=B.sev_mappings(True), no_value="정상", steps=[(None, C_OK)], color_mode="background_solid",
                 text={"titleSize": 13, "valueSize": 40}))
    P.append(kpi("미등록 API 호출", (4, 2, 4, 4), A, [target("A", A, f"{G_PERREQ} AND {IPV}", [m_count()], d)],
                 "이 IP가 보낸 미등록 API 요청 수입니다.", fixed=C_CALLS, text=sm))
    P.append(kpi("데이터 응답", (8, 2, 4, 4), A, [target("A", A, f"{G_DATA} AND {IPV}", [m_count()], d)],
                 "이 IP가 미등록 API로 데이터를 받아 간 요청 수입니다.", steps=[(None, C_OK), (1, SEV[2][3])], text=sm))
    P.append(kpi("노출 리소스", (12, 2, 4, 4), A,
                 [target("A", A, f"{G_DATA} AND {IPV}", [m_field("cardinality", "data.path", "1")], B.one_bucket())],
                 "이 IP가 데이터를 받아 간 서로 다른 경로 수입니다.", graph="none",
                 steps=[(None, C_OK), (1, SEV[2][3]), (100, SEV[3][3])], text=sm))
    for x, title, kind in ((16, "처음 활동", "min"), (20, "마지막 활동", "max")):
        P.append(kpi(title, (x, 2, 4, 4), A,
                     [target("A", A, f"{G_ALL} AND {IPV}", [m_field(kind, B.TF, "1")], B.one_bucket())],
                     f"이 IP의 미등록 API 경보 중 {title[:2]} 시각입니다.", calc=kind, graph="none",
                     unit="dateTimeAsLocalNoDateIfToday", no_value="-", text={"titleSize": 13, "valueSize": 22}))

    # 이 IP 활동 --------------------------------------------------------------
    P.append(take("위험도 변화", (0, 6, 24, 3)))
    P.append(take("탐색 빈도", (0, 9, 12, 6)))
    P.append(take("데이터 응답 빈도", (12, 9, 12, 6)))
    P.append(take("호출한 미등록 API", (0, 15, 14, 8)))

    # 다른 계층은 이 IP를 어떻게 처리했나
    layer_q = [("WAF 차단", f'{B.Q_WAF_BLOCK} AND data.srcip:"$ip"'),
               ("SIEM 기본 룰", f'({B.Q_SIEM_BASE}) AND data.srcip:"$ip"'),
               ("IDS/IPS", f'({B.Q_IDS}) AND data.src_ip:"$ip"')]
    P.append(panel(
        "stat", "다른 보안 계층의 반응", (14, 15, 10, 4), ds=A,
        targets=[target(chr(65 + i), A, q, [m_count()], d, alias=t) for i, (t, q) in enumerate(layer_q)],
        desc="같은 기간에 이 IP에 대해 다른 보안 계층이 낸 경보 수입니다. WAF가 막은 요청은 API까지 가지 않으므로 "
             "'데이터 응답'은 모두 WAF를 통과한 요청입니다. SIEM 기본 룰은 400~599 응답에만 반응합니다.",
        options={"reduceOptions": {"calcs": ["sum"], "fields": "", "values": False},
                 "colorMode": "value", "graphMode": "area", "justifyMode": "center", "textMode": "value_and_name",
                 "orientation": "vertical", "wideLayout": True, "showPercentChange": False,
                 "percentChangeColorMode": "standard", "text": {"titleSize": 13, "valueSize": 28}},
        field_config={"defaults": {"unit": "none", "decimals": 0, "noValue": "0",
                                   "color": {"mode": "fixed", "fixedColor": C_TEXT2}},
                      "overrides": [B.color_override(t, B.LAYER_COLOR["WAF" if t == "WAF 차단" else t])
                                    for t, _ in layer_q]}))
    acc = take("계정별 조회 리소스", (14, 19, 10, 4), "이 IP가 조회한 계정별 리소스")
    for t in acc["targets"]:
        t["query"] = f"{t['query']} AND {IPV}"
    P.append(acc)
    P.append(take("경보 원본 (최근 300건)", (0, 23, 24, 9), "이 IP의 경보 원본 (최근 300건)"))

    # 참고 (접힌 구역): 관제 화면에서 뺀 전체 정보 ------------------------------
    ref = [take("보안 계층별 탐지", (0, 0, 24, 5), "보안 계층별 경보 — 상자를 누르면 아래 계층 상세가 바뀝니다"),
           take("위험도별 경보 추이", (0, 5, 8, 7), "계층 상세 · ${layer:text} 위험도별 추이"),
           take("룰별 경보", (8, 5, 9, 7), "계층 상세 · ${layer:text} 룰별 경보"),
           take("출발지 IP", (17, 5, 7, 7), "계층 상세 · ${layer:text} 출발지 IP"),
           take("경보 원본 (최근 200건)", (0, 12, 24, 7), "계층 상세 · ${layer:text} 경보 원본"),
           take("위험도별 경보", (0, 19, 6, 7), "전체 · 위험도별 경보"),
           take("미등록 API 호출 순위", (6, 19, 12, 7), "전체 · 미등록 API 호출 순위"),
           take("계정별 조회 리소스", (18, 19, 6, 7), "전체 · 계정별 조회 리소스"),
           take("미등록 API 비율", (0, 26, 6, 4), "수집 · 미등록 API 비율"),
           take("탐지 기준", (6, 26, 9, 4)),
           take("서버 CPU 사용률", (15, 26, 9, 4))]
    ref_y = 32
    for p in ref:
        p["gridPos"]["y"] += ref_y + 1
    B._pid[0] += 1
    P.append({"id": B._pid[0], "type": "row", "title": "참고 — 보안 계층 상세 · 전체 현황 · 수집 상태",
              "collapsed": True, "gridPos": {"x": 0, "y": ref_y, "w": 24, "h": 1}, "panels": ref})
    return P


# ---------------------------------------------------------------------------
def next_num(folder: Path):
    nums = [1] if (folder / "shadow_api_dashboard.json").exists() else []
    for f in folder.glob("shadow_api_*_*.json"):
        m = re.fullmatch(r"shadow_api_(?:dashboard|investigate)_(\d+)\.json", f.name)
        if m:
            nums.append(int(m.group(1)))
    return max(nums or [0]) + 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ds-type", default="grafana-opensearch-datasource")
    ap.add_argument("--meta", default=str(B.META_PATH))
    ap.add_argument("--num", type=int, help="파일 번호 (생략하면 다음 번호)")
    args = ap.parse_args()
    B.DS.type = args.ds_type
    mp = Path(args.meta)
    meta = json.loads(mp.read_text(encoding="utf-8")) if mp.exists() else {}
    n = args.num or next_num(HERE)
    ov_uid, inv_uid = f"{OV_UID}-{n}", f"{INV_UID}-{n}"

    ops = dashboard(ov_uid, f"API 보안 관제 ({n})",
                    "보안 담당자용 관제 화면. 지금 위험한지, 데이터가 나갔는지, 누가, 어느 API로 — 를 한 화면에.",
                    build_ops(inv_uid), ds_vars(2), [dash_link("IP 조사 화면", inv_uid, "search")],
                    ["api-security", "shadow-api", "wazuh", "ops"])
    ip_q = json.dumps({"find": "terms", "field": "data.client_ip", "query": G_ALL, "size": 200,
                       "orderBy": "doc_count", "order": "desc"}, ensure_ascii=False)
    layer_q = ",".join(f"{t} : {q}" for _, t, q in B.LAYERS)
    inv_vars = ds_vars(0) + [
        {"type": "query", "name": "ip", "label": "조사할 IP", "datasource": B.DS.alerts(), "query": ip_q,
         "definition": ip_q, "refresh": 2, "multi": False, "includeAll": False, "sort": 0, "hide": 0, "options": []},
        {"type": "custom", "name": "layer", "label": "계층 상세", "query": layer_q, "multi": False, "includeAll": False,
         "hide": 2, "options": [], "current": {"selected": True, "text": B.LAYERS[0][1], "value": B.LAYERS[0][2]}}]
    inv = dashboard(inv_uid, f"API 보안 조사 — IP ({n})",
                    "관제 화면에서 IP를 누르면 열리는 조사 화면. 그 IP의 활동과 다른 보안 계층의 반응.",
                    build_investigate(meta, ov_uid), inv_vars, [dash_link("관제 화면", ov_uid, "dashboard")],
                    ["api-security", "shadow-api", "wazuh", "investigate"])
    for name, dsh in ((f"shadow_api_dashboard_{n}.json", ops), (f"shadow_api_investigate_{n}.json", inv)):
        out = HERE / name
        if out.exists():
            raise SystemExit(f"이미 있는 파일이라 덮어쓰지 않습니다: {out}")
        out.write_text(json.dumps(dsh, ensure_ascii=False, indent=2), encoding="utf-8")
        cnt = sum(1 for p in dsh["panels"] if p["type"] != "row")
        print(f"생성: {out.name}  uid {dsh['uid']}  패널 {cnt}개")


if __name__ == "__main__":
    main()
