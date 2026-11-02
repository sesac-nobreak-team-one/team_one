#!/usr/bin/env python3
"""
Shadow API 탐지 Grafana 대시보드 JSON 생성기 (계획서 7장)

  python3 build_dashboard.py            → shadow_api_dashboard.json

Grafana → Dashboards → New → Import 에서 이 JSON을 올리고,
데이터 소스 선택 칸에서 wazuh-alerts-* 를 보는 OpenSearch 데이터 소스를 고르면 된다.

단계는 룰 ID가 아니라 그룹 이름(shadow_api_recon 등)으로 거른다.
그래서 --base-id 를 바꿔 룰을 다시 만들어도 대시보드는 고칠 필요가 없다.
"""
import json
from pathlib import Path

DS = {"type": "grafana-opensearch-datasource", "uid": "${DS_WAZUH_ALERTS}"}
TIME_FIELD = "timestamp"
IP_FILTER = "data.client_ip:$ip"

# 단계: (표시 이름, 그룹, 색)
STAGES = [
    ("L1 정찰", "shadow_api_recon", "blue"),
    ("L2 발견", "shadow_api_discovery", "yellow"),
    ("L3 악용", "shadow_api_exploit", "orange"),
    ("L3-E 서버 오류", "shadow_api_error", "purple"),
    ("F1 자동화 정찰", "shadow_api_recon_burst", "light-blue"),
    ("F2 대량 유출", "shadow_api_mass_exfil", "red"),
]

# 최고 레벨 → 단계 이름 (레벨 10은 L3-E와 F1이 같이 쓴다)
LEVEL_NAMES = {5: "L1 정찰", 6: "명세 밖(기타)", 8: "L2 발견", 10: "L3-E / F1", 12: "L3 악용", 14: "F2 대량 유출"}
LEVEL_COLORS = {5: "blue", 6: "text", 8: "yellow", 10: "purple", 12: "orange", 14: "red"}


def q(ref, lucene, alias="", metrics=None, buckets=None, qtype="Metric"):
    return {
        "refId": ref,
        "datasource": DS,
        "queryType": "lucene",
        "luceneQueryType": qtype,
        "query": lucene,
        "alias": alias,
        "metrics": metrics or [{"id": "1", "type": "count"}],
        "bucketAggs": buckets if buckets is not None else [date_hist("2")],
        "timeField": TIME_FIELD,
    }


def date_hist(i):
    return {"id": i, "type": "date_histogram", "field": TIME_FIELD,
            "settings": {"interval": "auto", "min_doc_count": "0", "trimEdges": "0"}}


def terms(i, field, size, order_by="_count"):
    return {"id": i, "type": "terms", "field": field,
            "settings": {"size": str(size), "order": "desc", "orderBy": order_by, "min_doc_count": "1"}}


def by_name_color(name, color):
    return {"matcher": {"id": "byName", "options": name},
            "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": color}}]}


def stage_queries():
    refs = "ABCDEF"
    return [q(refs[i], f"rule.groups:{g} AND {IP_FILTER}", name) for i, (name, g, _c) in enumerate(STAGES)]


panels = []

# ── 1행: 단계별 건수 타일 ──────────────────────────────────────────────
panels.append({
    "id": 1, "type": "stat", "title": "기간 내 단계별 경보 수",
    "description": "오른쪽 위 시간 범위 안의 경보 건수. L3(악용)·F2(대량 유출)가 0보다 크면 개인정보 노출이 일어난 것.",
    "gridPos": {"x": 0, "y": 0, "w": 24, "h": 4},
    "datasource": DS,
    "targets": stage_queries(),
    "options": {"reduceOptions": {"calcs": ["sum"], "fields": "", "values": False},
                "orientation": "vertical", "textMode": "value_and_name", "colorMode": "background",
                "graphMode": "none", "justifyMode": "center"},
    "fieldConfig": {"defaults": {"unit": "short", "decimals": 0,
                                 "color": {"mode": "fixed", "fixedColor": "text"}},
                    "overrides": [by_name_color(n, c) for n, _g, c in STAGES]},
})

# ── 2행 왼쪽: 단계별 경보 추이 ─────────────────────────────────────────
panels.append({
    "id": 2, "type": "timeseries", "title": "단계별 경보 추이",
    "description": "한 IP가 정찰(L1) → 발견(L2) → 악용(L3) → 대량 유출(F2)로 올라가는 흐름을 시간축으로 본다.",
    "gridPos": {"x": 0, "y": 4, "w": 16, "h": 10},
    "datasource": DS,
    "targets": stage_queries(),
    "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
                "tooltip": {"mode": "multi", "sort": "desc"}},
    "fieldConfig": {"defaults": {"unit": "short", "decimals": 0,
                                 "custom": {"drawStyle": "bars", "fillOpacity": 80, "lineWidth": 1,
                                            "stacking": {"mode": "normal", "group": "A"},
                                            "barAlignment": 0, "showPoints": "never"}},
                    "overrides": [by_name_color(n, c) for n, _g, c in STAGES]},
})

# ── 2행 오른쪽: 위험 IP 순위 ───────────────────────────────────────────
panels.append({
    "id": 3, "type": "table", "title": "위험 IP 순위",
    "description": "IP별 경보 수와 최고 도달 단계. 최고 레벨 순으로 정렬.",
    "gridPos": {"x": 16, "y": 4, "w": 8, "h": 10},
    "datasource": DS,
    "targets": [q("A", f"rule.groups:shadow_api AND {IP_FILTER}",
                  metrics=[{"id": "1", "type": "count"},
                           {"id": "3", "type": "max", "field": "rule.level"}],
                  buckets=[terms("2", "data.client_ip", 10, order_by="3")])],
    "transformations": [{"id": "organize", "options": {
        "renameByName": {"data.client_ip": "IP", "Count": "경보 수", "Max rule.level": "최고 단계",
                         "Max": "최고 단계"}}}],
    "options": {"showHeader": True, "sortBy": [{"displayName": "최고 단계", "desc": True}]},
    "fieldConfig": {"defaults": {"custom": {"align": "auto", "cellOptions": {"type": "auto"}}},
                    "overrides": [{
                        "matcher": {"id": "byName", "options": "최고 단계"},
                        "properties": [
                            {"id": "mappings", "value": [{"type": "value", "options": {
                                str(lv): {"text": name, "color": LEVEL_COLORS[lv], "index": i}
                                for i, (lv, name) in enumerate(LEVEL_NAMES.items())}}]},
                            {"id": "custom.cellOptions", "value": {"type": "color-background"}},
                        ]}]},
})

# ── 3행 왼쪽: 명세 밖 엔드포인트 순위 ──────────────────────────────────
panels.append({
    "id": 4, "type": "table", "title": "명세 밖 엔드포인트 순위 (Shadow API 후보)",
    "description": "가장 많이 호출된 명세 밖 메서드+경로. ID가 다르면 다른 줄로 잡히므로 열거 공격은 같은 경로가 여러 줄로 보인다.",
    "gridPos": {"x": 0, "y": 14, "w": 12, "h": 10},
    "datasource": DS,
    "targets": [q("A", f"rule.groups:shadow_api AND {IP_FILTER}",
                  buckets=[terms("2", "data.method", 10), terms("3", "data.path", 15)])],
    "transformations": [{"id": "organize", "options": {
        "renameByName": {"data.method": "메서드", "data.path": "경로", "Count": "호출 수"}}}],
    "options": {"showHeader": True, "sortBy": [{"displayName": "호출 수", "desc": True}]},
    "fieldConfig": {"defaults": {}, "overrides": []},
})

# ── 3행 오른쪽: 기존 장비 비교 ─────────────────────────────────────────
compare = [
    ("명세 대조 룰 (L2 이상)", "rule.groups:shadow_api AND rule.level:>=8", "red"),
    ("Suricata", "rule.groups:suricata", "green"),
    ("ModSecurity WAF", "rule.groups:modsecurity", "green"),
    ("Wazuh 기본 웹 룰", "rule.groups:web AND NOT rule.groups:shadow_api", "green"),
]
panels.append({
    "id": 5, "type": "bargauge", "title": "기존 보안 장비와 비교 (같은 시간대 경보 수)",
    "description": "Suricata·ModSecurity·Wazuh 기본 룰의 그룹 이름은 실제 경보에서 rule.groups 값을 보고 맞춰야 한다 (패널 편집에서 쿼리 수정).",
    "gridPos": {"x": 12, "y": 14, "w": 12, "h": 10},
    "datasource": DS,
    "targets": [q("ABCD"[i], lucene, name) for i, (name, lucene, _c) in enumerate(compare)],
    "options": {"reduceOptions": {"calcs": ["sum"], "fields": "", "values": False},
                "orientation": "horizontal", "displayMode": "basic", "showUnfilled": True,
                "valueMode": "color", "namePlacement": "left"},
    "fieldConfig": {"defaults": {"unit": "short", "decimals": 0, "min": 0,
                                 "color": {"mode": "fixed", "fixedColor": "green"}},
                    "overrides": [by_name_color(n, c) for n, _l, c in compare]},
})

# ── 4행: 최근 경보 표 ─────────────────────────────────────────────────
cols = ["timestamp", "rule.level", "rule.description", "data.client_ip", "data.method",
        "data.path", "data.status", "data.user_id", "data.user_agent", "rule.id"]
panels.append({
    "id": 6, "type": "table", "title": "최근 경보",
    "description": "원본 경보. data.user_id로 공격에 쓰인 계정을 확인할 수 있다.",
    "gridPos": {"x": 0, "y": 24, "w": 24, "h": 12},
    "datasource": DS,
    "targets": [q("A", f"rule.groups:shadow_api AND {IP_FILTER}", qtype="RawData",
                  metrics=[{"id": "1", "type": "raw_data", "settings": {"size": "500"}}], buckets=[])],
    "transformations": [
        {"id": "filterFieldsByName", "options": {"include": {"names": cols}}},
        {"id": "organize", "options": {
            "indexByName": {c: i for i, c in enumerate(cols)},
            "renameByName": {"timestamp": "시각", "rule.level": "레벨", "rule.description": "설명",
                             "data.client_ip": "IP", "data.method": "메서드", "data.path": "경로",
                             "data.status": "상태", "data.user_id": "user_id",
                             "data.user_agent": "User-Agent", "rule.id": "룰 ID"}}},
        {"id": "sortBy", "options": {"sort": [{"field": "시각", "desc": True}]}},
    ],
    "options": {"showHeader": True},
    "fieldConfig": {"defaults": {"custom": {"align": "auto"}},
                    "overrides": [{
                        "matcher": {"id": "byName", "options": "레벨"},
                        "properties": [
                            {"id": "mappings", "value": [{"type": "value", "options": {
                                str(lv): {"text": f"{lv} {name}", "color": LEVEL_COLORS[lv], "index": i}
                                for i, (lv, name) in enumerate(LEVEL_NAMES.items())}}]},
                            {"id": "custom.cellOptions", "value": {"type": "color-text"}},
                            {"id": "custom.width", "value": 140},
                        ]}, {
                        "matcher": {"id": "byName", "options": "시각"},
                        "properties": [{"id": "custom.width", "value": 190}]}]},
})

dashboard = {
    "__inputs": [{
        "name": "DS_WAZUH_ALERTS", "label": "Wazuh 경보 (wazuh-alerts-*)",
        "description": "wazuh-alerts-* 인덱스, 시간 필드 timestamp 로 만든 OpenSearch 데이터 소스",
        "type": "datasource", "pluginId": "grafana-opensearch-datasource", "pluginName": "OpenSearch",
    }],
    "__requires": [
        {"type": "datasource", "id": "grafana-opensearch-datasource", "name": "OpenSearch", "version": ""},
        {"type": "panel", "id": "stat", "name": "Stat", "version": ""},
        {"type": "panel", "id": "timeseries", "name": "Time series", "version": ""},
        {"type": "panel", "id": "table", "name": "Table", "version": ""},
        {"type": "panel", "id": "bargauge", "name": "Bar gauge", "version": ""},
    ],
    "title": "Shadow API 탐지",
    "uid": "shadow-api-detect",
    "description": "openapi.yaml 명세 대조 룰(Shadow API) 경보 대시보드. 통합 계획서 7장.",
    "tags": ["shadow_api", "wazuh"],
    "timezone": "browser",
    "editable": True,
    "graphTooltip": 1,
    "refresh": "10s",
    "time": {"from": "now-1h", "to": "now"},
    "timepicker": {"refresh_intervals": ["5s", "10s", "30s", "1m", "5m"]},
    "templating": {"list": [{
        "name": "ip", "label": "IP 필터 (* = 전체)", "type": "textbox", "query": "*",
        "current": {"text": "*", "value": "*"}, "options": [{"selected": True, "text": "*", "value": "*"}],
        "hide": 0,
    }]},
    "annotations": {"list": []},
    "panels": panels,
    "schemaVersion": 39,
    "version": 1,
}

out = Path(__file__).with_name("shadow_api_dashboard.json")
out.write_text(json.dumps(dashboard, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"{out} ({len(panels)}개 패널)")
