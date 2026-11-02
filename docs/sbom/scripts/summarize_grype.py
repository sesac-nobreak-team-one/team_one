"""grype JSON 결과 → 보고서용 요약(Markdown).

사용법:
    python summarize_grype.py <grype-result.json> [--sbom <sbom.cdx.json>] [-o summary.md]

grype 결과 JSON은 수십 MB라 레포에 올리지 않고, 이 요약만 올린다.
표준 라이브러리만 사용한다.
"""
import argparse
import collections
import json
import re
import sys

SEVERITIES = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def version_key(v):
    """'2.4.67-1~deb11u3' 같은 버전을 숫자 단위로 비교 (8.5.12 > 8.5.1)"""
    return [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.findall(r"\d+|[A-Za-z]+", v)]


def source_name(artifact):
    """apache2-bin, apache2-utils … 처럼 한 원본 패키지에서 나온 부품은 원본 이름으로 묶는다"""
    ups = artifact.get("upstreams") or []
    return ups[0]["name"] if ups else artifact["name"]


def main():
    ap = argparse.ArgumentParser(description="grype JSON 결과를 Markdown 요약으로 변환")
    ap.add_argument("grype_json")
    ap.add_argument("--sbom", help="검사한 CycloneDX SBOM (부품 수 표시용)")
    ap.add_argument("-o", "--out", help="출력 파일 (기본: 표준 출력)")
    ap.add_argument("--top", type=int, default=10, help="부품별 상위 N개 (기본 10)")
    args = ap.parse_args()

    g = load(args.grype_json)
    matches = g.get("matches", [])
    desc = g.get("descriptor", {})
    db = desc.get("db", {}).get("status", {})
    target = g.get("source", {}).get("target", {})
    distro = g.get("distro", {})

    sev = collections.Counter(m["vulnerability"].get("severity", "Unknown") for m in matches)
    fixed = [m for m in matches if m["vulnerability"].get("fix", {}).get("state") == "fixed"]
    kev = [m for m in matches if m["vulnerability"].get("knownExploited")]

    # 원본 패키지별 Critical · High 수 (같은 CVE가 여러 바이너리 패키지에 걸리면 한 번만 센다)
    by_src = collections.defaultdict(lambda: {"version": "", "type": "", "pkgs": set(), "cves": {}})
    for m in matches:
        a = m["artifact"]
        s = by_src[source_name(a)]
        s["version"], s["type"] = a["version"], a.get("type", "")
        s["pkgs"].add(a["name"])
        s["cves"][m["vulnerability"]["id"]] = m["vulnerability"].get("severity", "Unknown")
    for s in by_src.values():
        s["sev"] = collections.Counter(s["cves"].values())
    top = sorted(by_src.items(), key=lambda kv: (kv[1]["sev"]["Critical"], kv[1]["sev"]["High"]), reverse=True)[: args.top]

    # 지금 바로 조치 가능한 것: 수정 버전이 있는 Critical · High를 원본 패키지별로, 최신 수정 버전만
    action = collections.defaultdict(lambda: {"version": "", "fix": set(), "cves": set()})
    for m in fixed:
        if m["vulnerability"].get("severity") not in ("Critical", "High"):
            continue
        a = m["artifact"]
        x = action[source_name(a)]
        x["version"] = a["version"]
        x["cves"].add(m["vulnerability"]["id"])
        x["fix"].update(m["vulnerability"]["fix"].get("versions", []))
    action_top = sorted(action.items(), key=lambda kv: len(kv[1]["cves"]), reverse=True)[: args.top]

    out = []
    w = out.append
    w("# grype 점검 요약\n")
    w("| 항목 | 값 |")
    w("|---|---|")
    w(f"| 대상 | `{target.get('userInput', '')}` ({g.get('source', {}).get('type', '')}) |")
    if distro:
        w(f"| 배포판 | {distro.get('name', '')} {distro.get('version', '')} |")
    w(f"| grype | v{desc.get('version', '')} |")
    w(f"| 취약점 DB 기준 시각 | {db.get('built', '알 수 없음')} (schema {db.get('schemaVersion', '')}) |")
    w(f"| 검사 시각 | {desc.get('timestamp', '')} |")
    if args.sbom:
        comps = load(args.sbom).get("components", [])
        kinds = collections.Counter(
            (c.get("purl", "").split(":", 1)[1].split("/", 1)[0] if c.get("purl") else "기타") for c in comps
        )
        w(f"| SBOM 부품 수 | {len(comps)} ({', '.join(f'{k} {v}' for k, v in kinds.most_common())}) |")
    w("")

    w("## 심각도별\n")
    w("| " + " | ".join(SEVERITIES[:5]) + " | 합계 |")
    w("|" + "---|" * 6)
    w("| " + " | ".join(str(sev.get(s, 0)) for s in SEVERITIES[:5]) + f" | {len(matches)} |")
    w("")
    w(f"- 수정 버전이 있는 것: **{len(fixed)}건** / {len(matches)}건")
    w(f"- 실제 악용 확인(KEV): **{len(kev)}건**")
    w("")

    w(f"## Critical · High가 많은 원본 패키지 상위 {len(top)}\n")
    w("| 원본 패키지 | 버전 | 종류 | Critical | High | 포함 부품 |")
    w("|---|---|---|---|---|---|")
    for name, s in top:
        w(f"| {name} | {s['version']} | {s['type']} | {s['sev']['Critical']} | {s['sev']['High']} | {', '.join(sorted(s['pkgs']))} |")
    w("")

    w(f"## 지금 조치 가능한 원본 패키지 (수정 버전 있는 Critical · High) 상위 {len(action_top)}\n")
    w("| 원본 패키지 | 현재 버전 | 최신 수정 버전 | CVE 수 |")
    w("|---|---|---|---|")
    for name, x in action_top:
        latest = max(x["fix"], key=version_key) if x["fix"] else "-"
        w(f"| {name} | {x['version']} | {latest} | {len(x['cves'])} |")
    w("")
    w("> CVE 수는 원본 패키지 단위로 중복을 뺀 값이다. 심각도별 표(위)는 grype가 낸 부품 단위 건수 그대로다.")
    w("")
    w("> 숫자는 취약점 DB 기준 시각에 따라 달라진다. 비교할 때는 DB 기준 시각을 함께 적는다.")

    text = "\n".join(out) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
