"""OpenAPI 명세 → Elasticsearch api-inventory 적재용 NDJSON 변환.

사용법:
    python openapi_to_inventory.py <spec.yaml|json> <service> <owner> [path_prefix] > inventory.ndjson
    curl ... -X POST "https://<es>:9200/api-inventory/_bulk" -H "Content-Type: application/x-ndjson" --data-binary @inventory.ndjson

경로 파라미터 {userId}, {orderNo} 등은 모두 {id}로 통일한다 (ingest pipeline 정규화 규칙과 맞춤).
operation에 deprecated: true 가 있으면 status=deprecated (→ 관측되면 Zombie).
"""
import json
import re
import sys

METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def load_spec(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if path.lower().endswith(".json"):
        return json.loads(text)
    import yaml  # YAML 명세일 때만 필요: pip install pyyaml
    return yaml.safe_load(text)


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    spec_path, service, owner = sys.argv[1:4]
    prefix = sys.argv[4].rstrip("/") if len(sys.argv) > 4 else ""

    spec = load_spec(spec_path)

    for path, ops in (spec.get("paths") or {}).items():
        endpoint = re.sub(r"\{[^}]+\}", "{id}", prefix + path)
        if len(endpoint) > 1:
            endpoint = endpoint.rstrip("/")
        for method, op in ops.items():
            if method.lower() not in METHODS:
                continue
            deprecated = isinstance(op, dict) and op.get("deprecated") is True
            doc = {
                "endpoint_key": f"{method.upper()} {endpoint}",
                "service": service,
                "owner": owner,
                "status": "deprecated" if deprecated else "active",
            }
            print(json.dumps({"index": {}}))
            print(json.dumps(doc, ensure_ascii=False))


if __name__ == "__main__":
    main()
