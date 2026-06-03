import json

import yaml


def load_heuristic_rule(content: str) -> dict:
    try:
        data = yaml.safe_load(content)
    except Exception:  # noqa: BLE001
        data = json.loads(content)
    if not isinstance(data, dict):
        raise ValueError("Heuristic rule content must be a mapping")
    return data


def build_heuristic_query(rule_data: dict) -> dict:
    any_conditions = rule_data.get("query", {}).get("any", [])
    should = []
    for item in any_conditions:
        field = item.get("field")
        if not field:
            continue
        if "contains" in item:
            should.append({"wildcard": {field: f"*{item['contains']}*"}})
        elif "equals" in item:
            should.append({"term": {field: item["equals"]}})
    filters = []
    for field, values in (rule_data.get("filters") or {}).items():
        if isinstance(values, list):
            filters.append({"terms": {field: values}})
        else:
            filters.append({"term": {field: values}})
    return {
        "query": {
            "bool": {
                "should": should or [{"match_none": {}}],
                "minimum_should_match": 1,
                "filter": filters,
            }
        }
    }
