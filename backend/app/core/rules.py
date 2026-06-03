import logging
from pathlib import Path

import yaml


logger = logging.getLogger(__name__)


def get_rules_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "rules"


def load_yaml_rule_file(filename: str) -> dict:
    path = get_rules_dir() / filename
    if not path.exists():
        logger.warning("Rule file %s not found, using safe defaults", path)
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            logger.warning("Rule file %s did not contain a mapping, using safe defaults", path)
            return {}
        return data
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not load rule file %s: %s", path, exc)
        return {}


def load_suspicious_keywords() -> dict:
    data = load_yaml_rule_file("suspicious_keywords.yaml")
    return {
        "process_names": data.get("process_names", []),
        "command_line_patterns": data.get("command_line_patterns", []),
        "paths": data.get("paths", []),
        "event_ids": data.get("event_ids", {}),
    }


def load_builtin_detection_overrides() -> dict:
    data = load_yaml_rule_file("builtin_detection_overrides.yaml")
    disabled_rules = data.get("disabled_rules", [])
    if not isinstance(disabled_rules, list):
        disabled_rules = []
    return {"disabled_rules": [str(item).strip() for item in disabled_rules if str(item).strip()]}
