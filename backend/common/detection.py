import json
from pathlib import Path
from typing import Any


RULES_DIR = Path(__file__).resolve().parents[1] / "detection_rules"


def load_rules() -> list[dict[str, Any]]:
    rules = []
    for path in RULES_DIR.glob("*.json"):
        rules.append(json.loads(path.read_text(encoding="utf-8")))
    return rules


def classify_detection(record: dict[str, Any]) -> list[dict[str, Any]]:
    matches = []
    rules = load_rules()
    text = json.dumps(record).lower()
    for rule in rules:
        keywords = [keyword.lower() for keyword in rule.get("keywords", [])]
        score = sum(1 for keyword in keywords if keyword in text)
        if score >= rule.get("min_keyword_matches", 1):
            matches.append(
                {
                    "ruleId": rule["id"],
                    "ruleName": rule["name"],
                    "category": rule["category"],
                    "confidence": min(99, rule.get("base_confidence", 60) + score * 8),
                    "attackClass": rule["attack_class"],
                }
            )
    return matches
