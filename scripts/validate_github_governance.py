from __future__ import annotations

import json
from pathlib import Path


REQUIRED_RULES = {
    "deletion",
    "non_fast_forward",
    "required_linear_history",
    "required_signatures",
    "required_status_checks",
}
REQUIRED_CONTEXTS = {"ci-policy-gate", "security-policy-gate", "container-policy-gate"}


def main() -> int:
    ruleset = json.loads(Path("infra/github/main-ruleset.json").read_text(encoding="utf-8"))
    if ruleset.get("enforcement") != "active" or ruleset.get("bypass_actors") != []:
        raise ValueError("The main ruleset must be active and have no bypass actors")
    if ruleset.get("conditions", {}).get("ref_name", {}).get("include") != ["refs/heads/main"]:
        raise ValueError("The ruleset must target only main")
    rules = {rule["type"]: rule for rule in ruleset.get("rules", [])}
    if not REQUIRED_RULES.issubset(rules):
        raise ValueError("The main ruleset is missing required protections")
    if "pull_request" in rules:
        raise ValueError("The permanent main-only workflow must not require a pull request")
    contexts = {item["context"] for item in rules["required_status_checks"]["parameters"]["required_status_checks"]}
    if contexts != REQUIRED_CONTEXTS:
        raise ValueError("The protected-main status contexts do not match the required policy gates")
    codeowners = Path(".github/CODEOWNERS").read_text(encoding="utf-8")
    for required_path in (
        "/.github/",
        "/backend/common/jwt_verifier.py",
        "/vercel.json",
        "/scripts/build-vercel-site.mjs",
        "/backend/apps/forensics/migrations/",
    ):
        if required_path not in codeowners:
            raise ValueError(f"CODEOWNERS is missing {required_path}")
    print("Validated CODEOWNERS and the signed, no-bypass main-only contract.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
