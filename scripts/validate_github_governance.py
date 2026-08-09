from __future__ import annotations

import json
from pathlib import Path


REQUIRED_RULES = {
    "deletion",
    "non_fast_forward",
    "required_linear_history",
    "required_review_thread_resolution",
    "pull_request",
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
    pull_request = rules["pull_request"]["parameters"]
    if pull_request.get("required_approving_review_count") != 0 or not pull_request.get("dismiss_stale_reviews_on_push"):
        raise ValueError("The solo-maintainer review policy is not encoded correctly")
    contexts = {item["context"] for item in rules["required_status_checks"]["parameters"]["required_status_checks"]}
    if contexts != REQUIRED_CONTEXTS:
        raise ValueError("The protected-main status contexts do not match Phase 7 policy gates")
    codeowners = Path(".github/CODEOWNERS").read_text(encoding="utf-8")
    for required_path in ("/.github/", "/backend/common/jwt_verifier.py", "/frontend/vercel.json", "/backend/apps/forensics/migrations/"):
        if required_path not in codeowners:
            raise ValueError(f"CODEOWNERS is missing {required_path}")
    print("Validated CODEOWNERS and the no-bypass protected-main contract.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
