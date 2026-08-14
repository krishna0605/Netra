"""Every permission decision has to say what it was about.

require_permission writes an AccessLog row whether it allows or denies. A row
reading "permission:export — allowed" with no resource names an action nobody
can review: an auditor asking "exported what?" a year later has no answer, and
the log is longest precisely where it is least useful.

This began as a one-off audit of the 39 call sites. It is a test because an
audit is true on the day it is run and a test is true on the day someone adds
the fortieth.
"""

import ast
from pathlib import Path

from django.test import SimpleTestCase


API_ROOT = Path(__file__).resolve().parents[1] / "api"
SERVICES_ROOT = Path(__file__).resolve().parents[1] / "services"

# Parameters that name a specific resource. A view taking one of these has an
# identifier in hand at the moment it authorizes, so it has no excuse for
# logging the decision without it.
RESOURCE_PARAMETERS = {
    "case_id",
    "route_ref",
    "evidence_id",
    "report_id",
    "export_id",
    "upload_session_id",
    "job_id",
    "user_id",
    "integration_id",
    "session_id",
    "organization_id",
}


def _call_sites():
    """Yield (file, line, enclosing function, keyword names) per call."""
    for path in sorted([*API_ROOT.glob("*.py"), *SERVICES_ROOT.glob("*.py")]):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for inner in ast.walk(node):
                if not isinstance(inner, ast.Call):
                    continue
                target = inner.func
                name = getattr(target, "id", None) or getattr(target, "attr", None)
                if name != "require_permission":
                    continue
                yield (
                    path.name,
                    inner.lineno,
                    node,
                    {keyword.arg for keyword in inner.keywords if keyword.arg},
                )


class PermissionLoggingTests(SimpleTestCase):
    def test_there_are_call_sites_to_check(self):
        """A scan that silently matches nothing passes forever."""
        self.assertGreaterEqual(len(list(_call_sites())), 30)

    def test_every_permission_check_records_what_it_was_about(self):
        missing = [
            f"{filename}:{line} in {function.name}()"
            for filename, line, function, keywords in _call_sites()
            if "resource_type" not in keywords
        ]

        self.assertEqual(
            missing,
            [],
            "These log a permission decision without saying what kind of thing it concerned:\n  "
            + "\n  ".join(missing),
        )

    def test_a_view_holding_an_identifier_records_it(self):
        """Collection and creation endpoints legitimately have no identifier —
        the resource does not exist yet. A view that took one in its URL does,
        and omitting it turns a reviewable record into a shrug."""
        missing = []
        for filename, line, function, keywords in _call_sites():
            parameters = {argument.arg for argument in function.args.args}
            identifiers = parameters & RESOURCE_PARAMETERS
            if identifiers and "resource_id" not in keywords and "case" not in keywords:
                missing.append(f"{filename}:{line} in {function.name}() has {sorted(identifiers)}")

        self.assertEqual(
            missing,
            [],
            "These had a resource identifier available and did not record it:\n  " + "\n  ".join(missing),
        )
