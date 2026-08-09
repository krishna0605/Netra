"""Shared harness for tests that rewind the forensics migration graph.

A migration test leaves the database at whichever migration it targeted. Every
later test in the same process then runs current models against a stale schema,
which fails with errors such as::

    column "operation_kind" of relation "forensics_processingjob" does not exist

Restoring the graph leaf rather than a hardcoded migration keeps the harness
correct as new migrations land.
"""

from __future__ import annotations

from django.db import connection
from django.db.migrations.executor import MigrationExecutor


def latest_migration(app_label: str = "forensics") -> list[tuple[str, str]]:
    """Return the app's current migration graph leaf as an executor target."""
    leaves = [node for node in MigrationExecutor(connection).loader.graph.leaf_nodes(app_label)]
    if len(leaves) != 1:
        raise RuntimeError(f"{app_label} must have exactly one migration leaf, found {leaves}")
    return leaves


class MigrationHarnessMixin:
    """Restore the newest schema once a migration test finishes.

    Subclasses declare ``migrate_from`` and ``migrate_to`` and drive the rewind
    themselves; this mixin only guarantees the database is returned to the
    graph leaf afterwards.
    """

    def tearDown(self):
        MigrationExecutor(connection).migrate(latest_migration())
        super().tearDown()
