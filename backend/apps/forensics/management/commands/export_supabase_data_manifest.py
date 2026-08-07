import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import connection


class Command(BaseCommand):
    help = "Export row counts and primary-key digests for Netra/Django migration verification."

    def add_arguments(self, parser):
        parser.add_argument("--output", default="-", help="Output JSON path, or '-' for stdout.")
        parser.add_argument("--require-count", type=int, default=49, help="Fail unless this many application tables exist.")

    def handle(self, *args, **options):
        if connection.vendor != "postgresql":
            raise CommandError("Data migration manifests require PostgreSQL.")
        quote = connection.ops.quote_name
        table_names = sorted(
            table
            for table in connection.introspection.table_names()
            if table.startswith(("forensics_", "auth_", "django_"))
        )
        expected = options["require_count"]
        if expected >= 0 and len(table_names) != expected:
            raise CommandError(f"Expected {expected} Netra/Django tables, found {len(table_names)}.")

        table_manifest = []
        with connection.cursor() as cursor:
            for table in table_names:
                constraints = connection.introspection.get_constraints(cursor, table)
                primary_key = next(
                    (details.get("columns") or [] for details in constraints.values() if details.get("primary_key")),
                    [],
                )
                cursor.execute(f"select count(*) from {quote(table)}")
                row_count = cursor.fetchone()[0]
                digest = None
                if primary_key:
                    key_expression = "concat_ws(chr(31), " + ", ".join(f"{quote(column)}::text" for column in primary_key) + ")"
                    order_expression = ", ".join(quote(column) for column in primary_key)
                    cursor.execute(
                        f"select md5(coalesce(string_agg({key_expression}, chr(30) order by {order_expression}), '')) "
                        f"from {quote(table)}"
                    )
                    digest = cursor.fetchone()[0]
                table_manifest.append(
                    {
                        "name": table,
                        "rowCount": row_count,
                        "primaryKey": primary_key,
                        "primaryKeyDigest": digest,
                    }
                )

            cursor.execute(
                "select "
                "(select count(*) from auth.users), "
                "(select count(*) from auth.identities), "
                "(select count(*) from auth.sessions), "
                "(select count(*) from auth.refresh_tokens)"
            )
            auth_users, auth_identities, auth_sessions, auth_refresh_tokens = cursor.fetchone()

        manifest = {
            "formatVersion": 1,
            "tableCount": len(table_manifest),
            "tables": table_manifest,
            "auth": {
                "users": auth_users,
                "identities": auth_identities,
                "sessions": auth_sessions,
                "refreshTokens": auth_refresh_tokens,
            },
        }
        payload = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        output = options["output"]
        if output == "-":
            self.stdout.write(payload, ending="")
            return
        output_path = Path(output).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(payload, encoding="utf-8")
        self.stdout.write(self.style.SUCCESS(f"Wrote data manifest to {output_path}"))
