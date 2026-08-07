import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import connection


def _json_value(value):
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return str(value)


class Command(BaseCommand):
    help = "Export the repository-backed Netra/Django database schema as a deterministic JSON manifest."

    def add_arguments(self, parser):
        parser.add_argument("--output", default="-", help="Output JSON path, or '-' for stdout.")
        parser.add_argument("--require-count", type=int, default=49, help="Fail unless this many application tables exist.")

    def handle(self, *args, **options):
        table_names = sorted(
            table
            for table in connection.introspection.table_names()
            if table.startswith(("forensics_", "auth_", "django_"))
        )
        expected = options["require_count"]
        if expected >= 0 and len(table_names) != expected:
            raise CommandError(f"Expected {expected} Netra/Django tables, found {len(table_names)}.")

        tables = []
        with connection.cursor() as cursor:
            for table in table_names:
                description = connection.introspection.get_table_description(cursor, table)
                constraints = connection.introspection.get_constraints(cursor, table)
                tables.append(
                    {
                        "name": table,
                        "columns": [
                            {
                                "name": column.name,
                                "type": connection.introspection.get_field_type(column.type_code, column),
                                "databaseTypeCode": _json_value(column.type_code),
                                "nullable": bool(column.null_ok),
                                "default": _json_value(column.default),
                                "collation": _json_value(getattr(column, "collation", None)),
                            }
                            for column in description
                        ],
                        "constraints": {
                            name: _json_value(details)
                            for name, details in sorted(constraints.items())
                        },
                    }
                )

        manifest = {
            "formatVersion": 1,
            "databaseVendor": connection.vendor,
            "tableCount": len(tables),
            "tables": tables,
        }
        payload = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        output = options["output"]
        if output == "-":
            self.stdout.write(payload, ending="")
            return
        output_path = Path(output).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(payload, encoding="utf-8")
        self.stdout.write(self.style.SUCCESS(f"Wrote schema manifest to {output_path}"))
