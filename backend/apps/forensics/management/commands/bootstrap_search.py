import json

from django.core.management.base import BaseCommand

from common.indexing import bootstrap_search_resources


class Command(BaseCommand):
    help = "Create Phase 7 Elasticsearch lifecycle policies, templates, aliases, and today's backing indexes."

    def handle(self, *args, **options):
        result = bootstrap_search_resources()
        self.stdout.write(json.dumps(result, indent=2))
        if result["failed"]:
            self.stderr.write(self.style.WARNING("Search bootstrap completed with warnings."))
        else:
            self.stdout.write(self.style.SUCCESS("Search bootstrap completed."))
