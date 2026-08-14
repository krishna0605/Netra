from django.core.management import call_command
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Run production deployment checks, then apply database migrations."

    def handle(self, *args, **options):
        call_command("check", deploy=True, stdout=self.stdout, stderr=self.stderr)
        call_command("migrate", interactive=False, stdout=self.stdout, stderr=self.stderr)
