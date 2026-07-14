from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.forensics.models import UserProfile


class Command(BaseCommand):
    help = "Provision or update a Netra authorization profile after identity has been verified out of band."

    def add_arguments(self, parser):
        parser.add_argument("email", help="Email address used by the configured identity provider")
        parser.add_argument(
            "--role",
            required=True,
            choices=[choice.value for choice in UserProfile.Role],
            help="Explicit Netra application role",
        )
        parser.add_argument("--name", default="", help="Display name shown in audit records")

    @transaction.atomic
    def handle(self, *args, **options):
        email = options["email"].strip().lower()
        if not email or "@" not in email or len(email) > 254:
            raise CommandError("A valid email address is required.")
        display_name = options["name"].strip() or email
        User = get_user_model()
        user, created = User.objects.get_or_create(username=email, defaults={"email": email})
        if not user.email:
            user.email = email
            user.save(update_fields=["email"])
        profile, _ = UserProfile.objects.update_or_create(
            user=user,
            defaults={"role": options["role"], "display_name": display_name},
        )
        action = "created" if created else "updated"
        self.stdout.write(self.style.SUCCESS(f"Netra profile {action}: {email} ({profile.role})"))
