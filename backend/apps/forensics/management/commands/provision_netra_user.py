from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.forensics.models import AccessLog, OperationalEvent, Organization, UserProfile


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
        parser.add_argument("--organization", default="netra", help="Organization slug")
        parser.add_argument("--ticket", required=True, help="Approved change or incident ticket")
        parser.add_argument("--reason", required=True, help="Reason for break-glass provisioning")
        parser.add_argument("--operator", required=True, help="Human/operator identity recorded in audit logs")
        parser.add_argument("--transfer-admin", action="store_true", help="Atomically transfer the administrator role")

    @transaction.atomic
    def handle(self, *args, **options):
        email = options["email"].strip().lower()
        if not email or "@" not in email or len(email) > 254:
            raise CommandError("A valid email address is required.")
        display_name = options["name"].strip() or email
        ticket = options["ticket"].strip()
        reason = options["reason"].strip()
        operator = options["operator"].strip()
        if not ticket or not operator or not 10 <= len(reason) <= 1000:
            raise CommandError("Ticket, operator, and a reason between 10 and 1000 characters are required.")
        organization = Organization.objects.select_for_update().filter(slug=options["organization"].strip().lower()).first()
        if organization is None:
            raise CommandError("Organization not found.")
        User = get_user_model()
        user, created = User.objects.get_or_create(username=email, defaults={"email": email})
        if not user.email:
            user.email = email
            user.save(update_fields=["email"])
        existing_profile = UserProfile.objects.select_for_update().filter(user=user).first()
        current_admin = UserProfile.objects.select_for_update().filter(organization=organization, role=UserProfile.Role.ADMIN).first()
        requested_role = options["role"]
        previous_admin_id = current_admin.user_id if current_admin else None
        if existing_profile and existing_profile.role == UserProfile.Role.ADMIN and requested_role != UserProfile.Role.ADMIN:
            raise CommandError("The current administrator must be changed with --transfer-admin to another active user.")
        if requested_role == UserProfile.Role.ADMIN and current_admin and current_admin.user_id != user.id:
            if not options["transfer_admin"]:
                raise CommandError("An administrator already exists. Use --transfer-admin for an approved atomic transfer.")
            current_admin.role = UserProfile.Role.INVESTIGATOR
            current_admin.save(update_fields=["role", "updated_at"])
        profile, _ = UserProfile.objects.update_or_create(
            user=user,
            defaults={"organization": organization, "role": requested_role, "display_name": display_name},
        )
        details = {
            "ticket": ticket,
            "reason": reason,
            "operator": operator,
            "targetUserId": user.id,
            "requestedRole": requested_role,
            "previousAdminId": previous_admin_id,
        }
        AccessLog.objects.create(
            organization=organization,
            user_label=operator,
            role=UserProfile.Role.ADMIN,
            action="break_glass.profile_provisioned",
            resource_type="UserProfile",
            resource_id=str(profile.id),
            result="allowed",
        )
        OperationalEvent.objects.create(
            organization=organization,
            event_type="break_glass.profile_provisioned",
            payload_json=details,
        )
        action = "created" if created else "updated"
        self.stdout.write(self.style.SUCCESS(f"Netra profile {action}: {email} ({profile.role})"))
