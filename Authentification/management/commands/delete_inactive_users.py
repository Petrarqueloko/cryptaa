# your_app/management/commands/delete_inactive_users.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.contrib.auth.models import User
from datetime import timedelta

class Command(BaseCommand):
    help = 'Delete users who have not activated their account within the activation period.'

    def handle(self, *args, **kwargs):
        expiration_time = timezone.now() - timedelta(seconds=60 * 60 * 24 * 2)  # 2 days
        inactive_users = User.objects.filter(is_active=False, date_joined__lt=expiration_time)

        for user in inactive_users:
            user.delete()
            self.stdout.write(self.style.SUCCESS(f'Deleted user {user.username}'))
