from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

class EmailBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        User = get_user_model()
        try:
            # On ne prend que le premier utilisateur actif avec cet email
            user = User.objects.filter(email=username, is_active=True).first()
        except User.DoesNotExist:
            return None

        if user is not None and user.check_password(password):
            return user
        return None