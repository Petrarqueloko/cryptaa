from django.contrib.auth.models import User
from django.db import models
from django.core.validators import FileExtensionValidator

class Encryption_Cle(models.Model):
    idCle = models.AutoField(primary_key=True)
    cle_privee_rsa = models.BinaryField()
    cle_publique_rsa = models.BinaryField()
    date_creation = models.DateTimeField(auto_now_add=True)
    date_expiration = models.DateTimeField()
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return f"Encryption_Cle for {self.user.username}"


class UserFile(models.Model):
    file = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.file} uploaded by {self.user.username}"