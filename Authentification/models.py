from django.contrib.auth.models import User
from django.db import models
from django.core.validators import FileExtensionValidator


from django.db import models
from django.contrib.auth.models import User

class Encryption_Cle(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    cle_privee_rsa = models.TextField()  # Stocker la clé privée chiffrée en base64
    cle_publique_rsa = models.TextField()  # Stocker la clé publique en base64
    salt = models.TextField(default="default_salt_value")  # Stocker le sel en base64
    date_creation = models.DateTimeField(auto_now_add=True)
    date_expiration = models.DateTimeField()

    def __str__(self):
        return f"Encryption_Cle for {self.user.username}"



class UserFile(models.Model):
    file = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.file} uploaded by {self.user.username}"
    


