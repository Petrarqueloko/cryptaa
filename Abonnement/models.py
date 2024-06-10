# models.py
from django.db import models
from django.contrib.auth.models import User

class Abonnement(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    type_abonnement = models.CharField(max_length=50, default='premium')
    date_debut = models.DateField()
    date_expiration = models.DateField()

    def __str__(self):
        return f"{self.user.username} - {self.type_abonnement}"