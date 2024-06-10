from django.urls import path

from .views import dashboard, encrypt_file

urlpatterns = [
    path('dashboard/', dashboard, name='dashboard'),
    path('encrypt/', encrypt_file, name='encrypt_file'),
]
   