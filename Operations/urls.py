from django.urls import path

from .views import dashboard, encrypt_file, decrypt_file, encrypt_folder, decrypt_folder

urlpatterns = [
    path('dashboard/', dashboard, name='dashboard'),
    path('encrypt/', encrypt_file, name='encrypt_file'),
    path('decrypt/', decrypt_file, name='decrypt_file'),
    path('encrypt_folder/', encrypt_folder, name='encrypt_folder'),
    path('decrypt_folder/', decrypt_folder, name='decrypt_folder'),
]
   