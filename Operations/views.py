from django.shortcuts import render
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.conf import settings
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import json

from Authentification.models import Encryption_Cle, UserFile
from Operations.forms import FileUploadForm

@login_required
def dashboard(request):
    return render(request, 'Operations/dashboard.html')
    

def derive_key(secret_key, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    key = kdf.derive(secret_key.encode())
    return key

def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return iv + encrypted_data


import os
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.files.storage import FileSystemStorage
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Authentification.models import Encryption_Cle

@login_required
def encrypt_file(request):
    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']
        user = request.user

        # Enregistrer le fichier téléchargé temporairement
        fs = FileSystemStorage()
        temp_file_path = fs.save(uploaded_file.name, uploaded_file)
        temp_full_file_path = fs.path(temp_file_path)

        # Générer une clé AES aléatoire
        aes_key = os.urandom(32)

        # Récupérer la dernière clé publique RSA de l'utilisateur
        latest_encryption_cle = Encryption_Cle.objects.filter(user=user).order_by('-date_creation').first()
        if not latest_encryption_cle:
            return JsonResponse({'error': 'No RSA key found for user'}, status=400)

        public_key = serialization.load_pem_public_key(latest_encryption_cle.cle_publique_rsa)

        # Chiffrer la clé AES avec la clé publique RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Chiffrer le fichier avec la clé AES
        with open(temp_full_file_path, 'rb') as f:
            file_data = f.read()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_file_data = encryptor.update(file_data) + encryptor.finalize()

        encrypted_file_with_header = encrypted_aes_key + iv + encrypted_file_data

        # Déterminer le chemin du fichier crypté dans le répertoire MEDIA_ROOT
        encrypted_file_name = uploaded_file.name + '.enc'
        encrypted_file_path = os.path.join(settings.MEDIA_ROOT, encrypted_file_name)
        with open(encrypted_file_path, 'wb') as ef:
            ef.write(encrypted_file_with_header)

        # Supprimer le fichier temporaire
        os.remove(temp_full_file_path)

        # Sauvegarder les informations sur le fichier chiffré
        UserFile.objects.create(file=encrypted_file_path, user=user)

        # Créer le chemin relatif pour le fichier crypté
        relative_encrypted_file_path = os.path.join(settings.MEDIA_URL, encrypted_file_name)

        return JsonResponse({'message': 'File encrypted successfully', 'encrypted_file_path': relative_encrypted_file_path})
    else:
        return render(request, 'Operations/encrypt_file.html')
