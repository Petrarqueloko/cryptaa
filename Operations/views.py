from django.shortcuts import render
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import os
import base64

from Authentification.models import Encryption_Cle, UserFile

# Fonction pour dériver une clé symétrique à partir de SECRE_KEY
def derive_key(secret_key, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(secret_key.encode())
    return key

# Fonction pour déchiffrer des données avec une clé symétrique
def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data

@login_required
def dashboard(request):
    return render(request, 'Operations/dashboard.html')




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

        public_key = serialization.load_pem_public_key(base64.b64decode(latest_encryption_cle.cle_publique_rsa), backend=default_backend())

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






@login_required
def decrypt_file(request):
    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']
        user = request.user

        # Sauvegarder temporairement le fichier uploadé
        fs = FileSystemStorage()
        temp_file_path = fs.save(uploaded_file.name, uploaded_file)
        temp_full_file_path = fs.path(temp_file_path)

        # Lire le fichier chiffré et extraire l'IV et les données chiffrées
        with open(temp_full_file_path, 'rb') as f:
            encrypted_aes_key = f.read(256)  # Supposons que la clé AES chiffrée fait 256 octets
            iv = f.read(16)
            encrypted_file_data = f.read()

        aes_key = None

        # Récupérer et essayer de déchiffrer la clé AES avec chaque clé RSA de la plus récente à la plus ancienne
        for encryption_cle in Encryption_Cle.objects.filter(user=user).order_by('-date_creation'):
            try:
                # Récupérer le salt et la clé privée chiffrée
                salt = base64.b64decode(encryption_cle.salt)
                encrypted_private_key = base64.b64decode(encryption_cle.cle_privee_rsa)

                # Dériver la clé symétrique à partir du salt et du SECRE_KEY
                key = derive_key(settings.SECRE_KEY, salt)

                # Déchiffrer la clé privée en utilisant la clé dérivée
                private_key_bytes = decrypt_data(encrypted_private_key, key)
                private_key = serialization.load_pem_private_key(private_key_bytes, password=None, backend=default_backend())

                # Déchiffrer la clé AES avec la clé privée RSA
                aes_key = private_key.decrypt(
                    encrypted_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                break  # Quitter la boucle si la clé AES est déchiffrée avec succès
            except Exception as e:
                # Si le déchiffrement échoue, essayer la clé suivante
                continue

        if aes_key is None:
            return JsonResponse({'error': 'Failed to decrypt AES key with available RSA keys'}, status=400)

        # Déchiffrer le fichier en utilisant la clé AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_file_data = decryptor.update(encrypted_file_data) + decryptor.finalize()

        # Déterminer le chemin du fichier déchiffré dans le répertoire MEDIA_ROOT
        decrypted_file_name = f"decrypted_{uploaded_file.name}"
        decrypted_file_path = os.path.join(settings.MEDIA_ROOT, decrypted_file_name)
        with open(decrypted_file_path, 'wb') as df:
            df.write(decrypted_file_data)

        # Supprimer le fichier temporaire
        os.remove(temp_full_file_path)

        # Préparer l'URL du fichier décrypté
        relative_decrypted_file_path = os.path.join(settings.MEDIA_URL, decrypted_file_name)

        # Retourner l'URL du fichier décrypté
        return JsonResponse({'message': 'File decrypted successfully', 'decrypted_file_path': relative_decrypted_file_path})
    else:
        return render(request, 'Operations/decrypt_file.html')






import os
import shutil
import zipfile
from django.shortcuts import render
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.conf import settings
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

from Authentification.models import Encryption_Cle, UserFile

@login_required
def encrypt_folder(request):
    if request.method == 'POST' and request.FILES.getlist('folder'):
        uploaded_files = request.FILES.getlist('folder')
        user = request.user

        # Récupérer le nom du dossier d'origine depuis le champ caché
        original_folder_name = request.POST.get('original_folder_name')

        if not original_folder_name:
            return JsonResponse({'error': 'Original folder name not found'}, status=400)

        # Create a temporary directory to store the uploaded files
        fs = FileSystemStorage()
        temp_dir = fs.path(f"temp_{user.id}")

        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)

        for uploaded_file in uploaded_files:
            file_path = os.path.join(temp_dir, uploaded_file.name)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'wb+') as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)

        # Generate a random AES key
        aes_key = os.urandom(32)

        # Retrieve the user's latest RSA public key
        latest_encryption_cle = Encryption_Cle.objects.filter(user=user).order_by('-date_creation').first()
        if not latest_encryption_cle:
            return JsonResponse({'error': 'No RSA key found for user'}, status=400)

        public_key = serialization.load_pem_public_key(base64.b64decode(latest_encryption_cle.cle_publique_rsa), backend=default_backend())

        # Encrypt the AES key with the RSA public key
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Compress the folder with the original folder name
        zip_file_path = os.path.join(settings.MEDIA_ROOT, f"{original_folder_name}.zip")
        with zipfile.ZipFile(zip_file_path, 'w') as zip_file:
            for foldername, subfolders, filenames in os.walk(temp_dir):
                for filename in filenames:
                    file_path = os.path.join(foldername, filename)
                    zip_file.write(file_path, os.path.relpath(file_path, temp_dir))

        # Encrypt the zip file with the AES key
        with open(zip_file_path, 'rb') as f:
            file_data = f.read()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_file_data = encryptor.update(file_data) + encryptor.finalize()

        encrypted_file_with_header = encrypted_aes_key + iv + encrypted_file_data

        # Save the encrypted file with the original folder name
        encrypted_file_path = os.path.join(settings.MEDIA_ROOT, f"{original_folder_name}.zip.enc")
        with open(encrypted_file_path, 'wb') as ef:
            ef.write(encrypted_file_with_header)

        # Clean up temporary files
        shutil.rmtree(temp_dir)
        os.remove(zip_file_path)

        # Save information about the encrypted file
        UserFile.objects.create(file=encrypted_file_path, user=user)

        # Create a relative path for the encrypted file
        relative_encrypted_file_path = os.path.join(settings.MEDIA_URL, f"{original_folder_name}.zip.enc")

        return JsonResponse({'message': 'Folder encrypted successfully', 'encrypted_file_path': relative_encrypted_file_path})
    else:
        return render(request, 'Operations/encrypt_folder.html')






@login_required
def decrypt_folder(request):
    if request.method == 'POST' and request.FILES.get('folder'):
        uploaded_file = request.FILES['folder']
        user = request.user

        # Sauvegarder temporairement le fichier uploadé
        fs = FileSystemStorage()
        temp_file_path = fs.save(uploaded_file.name, uploaded_file)
        temp_full_file_path = fs.path(temp_file_path)

        # Lire le fichier chiffré et extraire l'IV et les données chiffrées
        with open(temp_full_file_path, 'rb') as f:
            encrypted_aes_key = f.read(256)  # Supposons que la clé AES chiffrée fait 256 octets
            iv = f.read(16)
            encrypted_file_data = f.read()

        aes_key = None

        for encryption_cle in Encryption_Cle.objects.filter(user=user).order_by('-date_creation'):
            try:
                salt = base64.b64decode(encryption_cle.salt)
                encrypted_private_key = base64.b64decode(encryption_cle.cle_privee_rsa)
                key = derive_key(settings.SECRE_KEY, salt)
                private_key_bytes = decrypt_data(encrypted_private_key, key)
                private_key = serialization.load_pem_private_key(private_key_bytes, password=None, backend=default_backend())
                aes_key = private_key.decrypt(
                    encrypted_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                break
            except Exception:
                continue

        if aes_key is None:
            return JsonResponse({'error': 'ERREUR !!!'}, status=400)

        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted_file_data = decryptor.update(encrypted_file_data) + decryptor.finalize()

        decrypted_file_name = f"{uploaded_file.name}"
        decrypted_file_path = os.path.join(settings.MEDIA_ROOT, decrypted_file_name)
        
        with open(decrypted_file_path, 'wb') as df:
            df.write(decrypted_file_data)

        os.remove(temp_full_file_path)

        relative_final_file_path = os.path.join(settings.MEDIA_URL, decrypted_file_name)

        return JsonResponse({'message': 'Folder decrypted successfully', 'decrypted_folder_path': relative_final_file_path})
    else:
        return render(request, 'Operations/decrypt_folder.html')
