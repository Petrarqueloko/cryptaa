import json
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.shortcuts import render, redirect
from django.utils.encoding import force_bytes, force_str
from sendgrid.helpers.mail import Mail 
from django.core.mail import send_mail
from django.contrib.auth.hashers import check_password
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth import authenticate, login
from django.http import HttpResponse
from django.utils.encoding import force_str  # Utiliser force_str au lieu de force_text
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.views import PasswordChangeView
from django.views import View
from django.contrib import messages
from datetime import timedelta
from django.urls import reverse_lazy
from django.contrib.auth import logout as auth_logout
from django.utils.http import urlsafe_base64_decode
from django.core.signing import SignatureExpired, BadSignature
from django.views.generic.edit import FormView

from Abonnement.models import Abonnement
from .forms import SignUpForm, SignInForm, UpdateForm
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os
from sendgrid import SendGridAPIClient
from .tokens import account_activation_token
from datetime import timedelta
from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from .models import Encryption_Cle
from django.conf import settings  # Importer les settings
from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import render, redirect
from django.views import View
from django.conf import settings
from django.http import JsonResponse, HttpResponse


signer = TimestampSigner()


@login_required
def verify_password(request):
    if request.method == 'POST':
        password = request.POST.get('password')
        user = authenticate(username=request.user.username, password=password)
        if user:
            request.session['password_verified'] = True  # Marquer comme vérifié
            return redirect('update_info')
        else:
            return render(request, 'Authentification/verify_password.html', {'error': 'Invalid password'})
    return render(request, 'Authentification/verify_password.html')



@login_required
def update_info(request):
    if not request.session.get('password_verified'):
        return redirect('verify_password')

    user = request.user
    if request.method == 'POST':
        form = UpdateForm(request.POST)
        if form.is_valid():
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            current_site = get_current_site(request)
            
            # Construire le lien d'activation
            activation_link = reverse('activate', kwargs={'uidb64': uid, 'token': token})
            activation_url = f'http://{current_site.domain}{activation_link}'

            # Construire le corps de l'email directement dans la vue
            email_subject = 'Valider votre modification'
            email_body = f'Bonjour {user.username},\n\nVeuillez cliquer sur le lien suivant pour confirmer votre adresse email et compléter la mise à jour de vos informations :\n\n{activation_url}\n\nMerci.'

            # Envoyer l'email
            send_mail(email_subject, email_body, 'lokopetrarque2003@gmail.com', [form.cleaned_data['email']])
            
            # Sauvegarder les nouvelles données dans la session jusqu'à confirmation
            request.session['new_user_data'] = form.cleaned_data
            return HttpResponse('Please confirm your email address to complete the update')
    else:
        form = UpdateForm(initial={
            'username': user.username,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email
        })

    return render(request, 'Authentification/update_info.html', {'form': form})




import logging
logger = logging.getLogger(__name__)

def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        logger.info(f'User found: {user.username}')
    except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
        logger.error(f'Error decoding UID or user does not exist: {e}')
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        logger.info('Token is valid')
        new_user_data = request.session.get('new_user_data')
        if new_user_data:
            user.username = new_user_data.get('username')
            user.first_name = new_user_data.get('first_name')
            user.last_name = new_user_data.get('last_name')
            user.email = new_user_data.get('email')
            user.save()

            # Nettoyer la session après mise à jour
            del request.session['new_user_data']
            return HttpResponse("Merci d'avoir confirmer votre adresse email. Vos informations ont été modifié avec succès.")
    else:
        logger.warning('Activation link is invalid!')
        return HttpResponse('Activation link is invalid!')


@login_required
def dashboard(request):
    return render(request, 'Authentification/dashboard.html')


def home(request):
    return render(request, 'index.html')




class SignInView(View):
    template_name = 'Authentification/login.html'

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)

    def post(self, request, *args, **kwargs):
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, username=email, password=password)

        if user is not None:
            if user.is_active:
                login(request, user)
                return redirect('profile')  # Redirige vers la page de profil
            else:
                messages.error(request, "Ce compte est désactivé.")
        else:
            messages.error(request, "Email ou mot de passe incorrect.")

        return render(request, self.template_name)




@login_required
def profile(request):
    user = request.user
    has_active_subscription = Abonnement.objects.filter(
        user=user,
        date_expiration__gte=timezone.now()
    ).exists()
    return render(request, 'Authentification/profile.html', {
        'user': user,
        'has_active_subscription': has_active_subscription
    })


@login_required
def update_keys(request):
    user = request.user
    active_subscription = Abonnement.objects.filter(user=user, date_expiration__gte=timezone.now()).exists()
    
    if not active_subscription:
        return render(request, 'Authentification/profile.html', {'error': 'Vous n\'avez pas un abonnement actif.'})
    
    if request.method == 'POST':
        # Générer les clés RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        # Sérialiser les clés en format PEM
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Dériver une clé symétrique à partir de SECRE_KEY
        salt = os.urandom(16)  # Générer un sel pour la dérivation de clé
        key = derive_key(settings.SECRE_KEY, salt)

        # Chiffrer la clé privée
        encrypted_private_key = encrypt_data(private_key_bytes, key)

        # Définir la date de création et d'expiration
        date_creation = timezone.now()
        date_expiration = date_creation + timedelta(days=90)

        # Enregistrer la nouvelle paire de clés dans la table Encryption_Cle sans remplacer l'ancienne
        encryption_cle = Encryption_Cle.objects.create(
            cle_privee_rsa=encrypted_private_key,
            cle_publique_rsa=public_key_bytes,
            date_creation=date_creation,
            date_expiration=date_expiration,
            user=user
        )
        encryption_cle.save()

        return redirect('update_keys_success')

    return render(request, 'Authentification/profile.html', {'active_subscription': active_subscription})

@login_required
def update_keys_success(request):
    return render(request, 'Authentification/update_keys_success.html')


class SignUpView(FormView):
    template_name = 'Authentification/signup.html'
    form_class = SignUpForm
    success_url = reverse_lazy('home')
   
    def form_valid(self, form):
        # Vérifier si les mots de passe correspondent
        if form.cleaned_data['password'] != form.cleaned_data['repassword']:
            return HttpResponse("Les mots de passe ne correspondent pas")

        # Vérifier si l'email est déjà utilisé
        if User.objects.filter(email=form.cleaned_data['email'], is_active=True).exists():
            return HttpResponse("Cet email est déjà utilisé")

        # Vérifier si le nom d'utilisateur est déjà utilisé
        if User.objects.filter(username=form.cleaned_data['username']).exists():
            return HttpResponse("Ce nom d'utilisateur est déjà utilisé")

        # Créer un utilisateur avec un mot de passe hashé
        utilisateur = User.objects.create_user(
            username=form.cleaned_data['username'],
            email=form.cleaned_data['email'],
            first_name=form.cleaned_data['first_name'],
            last_name=form.cleaned_data['last_name'],
            password=form.cleaned_data['password'],
            is_active=False  # L'utilisateur doit activer son compte
        )

        # Générer le lien d'activation
        token = default_token_generator.make_token(utilisateur)
        uid = urlsafe_base64_encode(force_bytes(utilisateur.pk))
        activation_link = reverse('activate_account', kwargs={'uidb64': uid, 'token': token})
        activation_url = self.request.build_absolute_uri(activation_link)

        # Envoyer l'e-mail d'activation
        email_subject = 'Activation de votre compte'
        email_body = f'Cliquez sur le lien suivant pour activer votre compte : {activation_url}'
        send_mail(email_subject, email_body, 'lokopetrarque2003@gmail.com', [form.cleaned_data['email']])

        return HttpResponse("Inscription réussie, veuillez vérifier votre e-mail pour activer votre compte.")
    
    

        
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

def encrypt_data(data, key):
    # Générer un vecteur d'initialisation (IV)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return iv + encrypted_data  # Préfixer le IV pour le stockage

def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data

def activate_account(request, uidb64, token):
    try:
        # Décoder l'UID à partir de l'URL
        uid = force_str(urlsafe_base64_decode(uidb64))
        # Obtenir l'utilisateur correspondant
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    # Vérifier si l'utilisateur existe et si le token est valide
    if user is not None and default_token_generator.check_token(user, token):
        # Activer l'utilisateur
        user.is_active = True
        user.save()

        # Générer les clés RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        # Sérialiser les clés en format PEM
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Dériver une clé symétrique à partir de SECRE_KEY
        salt = os.urandom(16)  # Générer un sel pour la dérivation de clé
        key = derive_key(settings.SECRE_KEY, salt)

        # Chiffrer la clé privée
        encrypted_private_key = encrypt_data(private_key_bytes, key)

        # Définir la date de création et d'expiration
        date_creation = timezone.now()
        date_expiration = date_creation + timedelta(days=90)

        # Enregistrer les clés dans la table Encryption_Cle
        encryption_cle = Encryption_Cle.objects.create(
            cle_privee_rsa=encrypted_private_key,
            cle_publique_rsa=public_key_bytes,
            date_creation=date_creation,
            date_expiration=date_expiration,
            user=user
        )
        encryption_cle.save()
    
        return HttpResponse("Votre compte a été activé avec succès!")
    else:
        return HttpResponse("Le lien d'activation est invalide ou a expiré!")




def logout_view(request):
    auth_logout(request)
    return redirect('sign_in')



@login_required
def change_password_view(request):
    if request.method == 'POST':
        ancien_password = request.POST['ancien_password']
        new_password = request.POST['new_password']
        confirm_new_password = request.POST['confirm_new_password']

        if not check_password(ancien_password, request.user.password):
            messages.error(request, "L'ancien mot de passe est incorrect.")
        elif new_password != confirm_new_password:
            messages.error(request, "Les nouveaux mots de passe ne correspondent pas.")
        elif len(new_password) < 8:
            messages.error(request, "Le nouveau mot de passe doit contenir au moins 8 caractères.")
        else:
            request.user.set_password(new_password)
            request.user.save()
            update_session_auth_hash(request, request.user)
            messages.success(request, "Votre mot de passe a été mis à jour avec succès.")
            return redirect('profile')

    return render(request, 'Authentification/change_password.html')

        


    
    
    
def password_reset_request(request):
    if request.method == "POST":
        email = request.POST.get("email")
        users = User.objects.filter(email=email, is_active=True)
        if users.exists():
            if users.count() == 1:
                user = users.first()
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                reset_link = request.build_absolute_uri(reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token}))

                email_subject = 'Réinitialisation de votre mot de passe'
                email_body = f"Bonjour {user.username},\n\nCliquez sur le lien suivant pour réinitialiser votre mot de passe : {reset_link}\n\nMerci."

                send_mail(email_subject, email_body, settings.DEFAULT_FROM_EMAIL, [email])

                return HttpResponse("Un lien de réinitialisation a été envoyé à votre adresse email.")
            else:
                return HttpResponse("Plusieurs comptes sont associés à cette adresse email. Veuillez contacter le support.")
        else:
            return HttpResponse("Aucun compte actif trouvé avec cette adresse email.")
    return render(request, 'Authentification/password_reset_request.html')





def password_reset_confirm(request, uidb64, token):
    if request.method == "POST":
        new_password = request.POST.get("new_password")
        confirm_password = request.POST.get("confirm_password")
        
        if new_password != confirm_password:
            return HttpResponse("Les mots de passe ne correspondent pas.")
        
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        
        if user is not None and default_token_generator.check_token(user, token):
            user.set_password(new_password)
            user.save()
            return HttpResponse("Votre mot de passe a été réinitialisé avec succès.")
        else:
            return HttpResponse("Le lien de réinitialisation est invalide ou a expiré.")
    return render(request, 'Authentification/password_reset_confirm.html')


def password_reset_complete(request):
    return render(request, 'Authentification/password_reset_complete.html')




