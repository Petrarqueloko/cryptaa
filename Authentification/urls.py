from django import views
from django.urls import path
from .views import  change_password_view, dashboard, home, logout_view, profile, update_keys, update_keys_success, verify_password, update_info, activate
from .views import SignUpView, activate_account, SignInView, password_reset_request, password_reset_confirm, password_reset_complete

urlpatterns = [
    path('', home, name='home'),
    path('signup/', SignUpView.as_view(), name='signup'),
    path('activate/<uidb64>/<token>/', activate_account, name='activate_account'),
    path('sign_in/', SignInView.as_view(), name='sign_in'),  # Route pour la vue de connexion
    path('profile/', profile, name='profile'),
    path('update_keys/', update_keys, name='update_keys'),
    path('change_password/', change_password_view, name='change_password'),
    path('verify_password/', verify_password, name='verify_password'),
    path('update_info/', update_info, name='update_info'),
    path('confirm_update/<uidb64>/<token>/', activate, name='activate'),
    path('logout/', logout_view, name='logout'),
    path('password-reset/', password_reset_request, name='password_reset'),
    path('reset/<uidb64>/<token>/', password_reset_confirm, name='password_reset_confirm'),
    path('reset/done/', password_reset_complete, name='password_reset_complete'),
    path('dashboard/', dashboard, name='dashboard'),
    path('update-keys/success/', update_keys_success, name='update_keys_success'),

]
