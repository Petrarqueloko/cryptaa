from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from datetime import timedelta
from .models import Abonnement


def subscription_offer(request):
    return render(request, 'subscriptions/offer.html')

@login_required
def subscribe(request):
    user = request.user
    recent_subscription = Abonnement.objects.filter(user=user).order_by('-date_expiration').first()

    if recent_subscription and recent_subscription.date_expiration > timezone.now().date():
        date_debut_initial = recent_subscription.date_expiration
    else:
        date_debut_initial = timezone.now().date()

    if request.method == 'POST':
        date_debut = request.POST.get('date_debut')
        date_expiration = timezone.datetime.strptime(date_debut, '%Y-%m-%d').date() + timedelta(days=30)

        # Convertir les objets date en chaînes de caractères
        request.session['date_debut'] = date_debut
        request.session['date_expiration'] = date_expiration.isoformat()

        return redirect('payment')

    context = {
        'username': user.username,
        'email': user.email,
        'date_debut_initial': date_debut_initial,
        'date_expiration_initial': date_debut_initial + timedelta(days=30),
    }

    return render(request, 'subscriptions/subscribe.html', context)




from django.conf import settings
from kkiapay import Kkiapay
from .models import Abonnement

def payment_callback(request):
    transaction_id = request.GET.get('transaction_id')

    kkiapay = Kkiapay(
        settings.KKIAPAY_PUBLIC_KEY,
        settings.KKIAPAY_PRIVATE_KEY,
        settings.KKIAPAY_SECRET,
        sandbox=True
    )

    transaction = kkiapay.verify_transaction(transaction_id)

    if transaction['status'] == 'SUCCESS':
        user = request.user
        date_debut = request.session.get('date_debut')
        date_expiration = request.session.get('date_expiration')

        # Convertir les chaînes de caractères en objets date
        date_debut = timezone.datetime.strptime(date_debut, '%Y-%m-%d').date()
        date_expiration = timezone.datetime.strptime(date_expiration, '%Y-%m-%d').date()

        Abonnement.objects.create(
            user=user,
            date_debut=date_debut,
            date_expiration=date_expiration
        )

        return redirect('subscription_success')
    else:
        return redirect('subscription_failed')




@login_required
def subscription_list(request):
    user = request.user
    abonnements = Abonnement.objects.filter(user=user).order_by('-date_debut')
    
    def get_status(abonnement):
        today = timezone.now().date()
        if abonnement.date_expiration < today:
            return "Expiré"
        elif abonnement.date_debut > today:
            return "À venir"
        else:
            return "Actif"
    
    for abonnement in abonnements:
        abonnement.status = get_status(abonnement)
        
    return render(request, 'subscriptions/subscription_list.html', {'abonnements': abonnements})
