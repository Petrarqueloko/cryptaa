# subscriptions/urls.py
from django.views.generic import TemplateView 
from django.urls import path
from .views import subscribe, payment_callback, subscription_list, subscription_offer
urlpatterns = [
    path('offer/', subscription_offer, name='subscription_offer'),
    path('subscribe/', subscribe, name='subscribe'),
    path('payment_callback/', payment_callback, name='payment_callback'),
    path('subscription_success/', TemplateView.as_view(template_name="subscriptions/success.html"), name='subscription_success'),
    path('subscription_failed/', TemplateView.as_view(template_name="subscriptions/failed.html"), name='subscription_failed'),
    path('payment/', TemplateView.as_view(template_name="subscriptions/payment.html"), name='payment'),
    path('subscriptions/', subscription_list, name='subscription_list'),

]
