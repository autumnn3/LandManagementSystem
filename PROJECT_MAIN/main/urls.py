from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from LMS import views
import os

urlpatterns = [
    # Admin Panel
    path('admin/', admin.site.urls),
    path('admin', admin.site.urls),

    # Home & Basic Pages
    path('', views.home, name='home'),
    path('home/', views.home, name='home-alt'),
    path('home', views.home, name='home-noslash'),
    path('layout/', views.layout, name='layout'),
    path('contact/', views.contact, name='contact'),
    path('contact', views.contact, name='contact-noslash'),

    # Authentication Pages
    path('sellerloginpage/', views.sellerloginpage, name='sellerloginpage'),
    path('sellersignuppage/', views.sellersignuppage, name='sellersignuppage'),
    path('buyerloginpage/', views.buyerloginpage, name='buyerloginpage'),
    path('buyersignuppage/', views.buyersignuppage, name='buyersignuppage'),
    path('brokerloginpage/', views.broker_login, name='brokerloginpage'),
    path('brokersignuppage/', views.ureg, name='brokersignuppage'),
    path('sellerloginpage', views.sellerloginpage, name='sellerloginpage'),
    path('sellersignuppage', views.sellersignuppage, name='sellersignuppage'),
    path('brokerloginpage', views.broker_login, name='brokerloginpage-noslash'),
    path('brokersignuppage', views.ureg, name='brokersignuppage-noslash'),
    path('buyersignuppage', views.buyersignuppage, name='buyersignuppage-noslash'),
    path('buyerloginpage', views.buyerloginpage, name='buyerloginpage-noslash'),

    # Authentication Processing
    path('ulogin/', views.broker_login, name='broker-login'),  
    path('ureg/', views.ureg, name='broker-register'),
    path('uloginB/', views.uloginB, name='buyer-login'),
    path('uregB/', views.uregB, name='buyer-register'),
    path('uloginS/', views.uloginS, name='seller-login'),
    path('uregS/', views.uregS, name='seller-register'),
    path('uregS', views.uregS, name='seller-register-noslash'),
    path('ulogin/', views.ulogin, name='ulogin'), 
    path('brokerlogin/', views.broker_login, name='broker_login'),
    path('uregB', views.uregB, name='buyer-register-noslash'),

    # Seller Land Management
    path('SellerAddLand/', views.SellerAddLand, name='SellerAddLand'),
    path('SaddS/', views.SaddS, name='SaddS'),
    path('Sadd/', views.SaddS, name='Sadd'), 

    # Buyer Land Operations
    path('search/', views.search, name='search'),
    path('Bsearch/', views.Bsearch, name='Bsearch'),
    path('Bdisplay/', views.Bdisplay, name='Bdisplay'),
    path('lands/', views.lands, name='lands'),
    path('coll/', views.coll, name='coll'),
    path('uorder/', views.uorder, name='uorder'),

    # Broker Operations
    path('bro/', views.bro, name='bro'),
    path('border/', views.border, name='border'),
    path('Brokers/', views.Brokers, name='Brokers'),
    path('Brokerpage/', views.Brokerpage, name='Brokerpage'),

    # Password Reset
    path('getotpbr/', views.getotpbr, name='getotpbr'),
    path('brpass/', views.brpass, name='brpass'),
    path('brchangepass/', views.brchangepass, name='brchangepass'),
    path('getotpb/', views.getotpbr, name='getotpb'),
    path('bpass/', views.brpass, name='bpass'),
    path('bchangepass/', views.brchangepass, name='bchangepass'),
    path('getotps/', views.getotps, name='getotps'),
    path('spass/', views.spass, name='spass'),
    path('schangepass/', views.schangepass, name='schangepass'),
]

# Static files configuration
if settings.DEBUG:
    urlpatterns += staticfiles_urlpatterns()
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static('/static/images/', document_root=os.path.join(settings.BASE_DIR, 'static', 'images'))

# Error handlers
handler400 = 'LMS.views.bad_request'
handler403 = 'LMS.views.permission_denied'
handler404 = 'LMS.views.page_not_found'
handler500 = 'LMS.views.server_error'
