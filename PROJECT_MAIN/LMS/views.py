from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password
from django.core.mail import send_mail
from django.db import IntegrityError
from random import randint
import hashlib
from LMS.models import Broker, Amenities, Buyer, Seller, Land
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
import json
from django.template.loader import render_to_string
from django.conf import settings

# Helper functions
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

# Layout & Home
def home(request):
    return render(request, "home.html")

def layout(request):
    return render(request, "layout.html")

def contact(request):
    if request.method == "GET":
        name = request.GET.get('name')
        email = request.GET.get('email')
        subject = request.GET.get('subject')
        comment = request.GET.get('comment')

        if not all([name, email, subject, comment]):
            return JsonResponse({'success': False, 'error': 'All fields are required'}, status=400)

        try:
            send_mail(
                "Contact Form Submission",
                f"Name: {name}\nEmail: {email}\nSubject: {subject}\nComment: {comment}",
                "your-email@example.com",
                ["admin@example.com"],
                fail_silently=False,
            )
            return JsonResponse({'success': True, 'message': 'Message sent successfully!'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)

# Authentication Views
def login(request):
    return render(request, 'login.html')

def loginB(request):
    return render(request, 'loginB.html')

def loginS(request):
    return render(request, 'loginS.html')

# Buyer Authentication
def uloginB(request):
    """Handle buyer login via both AJAX (GET) and form submission (POST)"""
    if request.method == "GET":
        
        Bname = request.GET.get('Bname')
        pwd = request.GET.get('psw')

        if not Bname or not pwd:
            return JsonResponse(
                {'success': False, 'error': 'Username and password are required'}, 
                status=400
            )

        try:
            buyer = Buyer.objects.get(Bname__iexact=Bname)
            if check_password(pwd, buyer.password):
                
                response = JsonResponse({
                    'success': True,
                    'message': 'Login successful!',
                    'redirect_url': '/lands/',
                    'buyer_id': buyer.BuyerID 
                })
                response.set_cookie('Bname', Bname, httponly=True, samesite='Lax', secure=settings.DEBUG)
                request.session['buyer_id'] = buyer.BuyerID
                request.session['buyer_name'] = Bname
                return response
            return JsonResponse(
                {'success': False, 'error': 'Invalid credentials'}, 
                status=400
            )
        except Buyer.DoesNotExist:
            return JsonResponse(
                {'success': False, 'error': 'Buyer not found'}, 
                status=400
            )

    elif request.method == "POST":
        
        Bname = request.POST.get('Bname')
        pwd = request.POST.get('psw')

        if not Bname or not pwd:
            messages.error(request, "Username and password are required")
            return render(request, 'buyerloginpage.html')

        try:
            buyer = Buyer.objects.get(Bname__iexact=Bname)
            if check_password(pwd, buyer.password):
                response = redirect('lands')
                response.set_cookie('Bname', Bname, httponly=True, samesite='Lax', secure=settings.DEBUG)
                request.session['buyer_id'] = buyer.BuyerID
                request.session['buyer_name'] = Bname
                messages.success(request, "Login successful!")
                return response
            messages.error(request, "Invalid credentials")
        except Buyer.DoesNotExist:
            messages.error(request, "Buyer not found")

    return render(request, 'buyerloginpage.html')

def buyerloginpage(request):
    return render(request, "buyerloginpage.html")

def uregB(request):
    if request.method == "GET":
        
        uname = request.GET.get('usrname')
        pwd = request.GET.get('psw')
        address = request.GET.get('Address')
        phone = request.GET.get('phone')

        if not all([uname, pwd, address, phone]):
            return JsonResponse({'success': False, 'error': 'All fields are required'}, status=400)

        try:
            if Buyer.objects.filter(Bname=uname).exists():
                return JsonResponse({'success': False, 'error': 'Username already exists'}, status=400)

            if Buyer.objects.filter(Baddress=address).exists():
                return JsonResponse({'success': False, 'error': 'Email already registered'}, status=400)

            buyer = Buyer.objects.create(
                Bname=uname,
                password=make_password(pwd),
                Baddress=address,
                Bphone_number=phone
            )

            send_mail(
                "Registration Successful",
                f"Your Buyer ID is {buyer.BuyerID}",
                "your-email@example.com",
                [address],
                fail_silently=False,
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Registration successful! Please login.',
                'redirect_url': '/buyerloginpage/'
            })

        except IntegrityError:
            return JsonResponse({'success': False, 'error': 'Registration failed. Please try again.'}, status=400)

    elif request.method == "POST":
        
        uname = request.POST.get('usrname')
        pwd = request.POST.get('psw')
        address = request.POST.get('Address')
        phone = request.POST.get('phone')

        if not all([uname, pwd, address, phone]):
            messages.error(request, "All fields are required")
            return render(request, 'buyersignuppage.html')

        try:
            if Buyer.objects.filter(Bname=uname).exists():
                messages.error(request, "Username already exists")
                return render(request, 'buyersignuppage.html')

            if Buyer.objects.filter(Baddress=address).exists():
                messages.error(request, "Email already registered")
                return render(request, 'buyersignuppage.html')

            buyer = Buyer.objects.create(
                Bname=uname,
                password=make_password(pwd),
                Baddress=address,
                Bphone_number=phone
            )

            send_mail(
                "Registration Successful",
                f"Your Buyer ID is {buyer.BuyerID}",
                "your-email@example.com",
                [address],
                fail_silently=False,
            )
            messages.success(request, "Registration successful! Please login.")
            return redirect('buyerloginpage')
        except IntegrityError:
            messages.error(request, "Registration failed. Please try again.")
        
    return render(request, 'buyersignuppage.html')

def buyersignuppage(request):
    return render(request, "buyersignuppage.html")

# Seller Authentication
def seller_login(request):
    if request.method == "POST":
        Sname = request.POST.get('Sname')
        pwd = request.POST.get('psw')

        if not Sname or not pwd:
            messages.error(request, "Username and password are required")
            return render(request, 'sellerloginpage.html')

        try:
            seller = Seller.objects.get(Sname=Sname)
            if check_password(pwd, seller.password):
                response = redirect('SellerAddLand')
                response.set_cookie('Sname', Sname, httponly=True, samesite='Lax')
                messages.success(request, "Login successful!")
                return response
            else:
                messages.error(request, "Invalid credentials")
        except Seller.DoesNotExist:
            messages.error(request, "Seller not found")

    return render(request, 'sellerloginpage.html')

def sellerloginpage(request):
    return render(request, "sellerloginpage.html")

def uloginS(request):
    if request.method == "POST":
        try:
        
            is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
            
            
            if is_ajax and request.content_type == 'application/json':
                try:
                    data = json.loads(request.body)
                    Sname = data.get('Sname')
                    psw = data.get('psw')
                except json.JSONDecodeError:
                    return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
            else:
                Sname = request.POST.get('Sname')
                psw = request.POST.get('psw')

            # Validate input
            if not Sname or not psw:
                if is_ajax:
                    return JsonResponse({
                        'success': False,
                        'error': 'Username and password are required'
                    }, status=400)
                messages.error(request, "Username and password are required")
                return render(request, 'sellerloginpage.html')

            # Authenticate seller
            try:
                seller = Seller.objects.get(Sname=Sname)
                if not check_password(psw, seller.password):
                    raise Seller.DoesNotExist()
            except Seller.DoesNotExist:
                error_msg = "Invalid credentials"
                if is_ajax:
                    return JsonResponse({
                        'success': False,
                        'error': error_msg
                    }, status=400)
                messages.error(request, error_msg)
                return render(request, 'sellerloginpage.html')

            # Create successful response
            if is_ajax:
                response = JsonResponse({
                    'success': True,
                    'redirect_url': '/SellerAddLand/'
                })
            else:
                response = redirect('/SellerAddLand/')
                messages.success(request, "Login successful!")
            
            # Set cookie and return
            response.set_cookie('Sname', Sname, httponly=True, samesite='Lax')
            return response

        except Exception as e:
            error_msg = f"An error occurred: {str(e)}"
            if is_ajax:
                return JsonResponse({
                    'success': False,
                    'error': error_msg
                }, status=500)
            messages.error(request, error_msg)
            return render(request, 'sellerloginpage.html')

    
    return render(request, 'sellerloginpage.html')

def uregS(request):
    if request.method == "GET":
        uname = request.GET.get('usrname')
        pwd = request.GET.get('psw')
        address = request.GET.get('Address')
        phone = request.GET.get('phone')

        if not all([uname, pwd, address, phone]):
            return HttpResponse("All fields are required", status=400)

        try:
            if Seller.objects.filter(Sname=uname).exists():
                return HttpResponse("Username already exists", status=400)

            if Seller.objects.filter(Saddress=address).exists():
                return HttpResponse("Email already registered", status=400)

            seller = Seller.objects.create(
                Sname=uname,
                password=make_password(pwd),
                Saddress=address,
                Sphone_number=phone
            )

            send_mail(
                "Registration Successful",
                f"Your Seller ID is {seller.SellerID}",
                "your-email@example.com",
                [address],
                fail_silently=False,
            )
            return HttpResponse("Registration successful", status=200)
            
        except IntegrityError as e:
            return HttpResponse(f"Registration failed: {str(e)}", status=400)

    elif request.method == "POST":
        uname = request.POST.get('usrname')
        pwd = request.POST.get('psw')
        address = request.POST.get('Address')
        phone = request.POST.get('phone')

        if not all([uname, pwd, address, phone]):
            messages.error(request, "All fields are required")
            return render(request, 'sellersignuppage.html')

        try:
            if Seller.objects.filter(Sname=uname).exists():
                messages.error(request, "Username already exists")
                return render(request, 'sellersignuppage.html')

            if Seller.objects.filter(Saddress=address).exists():
                messages.error(request, "Email already registered")
                return render(request, 'sellersignuppage.html')

            seller = Seller.objects.create(
                Sname=uname,
                password=make_password(pwd),
                Saddress=address,
                Sphone_number=phone
            )

            send_mail(
                "Registration Successful",
                f"Your Seller ID is {seller.SellerID}",
                "your-email@example.com",
                [address],
                fail_silently=False,
            )
            messages.success(request, "Registration successful! Please login.")
            return redirect('sellerloginpage')
        except IntegrityError as e:
            messages.error(request, f"Registration failed: {str(e)}")
            return render(request, 'sellersignuppage.html')
    
    return render(request, 'sellersignuppage.html')

def sellersignuppage(request):
    return render(request, "sellersignuppage.html")

# Broker Authentication
def broker_login(request):
    if request.method == "GET":
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            uname = request.GET.get('usname')
            pwd = request.GET.get('psw')

            if not uname or not pwd:
                return JsonResponse({'success': False, 'error': 'Username and password are required'}, status=400)

            try:
                broker = Broker.objects.get(Brname=uname)
                if check_password(pwd, broker.password):
                    return JsonResponse({
                        'success': True,
                        'redirect_url': '/Brokerpage/',
                        'message': 'Login successful!'
                    })
                return JsonResponse({'success': False, 'error': 'Invalid credentials'}, status=400)

            except Broker.DoesNotExist:
                return JsonResponse({'success': False, 'error': 'Broker not found'}, status=400)

        return render(request, 'brokerloginpage.html')

    elif request.method == "POST":
        uname = request.POST.get('usname')
        pwd = request.POST.get('psw')

        if not uname or not pwd:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'error': 'Username and password are required'}, status=400)
            messages.error(request, "Username and password are required")
            return render(request, 'brokerloginpage.html')

        try:
            broker = Broker.objects.get(Brname=uname)
            if check_password(pwd, broker.password):
                response = JsonResponse({'success': True, 'redirect_url': '/Brokerpage/', 'message': 'Login successful!'})
                response.set_cookie('usname', uname, httponly=True, samesite='Lax')
                return response

            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'error': 'Invalid credentials'}, status=400)
            messages.error(request, "Invalid credentials")

        except Broker.DoesNotExist:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'error': 'Broker not found'}, status=400)
            messages.error(request, "Broker not found")

        return render(request, 'brokerloginpage.html')

def brokerloginpage(request):
    """Simple view to render broker login page"""
    return render(request, 'brokerloginpage.html')

def brokersignuppage(request):
    """Simple view to render broker signup page"""
    return render(request, 'brokersignuppage.html')


@require_http_methods(["GET", "POST"])
def ureg(request):
    if request.method == "GET":
        return render(request, 'brokersignuppage.html')

    elif request.method == "POST":
        uname = request.POST.get('usrname')
        pwd = request.POST.get('psw')
        address = request.POST.get('Address')
        phone = request.POST.get('phone')

        if not all([uname, pwd, address, phone]):
            return JsonResponse({'success': False, 'error': 'All fields are required'}, status=400)

        try:
            if Broker.objects.filter(Brname=uname).exists():
                return JsonResponse({'success': False, 'error': 'Username already exists'}, status=400)

            if Broker.objects.filter(address=address).exists():
                return JsonResponse({'success': False, 'error': 'Email already registered'}, status=400)

            broker = Broker.objects.create(
                Brname=uname,
                password=make_password(pwd),
                address=address,
                Brphone_number=phone
            )

            send_mail(
                "Registration Successful",
                f"Your Broker ID is {broker.BrokerID}",
                "your-email@example.com",
                [address],
                fail_silently=False,
            )

            return JsonResponse({
                'success': True,
                'message': 'Registration successful!',
                'redirect_url': '/brokerloginpage/'
            })

        except IntegrityError as e:
            return JsonResponse({'success': False, 'error': f'Registration failed: {str(e)}'}, status=400)

    return render(request, 'brokersignuppage.html')

# Land Management
def SellerAddLand(request):
    if 'Sname' not in request.COOKIES:
        messages.error(request, "Please login first")
        return redirect('sellerloginpage')
    return render(request, "addLand.html")

@require_http_methods(["POST"])
def SaddS(request):
    
    if 'Sname' not in request.COOKIES:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'error': 'Please login first'}, status=401)
        messages.error(request, "Please login first")
        return redirect('sellerloginpage')

    try:
        seller = Seller.objects.get(Sname=request.COOKIES.get('Sname'))
        
        
        land = Land.objects.create(
            owns=seller,
            Address=request.POST.get("Address"),
            Soil_type=request.POST.get("Soil_type"),
            water_sources=request.POST.get("water_sources"),
            Land_area=request.POST.get("Land_area"),
            suitable_crop=request.POST.get("suitable_crop"),
            weather=request.POST.get("weather"),
            protection_type=request.POST.get("protection_type"),
            Amount=request.POST.get("Amount")
        )
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'success': True, 
                'message': 'Land added successfully!',
                'redirect': '/lands/'
            })
        
        messages.success(request, "Land added successfully!")
        return redirect('lands')
            
    except Exception as e:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'error': str(e),
                'message': 'Failed to save land details'
            }, status=400)
        messages.error(request, f"Error: {str(e)}")
        return redirect('SellerAddLand')

# Land Search and Display
def search(request):
    return render(request, "search.html")

def Bsearch(request):
    query = request.GET.get('q')
    lands = Land.objects.filter(location__icontains=query) if query else Land.objects.all()
    return render(request, "search_results.html", {'lands': lands})

def Bdisplay(request):
    land_id = request.GET.get('id')
    try:
        land = Land.objects.get(id=land_id)
        return render(request, "land_detail.html", {'land': land})
    except Land.DoesNotExist:
        messages.error(request, "Land not found")
        return redirect('lands')

# Buyer Operations
def lands(request):
    lands = Land.objects.all()
    return render(request, "lands.html", {'lands': lands})

def coll(request):
    if 'Bname' not in request.COOKIES:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'error': 'Please login first'}, status=401)
        messages.error(request, "Please login first")
        return redirect('buyerloginpage')
    
    try:
        
        buyer = Buyer.objects.get(Bname=request.COOKIES.get('Bname'))
        
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'html': render_to_string('order_form.html', {}, request)
            })
        return render(request, "order_form.html")
        
    except Exception as e:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'error': str(e)}, status=400)
        messages.error(request, f"Error: {str(e)}")
        return redirect('lands')

def uorder(request):
    if request.method == "POST":
        if 'Bname' not in request.COOKIES:
            messages.error(request, "Please login first")
            return redirect('buyerloginpage')

        try:
            buyer_name = request.COOKIES.get('Bname')
            buyer = Buyer.objects.get(Bname=buyer_name)
            land_id = request.POST.get('land_id')
            land = Land.objects.get(id=land_id)
            
            messages.success(request, "Order placed successfully!")
            return redirect('lands')
        except Exception as e:
            messages.error(request, f"Failed to place order: {str(e)}")
    
    return redirect('lands')

# Broker Operations
def bro(request):
    if 'usname' not in request.COOKIES:
        messages.error(request, "Please login first")
        return redirect('brokerloginpage')
    return render(request, "broker_dashboard.html")

def border(request):
    if request.method == "POST":
        if 'usname' not in request.COOKIES:
            messages.error(request, "Please login first")
            return redirect('brokerloginpage')

        try:
            broker_name = request.COOKIES.get('usname')
            broker = Broker.objects.get(Brname=broker_name)
            land_id = request.POST.get('land_id')
            land = Land.objects.get(id=land_id)
            
            messages.success(request, "Booking confirmed!")
            return redirect('bro')
        except Exception as e:
            messages.error(request, f"Failed to confirm booking: {str(e)}")
    
    return redirect('bro')

def Brokers(request):
    brokers = Broker.objects.all()
    return render(request, "brokers_list.html", {'brokers': brokers})

def Brokerpage(request):
    if 'usname' not in request.COOKIES:
        messages.error(request, "Please login first")
        return redirect('brokerloginpage')

    try:
        broker_name = request.COOKIES.get('usname')
        broker = Broker.objects.get(Brname=broker_name)
        return render(request, "brokers.html", {'broker': broker})
    except Broker.DoesNotExist:
        messages.error(request, "Broker not found")
        return redirect('brokerloginpage')

# Password Reset - Broker
def getotpbr(request):
    if request.method == "POST":
        email = request.POST.get("email")
        if not email:
            messages.error(request, "Email is required")
            return render(request, "forgot_password_br.html")

        try:
            broker = Broker.objects.get(address=email)
            otp = randint(100000, 999999)
            broker.otp = otp
            broker.save()
            
            send_mail(
                "Password Reset OTP",
                f"Your OTP is {otp}",
                "your-email@example.com",
                [email],
                fail_silently=False,
            )
            return render(request, "otp_verify_br.html", {'email': email})
        except Broker.DoesNotExist:
            messages.error(request, "Email not found")
    
    return render(request, "forgot_password_br.html")

def brpass(request):
    if request.method == "POST":
        otp = request.POST.get("otp")
        email = request.POST.get("email")
        
        if not otp or not email:
            messages.error(request, "OTP and email are required")
            return render(request, "otp_verify_br.html")

        try:
            broker = Broker.objects.get(address=email, otp=otp)
            return render(request, "reset_password_br.html", {'email': email})
        except Broker.DoesNotExist:
            messages.error(request, "Invalid OTP")
    
    return render(request, "otp_verify_br.html")

def brchangepass(request):
    if request.method == "POST":
        email = request.POST.get("email")
        new_pass = request.POST.get("new_pass")
        
        if not email or not new_pass:
            messages.error(request, "Email and new password are required")
            return render(request, "reset_password_br.html")

        try:
            broker = Broker.objects.get(address=email)
            broker.password = make_password(new_pass)
            broker.save()
            messages.success(request, "Password changed successfully!")
            return redirect('brokerloginpage')
        except Broker.DoesNotExist:
            messages.error(request, "Invalid request")
    
    return render(request, "reset_password_br.html")

# Password Reset - Seller
def getotps(request):
    if request.method == "POST":
        email = request.POST.get("email")
        if not email:
            messages.error(request, "Email is required")
            return render(request, "forgot_password_seller.html")

        try:
            seller = Seller.objects.get(Saddress=email)
            otp = randint(100000, 999999)
            seller.otp = otp
            seller.save()
            
            send_mail(
                "Password Reset OTP",
                f"Your OTP is {otp}",
                "your-email@example.com",
                [email],
                fail_silently=False,
            )
            return render(request, "otp_verify_seller.html", {'email': email})
        except Seller.DoesNotExist:
            messages.error(request, "Email not found")
    
    return render(request, "forgot_password_seller.html")

def spass(request):
    if request.method == "POST":
        otp = request.POST.get("otp")
        email = request.POST.get("email")
        
        if not otp or not email:
            messages.error(request, "OTP and email are required")
            return render(request, "otp_verify_seller.html")

        try:
            seller = Seller.objects.get(Saddress=email, otp=otp)
            return render(request, "reset_password_seller.html", {'email': email})
        except Seller.DoesNotExist:
            messages.error(request, "Invalid OTP")
    
    return render(request, "otp_verify_seller.html")

def schangepass(request):
    if request.method == "POST":
        email = request.POST.get("email")
        new_pass = request.POST.get("new_pass")
        
        if not email or not new_pass:
            messages.error(request, "Email and new password are required")
            return render(request, "reset_password_seller.html")

        try:
            seller = Seller.objects.get(Saddress=email)
            seller.password = make_password(new_pass)
            seller.save()
            messages.success(request, "Password changed successfully!")
            return redirect('sellerloginpage')
        except Seller.DoesNotExist:
            messages.error(request, "Invalid request")
    
    return render(request, "reset_password_seller.html")

def ulogin(request):
    """Handle broker login through /ulogin/ endpoint"""
    if request.method == "POST":
        uname = request.POST.get('usname')
        pwd = request.POST.get('psw')

        if not uname or not pwd:
            messages.error(request, "Username and password are required")
            return render(request, 'brokerloginpage.html')

        try:
            broker = Broker.objects.get(Brname=uname)
            if check_password(pwd, broker.password):
                response = redirect('Brokerpage')
                response.set_cookie('usname', uname, httponly=True, samesite='Lax')
                messages.success(request, "Login successful!")
                return response
            messages.error(request, "Invalid credentials")
        except Broker.DoesNotExist:
            messages.error(request, "Broker not found")
    
    return render(request, 'brokerloginpage.html')

# Error Handlers
def bad_request(request, exception=None):
    return render(request, '400.html', status=400)

def permission_denied(request, exception=None):
    return render(request, '403.html', status=403)

def page_not_found(request, exception=None):
    return render(request, '404.html', status=404)

def server_error(request):
    return render(request, '500.html', status=500)
