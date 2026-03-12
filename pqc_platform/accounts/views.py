import pyotp
import qrcode
import base64

from io import BytesIO

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User

from .models import UserOTP


def home(request):
    return render(request,"home.html")


# --------------------------------
# LOGIN (USERNAME + PASSWORD)
# --------------------------------
def login_view(request):

    if request.method == "POST":

        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user:

            # Store user id temporarily before OTP verification
            request.session["pre_2fa_user"] = user.id

            return redirect("/verify-otp/")

        return render(request, "login.html", {"error": "Invalid credentials"})

    return render(request, "login.html")


# --------------------------------
# OTP VERIFICATION
# --------------------------------

def verify_otp(request):

    user_id = request.session.get("pre_2fa_user")

    if not user_id:
        return redirect("/")

    user = User.objects.get(id=user_id)

    otp_obj, created = UserOTP.objects.get_or_create(user=user)

    # FIRST TIME SETUP
    if not otp_obj.otp_enabled:

        if not otp_obj.otp_secret:
            otp_obj.otp_secret = pyotp.random_base32()
            otp_obj.save()

        totp = pyotp.TOTP(otp_obj.otp_secret)

        uri = totp.provisioning_uri(
            user.username,
            issuer_name="PQC Security Platform"
        )

        qr = qrcode.make(uri)

        buffer = BytesIO()
        qr.save(buffer, format="PNG")

        qr_code = base64.b64encode(buffer.getvalue()).decode()

        if request.method == "POST":

            code = request.POST.get("otp")

            if totp.verify(code):

                otp_obj.otp_enabled = True
                otp_obj.save()

                login(request, user)

                del request.session["pre_2fa_user"]

                return redirect("/dashboard/")

            return render(request, "otp.html", {
                "qr": qr_code,
                "error": "Invalid OTP"
            })

        return render(request, "otp.html", {
            "qr": qr_code,
            "setup": True
        })

    # USER ALREADY HAS 2FA
    else:

        totp = pyotp.TOTP(otp_obj.otp_secret)

        if request.method == "POST":

            code = request.POST.get("otp")

            if totp.verify(code):

                login(request, user)

                del request.session["pre_2fa_user"]

                return redirect("/dashboard/")

            return render(request, "otp.html", {
                "error": "Invalid OTP"
            })

        return render(request, "otp.html", {
            "setup": False
        })

# --------------------------------
# LOGOUT
# --------------------------------
def logout_view(request):

    logout(request)

    return redirect("/")
