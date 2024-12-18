import base64
from io import BytesIO

import qrcode
from .models import *
import pyotp

def getLoginUserService(request):
	data = request.data
	username = data.get('username', None)
	password = data.get('password', None)
	try:
		user = User.objects.get(username = username, password = password)
		return user
	except:
		return None

def getUserService(request):
	try:
		data = request.data
		user_id = data.get('user_id', None)
		user = User.objects.get(id = user_id)
		return user
	except:
		return None

def getOTPValidityService(user, otp):
	totp = pyotp.TOTP(user.otp_base32)
	if not totp.verify(otp):
		return False
	user.logged_in = True
	user.save()
	return True

def getQRCodeService(user):
    # Generate a base32 OTP secret key
    otp_base32 = pyotp.random_base32()

    # Generate OTP provisioning URI
    otp_auth_url = pyotp.totp.TOTP(otp_base32).provisioning_uri(
        name=user.username.lower(), issuer_name="localhost.com"
    )

    user.otp_base32 = otp_base32
    user.save()

    # Generate the QR code as an image
    qr = qrcode.make(otp_auth_url)

    # Save the QR code image to a BytesIO buffer
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)

    # Encode the QR code image in base64
    qr_code_base64 = base64.b64encode(buffer.read()).decode("utf-8")
    
    return f"data:image/png;base64,{qr_code_base64}"