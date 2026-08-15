import os
import json
import requests

_config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "keys.json")
try:
    with open(_config_path) as f:
        _keys = json.load(f)
except Exception:
    _keys = {}

MSG91_API_KEY = os.environ.get("MSG91_API_KEY", _keys.get("MSG91_API_KEY", ""))
MSG91_SENDER_ID = os.environ.get("MSG91_SENDER_ID", _keys.get("MSG91_SENDER_ID", "CYBSHL"))
MSG91_TEMPLATE_ID = os.environ.get("MSG91_TEMPLATE_ID", _keys.get("MSG91_TEMPLATE_ID", ""))

TWILIO_SID = os.environ.get("TWILIO_ACCOUNT_SID", _keys.get("TWILIO_ACCOUNT_SID", ""))
TWILIO_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", _keys.get("TWILIO_AUTH_TOKEN", ""))
TWILIO_FROM = os.environ.get("TWILIO_FROM", _keys.get("TWILIO_FROM", ""))
TWILIO_VERIFY_SID = os.environ.get("TWILIO_VERIFY_SERVICE_SID", _keys.get("TWILIO_VERIFY_SERVICE_SID", ""))


def send_sms(phone, otp):
    """Send OTP via SMS. Tries Twilio first, then MSG91, then console."""

    result_twilio = _send_twilio(phone, otp)
    if result_twilio[0]:
        return result_twilio

    result_msg91 = _send_msg91(phone, otp)
    if result_msg91[0]:
        return result_msg91

    print(f"[SMS][FALLBACK] OTP for {phone}: {otp}")
    return True, f"OTP {otp} (console fallback — configure MSG91 or Twilio for real SMS)"


def _send_msg91(phone, otp):
    """Send OTP via MSG91 Flow API (Indian SMS gateway). Free: 1000 SMS/month."""
    if not MSG91_API_KEY:
        return False, "MSG91 not configured"

    digits = phone.replace("+", "").replace(" ", "")
    if digits.startswith("91") and len(digits) == 12:
        pass
    elif len(digits) == 10:
        digits = "91" + digits

    if MSG91_TEMPLATE_ID:
        url = "https://api.msg91.com/api/v5/otp"
        headers = {"authkey": MSG91_API_KEY, "Content-Type": "application/json"}
        payload = {
            "mobile": f"+{digits}",
            "otp": otp,
            "template_id": MSG91_TEMPLATE_ID,
            "sender": MSG91_SENDER_ID
        }
    else:
        url = "https://api.msg91.com/api/v2/sendsms"
        headers = {
            "authkey": MSG91_API_KEY,
            "Content-Type": "application/json"
        }
        payload = {
            "sender": MSG91_SENDER_ID,
            "route": "4",
            "country": "91",
            "sms": [
                {
                    "message": f"Your CyberShield verification code is {otp}. Do not share this with anyone.",
                    "to": [digits]
                }
            ]
        }

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        data = resp.json()
        if resp.status_code == 200 and data.get("type") == "success":
            return True, f"SMS sent via MSG91 to {phone}"
        return False, f"MSG91 error: {data.get('message', resp.text)}"
    except Exception as e:
        return False, f"MSG91 error: {str(e)}"


def _send_twilio(phone, otp):
    """Send OTP via Twilio Verify API (trial-account friendly)."""
    if not (TWILIO_SID and TWILIO_TOKEN):
        return False, "Twilio not configured"

    try:
        from twilio.rest import Client
        client = Client(TWILIO_SID, TWILIO_TOKEN)

        if TWILIO_VERIFY_SID:
            verification = client.verify.v2.services(TWILIO_VERIFY_SID).verifications.create(
                to=phone, channel="sms"
            )
            if verification.status == "pending":
                return True, f"SMS sent via Twilio Verify to {phone}"
            return False, f"Twilio Verify status: {verification.status}"
        else:
            client.messages.create(
                body=f"{otp} is your verification code.",
                from_=TWILIO_FROM,
                to=phone
            )
            return True, f"SMS sent via Twilio to {phone}"
    except Exception as e:
        return False, f"Twilio error: {str(e)}"


def verify_twilio_otp(phone, otp):
    """Verify OTP via Twilio Verify API. Returns (bool, message)."""
    if not (TWILIO_SID and TWILIO_TOKEN and TWILIO_VERIFY_SID):
        return False, "Twilio Verify not configured"
    try:
        from twilio.rest import Client
        client = Client(TWILIO_SID, TWILIO_TOKEN)
        check = client.verify.v2.services(TWILIO_VERIFY_SID).verification_checks.create(
            to=phone, code=otp
        )
        if check.status == "approved":
            return True, "OTP verified via Twilio"
        return False, f"Twilio verify status: {check.status}"
    except Exception as e:
        return False, f"Twilio verify error: {str(e)}"
