"""
DukaanOS Auth Utilities
Handles: OTP generation, password hashing, session tokens,
         brute-force guards, IP extraction, real SMS & Email OTP delivery.
"""

import secrets
import hashlib
import random
import string
import logging
import requests
from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
#  PASSWORD HASHING
# ─────────────────────────────────────────────────────────────────

def hash_password(raw_password: str) -> str:
    from django.contrib.auth.hashers import make_password
    return make_password(raw_password)


def check_password(raw_password: str, hashed: str) -> bool:
    from django.contrib.auth.hashers import check_password as django_check
    return django_check(raw_password, hashed)


# ─────────────────────────────────────────────────────────────────
#  OTP
# ─────────────────────────────────────────────────────────────────

def generate_otp(length: int = 6) -> str:
    """Generate a numeric OTP of given length."""
    return ''.join(random.choices(string.digits, k=length))


def hash_otp(otp: str) -> str:
    """Hash an OTP before storing in DB."""
    return hashlib.sha256(otp.encode()).hexdigest()


def get_otp_expiry():
    """Return OTP expiry datetime (now + OTP_EXPIRY_MINUTES)."""
    minutes = getattr(settings, 'OTP_EXPIRY_MINUTES', 15)
    return timezone.now() + timedelta(minutes=minutes)


# ─────────────────────────────────────────────────────────────────
#  SMS OTP — Fast2SMS
# ─────────────────────────────────────────────────────────────────

def send_phone_otp(phone: str, otp: str) -> bool:
    """
    Send OTP via SMS using Fast2SMS.

    Required in settings.py:
        FAST2SMS_API_KEY = 'your_fast2sms_api_key'

    Optional (for DLT registered templates):
        FAST2SMS_SENDER_ID  = 'DKNOS'
        FAST2SMS_TEMPLATE_ID = 'your_dlt_template_id'

    Get your free API key at: https://www.fast2sms.com/
    """
    # ── [DEBUG] Print to terminal for easy access ──
    print(f"\n{'='*45}")
    print(f"  [TERMINAL OTP] PHONE: +91{phone}  =>  {otp}")
    print(f"{'='*45}\n", flush=True)

    api_key = getattr(settings, 'FAST2SMS_API_KEY', None)

    # ── Development fallback ──
    if not api_key or api_key == 'your_fast2sms_api_key':
        logger.warning("[DEV MODE] Fast2SMS not configured. OTP already printed above.")
        return True

    # ── Production: Twilio REST API (no package needed, uses requests) ──
    twilio_sid   = getattr(settings, 'TWILIO_ACCOUNT_SID', None)
    twilio_token = getattr(settings, 'TWILIO_AUTH_TOKEN', None)
    twilio_from  = getattr(settings, 'TWILIO_FROM_NUMBER', None)

    if twilio_sid and twilio_token and twilio_from             and twilio_sid != 'your_twilio_account_sid':
        try:
            url  = f"https://api.twilio.com/2010-04-01/Accounts/{twilio_sid}/Messages.json"
            data = {
                "From": twilio_from,
                "To":   f"+91{phone}",
                "Body": f"Your DukaanOS OTP is {otp}. Valid for 15 minutes. Do not share.",
            }
            resp = requests.post(url, data=data,
                                 auth=(twilio_sid, twilio_token), timeout=15)
            result = resp.json()
            if resp.status_code in (200, 201) and result.get('sid'):
                logger.info(f"SMS OTP sent to +91{phone} via Twilio (sid={result['sid']})")
                print(f"\n  SMS sent to +91{phone} via Twilio OK\n", flush=True)
                return True
            else:
                err_msg = result.get('message', str(result))
                logger.error(f"Twilio error for +91{phone}: {result}")
                print(f"\n  TWILIO ERROR: {err_msg}\n", flush=True)
                return False
        except Exception as e:
            logger.error(f"Twilio SMS failed for +91{phone}: {e}")
            return False

    # ── Fallback: Fast2SMS Quick SMS ──
    try:
        url     = "https://www.fast2sms.com/dev/bulkV2"
        headers = {"authorization": api_key, "Content-Type": "application/json"}
        payload = {
            "route": "q",
            "message": f"Your DukaanOS OTP is {otp}. Valid for 15 minutes. Do not share.",
            "language": "english",
            "flash": "0",
            "numbers": phone,
        }
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        data = resp.json()
        if data.get('return') is True:
            logger.info(f"SMS OTP sent to +91{phone} via Fast2SMS")
            return True
        else:
            logger.error(f"Fast2SMS error for {phone}: {data}")
            return False
    except Exception as e:
        logger.error(f"SMS OTP send failed for +91{phone}: {e}")
        return False


# ─────────────────────────────────────────────────────────────────
#  EMAIL OTP — Django SMTP
# ─────────────────────────────────────────────────────────────────

def send_email_otp(email: str, otp: str) -> bool:
    """
    Send OTP via email using Django's SMTP backend.

    Required in settings.py:
        EMAIL_BACKEND       = 'django.core.mail.backends.smtp.EmailBackend'
        EMAIL_HOST          = 'smtp.gmail.com'
        EMAIL_PORT          = 587
        EMAIL_USE_TLS       = True
        EMAIL_HOST_USER     = 'nickpate8687.com'
        EMAIL_HOST_PASSWORD = 'hdyc eoyz yadf fdbs'
        DEFAULT_FROM_EMAIL  = 'DukaanOS <nickpate8687.com>'

    For Gmail App Password: enable 2FA then visit
    https://myaccount.google.com/apppasswords
    """
    # ── [DEBUG] Print to terminal for easy access ──
    print(f"\n{'='*45}")
    print(f"  [TERMINAL OTP] EMAIL: {email}  =>  {otp}")
    print(f"{'='*45}\n", flush=True)

    host       = getattr(settings, 'EMAIL_HOST', None)
    from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', '')

    # ── Development fallback ──
    if not host or 'your@gmail.com' in from_email:
        logger.warning("[DEV MODE] Email not configured. OTP already printed above.")
        return True

    # ── Production: send real email ──
    try:
        subject = "DukaanOS – Your Verification OTP"

        plain_message = (
            f"Hello,\n\n"
            f"Your DukaanOS email verification OTP is:\n\n"
            f"  {otp}\n\n"
            f"This OTP is valid for 15 minutes.\n"
            f"Do not share this code with anyone.\n\n"
            f"If you did not request this, please ignore this email.\n\n"
            f"– DukaanOS Team"
        )

        html_message = f"""
<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;
            border:1px solid #e0e0e0;border-radius:8px;overflow:hidden;">
  <div style="background:#1a73e8;padding:20px;text-align:center;">
    <h2 style="color:#fff;margin:0;font-size:22px;">DukaanOS</h2>
    <p style="color:#d0e8ff;margin:4px 0 0;font-size:13px;">Email Verification</p>
  </div>
  <div style="padding:28px;">
    <p style="font-size:15px;color:#333;margin-top:0;">Hello,</p>
    <p style="font-size:15px;color:#333;">
      Use the following OTP to verify your email address:
    </p>
    <div style="text-align:center;margin:24px 0;">
      <span style="font-size:38px;font-weight:bold;letter-spacing:12px;
                   color:#1a73e8;background:#f0f6ff;padding:14px 24px;
                   border-radius:8px;display:inline-block;">{otp}</span>
    </div>
    <p style="font-size:13px;color:#666;text-align:center;">
      ⏱ Valid for <strong>15 minutes</strong> &nbsp;|&nbsp;
      🔒 Do <strong>not</strong> share this code
    </p>
    <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
    <p style="font-size:12px;color:#999;text-align:center;margin:0;">
      If you didn't request this, you can safely ignore this email.
    </p>
  </div>
</div>
"""

        send_mail(
            subject=subject,
            message=plain_message,
            from_email=from_email,
            recipient_list=[email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"Email OTP sent to {email}")
        return True

    except Exception as e:
        logger.error(f"Email OTP send failed for {email}: {e}")
        return False


# ─────────────────────────────────────────────────────────────────
#  SESSION TOKEN
# ─────────────────────────────────────────────────────────────────

def generate_session_token() -> str:
    return secrets.token_hex(32)


def get_session_expiry():
    days = getattr(settings, 'SESSION_EXPIRY_DAYS', 30)
    return timezone.now() + timedelta(days=days)


# ─────────────────────────────────────────────────────────────────
#  IP / REQUEST HELPERS
# ─────────────────────────────────────────────────────────────────

def get_client_ip(request) -> str:
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def get_user_agent(request) -> str:
    return request.META.get('HTTP_USER_AGENT', '')[:255]


# ─────────────────────────────────────────────────────────────────
#  BRUTE-FORCE GUARD
# ─────────────────────────────────────────────────────────────────

def is_login_blocked(phone: str, ip: str) -> bool:
    from .models import LoginAttempt
    max_attempts = getattr(settings, 'LOGIN_MAX_ATTEMPTS', 5)
    window_start = timezone.now() - timedelta(minutes=15)

    phone_fails = LoginAttempt.objects.filter(
        phone=phone, is_success=False, attempted_at__gte=window_start,
    ).count()

    ip_fails = LoginAttempt.objects.filter(
        ip_address=ip, is_success=False, attempted_at__gte=window_start,
    ).count()

    return phone_fails >= max_attempts or ip_fails >= (max_attempts * 3)


def log_login_attempt(phone: str, ip: str, success: bool):
    from .models import LoginAttempt
    LoginAttempt.objects.create(phone=phone, ip_address=ip, is_success=success)


# ─────────────────────────────────────────────────────────────────
#  AUDIT LOGGER
# ─────────────────────────────────────────────────────────────────

def write_audit(store_id, user_id, action: str, ip: str = None,
                entity_type: str = None, entity_id: int = None,
                metadata: dict = None):
    try:
        from .models import AuditLog
        AuditLog.objects.create(
            store_id=store_id, user_id=user_id, action=action,
            entity_type=entity_type, entity_id=entity_id,
            ip_address=ip, metadata=metadata,
        )
    except Exception as e:
        logger.warning(f"Audit log write failed: {e}")


# ─────────────────────────────────────────────────────────────────
#  VALIDATION HELPERS
# ─────────────────────────────────────────────────────────────────

def validate_phone(phone: str) -> bool:
    return bool(phone) and len(phone) == 10 and phone.isdigit() \
           and phone[0] in '6789'


def validate_pincode(pin: str) -> bool:
    return bool(pin) and len(pin) == 6 and pin.isdigit()


def validate_gst(gst: str) -> bool:
    if not gst:
        return True
    import re
    pattern = r'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$'
    return bool(re.match(pattern, gst.upper()))


def validate_fssai(fssai: str) -> bool:
    if not fssai:
        return True
    return len(fssai) == 14 and fssai.isdigit()
