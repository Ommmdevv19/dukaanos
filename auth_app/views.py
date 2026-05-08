"""
DukaanOS Views — Schema v2
Auth & store data APIs aligned with dukaanos_schema_v2.sql.

Key changes from v1:
  - users table: only user_id, first_name, last_name, is_active
  - user_credentials: phone_number, email, password_hash (separate table)
  - user_contact_verification: replaces otp_logs
  - login_sessions: replaces user_sessions (no session_token; uses session_id as token)
  - stores: only store_id, user_id, store_name, location, pincode, gst_number, fssai_number
  - items: replaces products (item_name, brand, gst_percentage, category_id, store_id)
  - stock: separate table with current_quantity, wholesale_price, selling_price
  - stock_entries: audit log for stock additions
  - bills / bill_items / payments: proper schema tables (not auto-created)
"""

import json
import random
import string
import hashlib
import secrets
import traceback
from datetime import datetime, timedelta

from django.conf import settings as _django_settings

from django.http import JsonResponse
from django.utils import timezone
from django.db import connection, IntegrityError
from django.contrib.auth.hashers import make_password, check_password

from .utils import send_phone_otp, send_email_otp


# ─────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────

def ok(data={}):
    data['success'] = True
    return JsonResponse(data)

def fail(msg, status=400):
    return JsonResponse({'success': False, 'message': msg}, status=status)

def body(request):
    try:
        return json.loads(request.body)
    except Exception:
        return {}

def otp_hash(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def make_otp():
    return ''.join(random.choices(string.digits, k=6))

def make_token():
    return secrets.token_hex(32)

def to_local(dt):
    """
    Convert a datetime from the database (which we store in UTC via init_command)
    to the project's local timezone (Asia/Kolkata).
    """
    if dt is None: return None
    if dt.tzinfo is None:
        # Declare naive as UTC (since that's how we saved it)
        dt = dt.replace(tzinfo=timezone.utc)
    # Convert to Asia/Kolkata
    return dt.astimezone(timezone.get_current_timezone())

def get_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    return xff.split(',')[0].strip() if xff else request.META.get('REMOTE_ADDR', '0.0.0.0')

import re

def validate_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, 'Password must be at least 8 characters.'
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter.'
    if not re.search(r'[0-9]', password):
        return False, 'Password must contain at least one number.'
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, 'Password must contain at least one special character.'
    common = ['password', '12345678', 'qwerty123', 'dukaanos123', 'admin123']
    if password.lower() in common:
        return False, 'Password is too common.'
    return True, ''

def get_device_info(request):
    ua = (request.META.get('HTTP_USER_AGENT') or '').strip()
    return ua[:255] if ua else 'Web Browser'

def get_bearer_token(request):
    auth = request.META.get('HTTP_AUTHORIZATION', '')
    if auth.startswith('Bearer '):
        token = auth[7:].strip()
        if token and token != 'PROTECTED':
            return token
    # Fallback to HttpOnly cookie (enhanced security)
    return request.COOKIES.get('dukaanos_session')


def ensure_login_attempt_log():
    """Tracks failed login attempts for brute-force protection."""
    with connection.cursor() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS login_attempt_log (
                id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                phone        VARCHAR(15)  NOT NULL,
                ip_address   VARCHAR(45)  NOT NULL,
                success      TINYINT(1)   NOT NULL DEFAULT 0,
                attempted_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_phone_time (phone, attempted_at),
                INDEX idx_ip_time    (ip_address, attempted_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)


def _log_attempt(phone, ip, success):
    ensure_login_attempt_log()
    with connection.cursor() as c:
        c.execute(
            "INSERT INTO login_attempt_log (phone, ip_address, success, attempted_at) VALUES (%s, %s, %s, NOW())",
            [phone, ip, 1 if success else 0]
        )


def _check_login_blocked(phone, ip):
    """Returns (is_blocked, message) based on recent failed attempts."""
    ensure_login_attempt_log()
    max_attempts = getattr(_django_settings, 'LOGIN_MAX_ATTEMPTS', 5)
    window_mins  = getattr(_django_settings, 'LOGIN_LOCKOUT_MINUTES', 15)
    window_start = timezone.now() - timedelta(minutes=window_mins)

    with connection.cursor() as c:
        c.execute(
            "SELECT COUNT(*) FROM login_attempt_log WHERE phone=%s AND success=0 AND attempted_at > %s",
            [phone, window_start]
        )
        phone_fails = c.fetchone()[0]

        c.execute(
            "SELECT COUNT(*) FROM login_attempt_log WHERE ip_address=%s AND success=0 AND attempted_at > %s",
            [ip, window_start]
        )
        ip_fails = c.fetchone()[0]

    if phone_fails >= max_attempts:
        return True, f'Too many failed attempts. Try again in {window_mins} minutes.'
    if ip_fails >= max_attempts * 3:
        return True, f'Too many requests from this device. Try again in {window_mins} minutes.'
    return False, None


def _check_otp_attempts(user_id_or_phone, otp_type, is_pending=False):
    """Returns True if OTP has been guessed wrong too many times (should invalidate)."""
    max_attempts = getattr(_django_settings, 'OTP_MAX_ATTEMPTS', 5)
    if is_pending:
        # pending_registrations: count wrong attempts tracked in a separate table
        return False  # handled inline
    with connection.cursor() as c:
        c.execute("""
            SELECT COUNT(*) FROM otp_attempt_log
            WHERE user_id=%s AND otp_type=%s AND success=0
              AND attempted_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)
        """, [user_id_or_phone, otp_type])
        row = c.fetchone()
    return row and row[0] >= max_attempts


def ensure_otp_send_log():
    """Tracks frequency of OTP sends to prevent SMS bombing."""
    with connection.cursor() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS otp_send_log (
                id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                phone        VARCHAR(15)  NOT NULL,
                ip_address   VARCHAR(45)  NOT NULL,
                created_at   DATETIME     NOT NULL,
                INDEX (phone),
                INDEX (ip_address)
            ) ENGINE=InnoDB;
        """)


def ensure_otp_attempt_log():
    with connection.cursor() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS otp_attempt_log (
                id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                user_id      BIGINT       NOT NULL,
                otp_type     VARCHAR(20)  NOT NULL,
                success      TINYINT(1)   NOT NULL DEFAULT 0,
                attempted_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_type_time (user_id, otp_type, attempted_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)


def _log_otp_attempt(user_id, otp_type, success):
    ensure_otp_attempt_log()
    with connection.cursor() as c:
        c.execute(
            "INSERT INTO otp_attempt_log (user_id, otp_type, success, attempted_at) VALUES (%s, %s, %s, NOW())",
            [user_id, otp_type, 1 if success else 0]
        )

def _log_otp_send(phone, ip_address):
    """Logs an OTP send event for rate limiting."""
    with connection.cursor() as c:
        c.execute("""
            INSERT INTO otp_send_log (phone, ip_address, created_at)
            VALUES (%s, %s, NOW())
        """, [phone, ip_address])





# ─────────────────────────────────────────────────────────────
#  PENDING REGISTRATIONS (temp table, not in v2 schema)
# ─────────────────────────────────────────────────────────────

def ensure_pending_table():
    """Temporary staging table for multi-step registration OTPs."""
    with connection.cursor() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS pending_registrations (
                pending_id        BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                phone             VARCHAR(15)  NOT NULL UNIQUE,
                email             VARCHAR(100) NOT NULL DEFAULT '',
                first_name        VARCHAR(50)  NOT NULL DEFAULT '',
                last_name         VARCHAR(50)  NOT NULL DEFAULT '',
                shop_name         VARCHAR(100) NOT NULL DEFAULT '',
                location          VARCHAR(255) NOT NULL DEFAULT '',
                pincode           VARCHAR(10)  NOT NULL DEFAULT '',
                gst_number        VARCHAR(20)  DEFAULT NULL,
                fssai_number      VARCHAR(20)  DEFAULT NULL,
                password_hash     VARCHAR(255) NOT NULL DEFAULT '',
                phone_otp_hash    VARCHAR(255) DEFAULT NULL,
                email_otp_hash    VARCHAR(255) DEFAULT NULL,
                phone_otp_expires DATETIME     DEFAULT NULL,
                email_otp_expires DATETIME     DEFAULT NULL,
                expires_at        DATETIME     NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)


# ─────────────────────────────────────────────────────────────
#  SESSION HELPER — returns (user_id, store_id) or (None, None)
#  v2 schema: login_sessions has no token column; we use a
#  separate session_tokens helper table to map token → session.
# ─────────────────────────────────────────────────────────────

def ensure_session_tokens_table():
    """
    login_sessions in v2 has no token column, so we maintain a small
    helper table that maps opaque tokens to session_ids.
    """
    with connection.cursor() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS session_tokens (
                token_id    BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                session_id  BIGINT          NOT NULL,
                user_id     BIGINT          NOT NULL,
                token       CHAR(64)        NOT NULL UNIQUE,
                is_active   TINYINT(1)      NOT NULL DEFAULT 1,
                expires_at  DATETIME        NOT NULL,
                created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

def ensure_forgot_tokens_table():
    with connection.cursor() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS forgot_password_tokens (
                id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                phone        VARCHAR(15)  NOT NULL,
                token        VARCHAR(64)  NOT NULL,
                is_used      TINYINT(1)   NOT NULL DEFAULT 0,
                expires_at   DATETIME     NOT NULL,
                created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_token (token),
                INDEX idx_phone (phone)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)


def get_session_user(request):
    """
    Read Bearer token → return (user_id, store_id) or (None, None).
    Also returns first_name, phone for convenience.
    Returns: (user_id, store_id, first_name, last_name, phone, email) or Nones.
    """
    ensure_session_tokens_table()
    token = get_bearer_token(request)
    if not token:
        return None, None, None, None, None, None
    now   = timezone.now()

    with connection.cursor() as c:
        c.execute("""
            SELECT st.user_id, s.store_id,
                   u.first_name, u.last_name,
                   uc.phone_number, uc.email
            FROM session_tokens st
            JOIN users u        ON u.user_id   = st.user_id
            JOIN user_credentials uc ON uc.user_id = st.user_id
            JOIN stores s       ON s.user_id   = st.user_id AND s.is_active = 1
            WHERE st.token=%s AND st.is_active=1 AND st.expires_at > %s
            LIMIT 1
        """, [token, now])
        row = c.fetchone()

    if not row:
        return None, None, None, None, None, None
    return row  # (user_id, store_id, first_name, last_name, phone, email)


def get_store_id(request):
    """Shortcut: just return store_id from Bearer token."""
    row = get_session_user(request)
    return row[1]  # store_id


# ─────────────────────────────────────────────────────────────
#  REGISTRATION
# ─────────────────────────────────────────────────────────────

def register_check(request):
    """Step 1: validate fields + check duplicates against new schema."""
    if request.method != 'POST':
        return fail('Method not allowed', 405)
    try:
        d = body(request)
        phone      = str(d.get('phone', '')).strip()
        email      = str(d.get('email', '')).strip().lower()
        password   = str(d.get('password', '')).strip()
        first_name = str(d.get('first_name', '')).strip()
        last_name  = str(d.get('last_name', '')).strip()
        shop_name  = str(d.get('shop_name', '')).strip()
        location   = str(d.get('location', '')).strip()
        pincode    = str(d.get('pincode', '')).strip()

        if not first_name:                           return fail('First name is required.')
        if not last_name:                            return fail('Last name is required.')
        if not shop_name:                            return fail('Shop name is required.')
        if not email:                                return fail('Email is required.')
        if len(phone) != 10 or not phone.isdigit(): return fail('Enter a valid 10-digit mobile number.')
        if not location:                             return fail('Location is required.')
        if len(pincode) < 6:                         return fail('Enter a valid 6-digit pincode.')
        is_strong, msg = validate_password_strength(password)
        if not is_strong: return fail(msg)

        # Duplicates are now in user_credentials
        with connection.cursor() as c:
            c.execute("SELECT COUNT(*) FROM user_credentials WHERE phone_number=%s", [phone])
            if c.fetchone()[0] > 0:
                return fail('This mobile number is already registered. Please log in.')
            c.execute("SELECT COUNT(*) FROM user_credentials WHERE email=%s", [email])
            if c.fetchone()[0] > 0:
                return fail('This email is already registered.')

        return ok({'message': 'Validation passed.'})
    except Exception as e:
        traceback.print_exc()
        return fail(f'Server error: {str(e)}', 500)


def otp_send(request):
    """Step 2: send phone or email OTP (registration or login)."""
    if request.method != 'POST':
        return fail('Method not allowed', 405)
    try:
        ensure_pending_table()
        d        = body(request)
        phone    = str(d.get('phone', '')).strip()
        email    = str(d.get('email', '')).strip().lower()
        otp_type = str(d.get('otp_type', '')).strip()   # 'phone' | 'email'
        purpose  = str(d.get('purpose', '')).strip()     # 'registration' | 'login'
        ip       = get_ip(request)

        # ── Rate Limiting ──
        ensure_otp_send_log()
        with connection.cursor() as c:
            # Per Phone: Max 3 per 10 mins
            c.execute("""
                SELECT COUNT(*) FROM otp_send_log
                WHERE phone=%s AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)
            """, [phone])
            if c.fetchone()[0] >= 3:
                return fail('Too many OTP requests. Please wait 10 minutes.', 429)
            
            # Per IP: Max 10 per 10 mins (prevent bot flooding)
            c.execute("""
                SELECT COUNT(*) FROM otp_send_log
                WHERE ip_address=%s AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)
            """, [ip])
            if c.fetchone()[0] >= 10:
                return fail('Too many requests from this device. Please wait 10 minutes.', 429)
        # ──────────────────

        otp    = make_otp()
        hashed = otp_hash(otp)
        expiry = timezone.now() + timedelta(minutes=15)

        if purpose in ('registration', 'login'):
            if len(phone) != 10 or not phone.isdigit():
                return fail('Invalid mobile number.')

        if purpose == 'registration':
            # Store OTP in pending_registrations
            if otp_type == 'phone':
                with connection.cursor() as c:
                    c.execute("""
                        INSERT INTO pending_registrations
                            (phone, email, phone_otp_hash, phone_otp_expires, expires_at)
                        VALUES (%s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                            email=%s, phone_otp_hash=%s,
                            phone_otp_expires=%s, expires_at=%s
                    """, [phone, email, hashed, expiry, expiry,
                          email, hashed, expiry, expiry])
                send_phone_otp(phone, otp)

            elif otp_type == 'email':
                with connection.cursor() as c:
                    c.execute("""
                        INSERT INTO pending_registrations
                            (phone, email, email_otp_hash, email_otp_expires, expires_at)
                        VALUES (%s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                            email=%s, email_otp_hash=%s,
                            email_otp_expires=%s, expires_at=%s
                    """, [phone, email, hashed, expiry, expiry,
                          email, hashed, expiry, expiry])
                send_email_otp(email, otp)

            _log_otp_send(phone, ip)
            return ok({'message': 'OTP sent. It will expire in 15 minutes.'})

        elif purpose == 'login':
            # Look up user via user_credentials (v2 schema)
            with connection.cursor() as c:
                c.execute("""
                    SELECT u.user_id FROM user_credentials uc
                    JOIN users u ON u.user_id = uc.user_id
                    WHERE uc.phone_number=%s AND u.is_active=1
                """, [phone])
                row = c.fetchone()
            if not row:
                return fail('No account found with this mobile number.', 404)
            user_id = row[0]

            # Invalidate old OTPs and insert new one into user_contact_verification
            with connection.cursor() as c:
                c.execute("""
                    UPDATE user_contact_verification
                    SET is_verified=1
                    WHERE user_id=%s AND type='phone' AND is_verified=0
                """, [user_id])
                c.execute("""
                    INSERT INTO user_contact_verification
                        (user_id, type, otp_hash, expires_at)
                    VALUES (%s, 'phone', %s, %s)
                """, [user_id, hashed, expiry])

            print(f'\n  LOGIN OTP for +91{phone}  =>  {otp}')
            print(f'========================================\n', flush=True)
            send_phone_otp(phone, otp)
            _log_otp_send(phone, ip)
            return ok({'message': 'OTP sent. It will expire in 15 minutes.'})

        elif purpose == 'profile':
            # OTP for profile phone/email change — user must be logged in
            row = get_session_user(request)
            user_id = row[0] if row else None
            if not user_id:
                return fail('Not authenticated.', 401)

            contact_type = otp_type  # 'phone' or 'email'

            # Invalidate old unverified OTPs of same type
            with connection.cursor() as c:
                c.execute("""
                    UPDATE user_contact_verification
                    SET is_verified=1
                    WHERE user_id=%s AND type=%s AND is_verified=0
                """, [user_id, contact_type])
                c.execute("""
                    INSERT INTO user_contact_verification
                        (user_id, type, otp_hash, expires_at)
                    VALUES (%s, %s, %s, %s)
                """, [user_id, contact_type, hashed, expiry])

            if contact_type == 'phone':
                print(f'\n  PROFILE PHONE OTP for +91{phone}  =>  {otp}')
                print(f'==========================================\n', flush=True)
                send_phone_otp(phone, otp)
            else:
                print(f'\n  PROFILE EMAIL OTP for {email}  =>  {otp}')
                print(f'==========================================\n', flush=True)
                send_email_otp(email, otp)

            _log_otp_send(phone, ip)
            return ok({'message': 'OTP sent. It will expire in 15 minutes.'})

        return fail('Invalid purpose.')

    except Exception as e:
        traceback.print_exc()
        return fail(f'Server error: {str(e)}', 500)


def profile_otp_verify(request):
    """Verify OTP for profile phone/email change."""
    if request.method != 'POST':
        return fail('Method not allowed', 405)
    try:
        row = get_session_user(request)
        user_id = row[0] if row else None
        if not user_id:
            return fail('Not authenticated.', 401)

        d            = body(request)
        otp_type     = str(d.get('otp_type', '')).strip()   # 'phone' or 'email'
        otp_input    = str(d.get('otp', '')).strip()

        if not otp_input or not otp_type:
            return fail('otp and otp_type are required.')

        hashed = otp_hash(otp_input)
        now    = timezone.now()

        # ── OTP attempt limiting ──────────────────────────────────
        max_otp_attempts = getattr(_django_settings, 'OTP_MAX_ATTEMPTS', 5)
        ensure_otp_attempt_log()
        with connection.cursor() as c:
            c.execute("""
                SELECT COUNT(*) FROM otp_attempt_log
                WHERE user_id=%s AND otp_type=%s AND success=0
                  AND attempted_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)
            """, [user_id, f'profile_{otp_type}'])
            otp_fails = c.fetchone()[0]
        if otp_fails >= max_otp_attempts:
            with connection.cursor() as c:
                c.execute("""
                    UPDATE user_contact_verification SET is_verified=1
                    WHERE user_id=%s AND type=%s AND is_verified=0
                """, [user_id, otp_type])
            return fail('Too many incorrect OTP attempts. Please request a new OTP.', 429)
        # ─────────────────────────────────────────────────────────

        with connection.cursor() as c:
            c.execute("""
                SELECT verification_id FROM user_contact_verification
                WHERE user_id=%s AND type=%s AND otp_hash=%s
                  AND is_verified=0 AND expires_at > %s
                ORDER BY created_at DESC LIMIT 1
            """, [user_id, otp_type, hashed, now])
            row2 = c.fetchone()

        if not row2:
            _log_otp_attempt(user_id, f'profile_{otp_type}', success=False)
            return fail('Invalid or expired OTP.', 400)

        # Mark as verified
        _log_otp_attempt(user_id, f'profile_{otp_type}', success=True)
        with connection.cursor() as c:
            c.execute("""
                UPDATE user_contact_verification SET is_verified=1
                WHERE verification_id=%s
            """, [row2[0]])

        return ok({'message': 'OTP verified successfully.'})
    except Exception as e:
        traceback.print_exc()
        return fail(f'Server error: {str(e)}', 500)


def otp_verify_register(request):
    """Step 3: verify both OTPs → create user + credentials + store → session."""
    """Step 3: verify both OTPs → create user + credentials + store → session."""
    if request.method != 'POST':
        return fail('Method not allowed', 405)
    try:
        ensure_pending_table()
        ensure_session_tokens_table()
        d          = body(request)
        phone      = str(d.get('phone', '')).strip()
        email      = str(d.get('email', '')).strip().lower()
        phone_otp  = str(d.get('phone_otp', '')).strip()
        email_otp  = str(d.get('email_otp', '')).strip()
        first_name = str(d.get('first_name', '')).strip()
        last_name  = str(d.get('last_name', '')).strip()
        shop_name  = str(d.get('shop_name', '')).strip()
        location   = str(d.get('location', '')).strip()
        pincode    = str(d.get('pincode', '')).strip()
        gst        = str(d.get('gst_number', '')).strip().upper() or None
        fssai      = str(d.get('fssai_number', '')).strip() or None
        password   = str(d.get('password', '')).strip()
        now        = timezone.now()

        with connection.cursor() as c:
            c.execute("""
                SELECT phone_otp_hash, phone_otp_expires,
                       email_otp_hash, email_otp_expires
                FROM pending_registrations
                WHERE phone=%s AND expires_at > %s
            """, [phone, now])
            row = c.fetchone()

        if not row:
            return fail('Session expired. Please start registration again.')

        ph_hash, ph_exp, em_hash, em_exp = row
        ph_exp = to_local(ph_exp)
        em_exp = to_local(em_exp)

        if not ph_hash:                  return fail('Mobile OTP not sent. Click Send first.')
        if now > ph_exp:                 return fail('Mobile OTP expired. Click Send again.')
        if otp_hash(phone_otp) != ph_hash: return fail('Mobile OTP is incorrect.')

        if not em_hash:                  return fail('Email OTP not sent. Click Send first.')
        if now > em_exp:                 return fail('Email OTP expired. Click Send again.')
        if otp_hash(email_otp) != em_hash: return fail('Email OTP is incorrect.')

        pw_hash = make_password(password)
        token   = make_token()
        expires = now + timedelta(days=30)
        ip      = get_ip(request)
        device_info = get_device_info(request)

        with connection.cursor() as c:
            # 1. Create user
            c.execute("""
                INSERT INTO users (first_name, last_name, is_active, created_at, updated_at)
                VALUES (%s, %s, 1, NOW(), NOW())
            """, [first_name, last_name])
            user_id = c.lastrowid

            # 2. Create credentials
            c.execute("""
                INSERT INTO user_credentials
                    (user_id, phone_number, email, password_hash, created_at, updated_at)
                VALUES (%s, %s, %s, %s, NOW(), NOW())
            """, [user_id, phone, email, pw_hash])

            # 3. Create store
            c.execute("""
                INSERT INTO stores
                    (user_id, store_name, location, pincode,
                     gst_number, fssai_number, is_active, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, 1, NOW(), NOW())
            """, [user_id, shop_name, location, pincode, gst, fssai])
            store_id = c.lastrowid

            # 4. Create login_session (status=SUCCESS)
            c.execute("""
                INSERT INTO login_sessions
                    (user_id, login_time, ip_address, device_info, status)
                VALUES (%s, NOW(), %s, %s, 'SUCCESS')
            """, [user_id, ip, device_info])
            session_id = c.lastrowid

            # 5. Create session token (helper table)
            c.execute("""
                INSERT INTO session_tokens
                    (session_id, user_id, token, is_active, expires_at, created_at)
                VALUES (%s, %s, %s, 1, %s, NOW())
            """, [session_id, user_id, token, expires])

            # 6. Audit login
            c.execute("""
                INSERT INTO audit_login
                    (user_id, phone_number, status, ip_address, device_info, created_at)
                VALUES (%s, %s, 'SUCCESS', %s, %s, NOW())
            """, [user_id, phone, ip, device_info])

            # 7. Cleanup pending
            c.execute("DELETE FROM pending_registrations WHERE phone=%s", [phone])

        print(f'\n  Store registered: {shop_name} | {phone}\n', flush=True)

        response = ok({
            'message': 'Registration successful!',
            'session_token': 'PROTECTED',
            'store': {
                'store_id': store_id, 'store_name': shop_name,
                'owner_name': f'{first_name} {last_name}',
                'location': location, 'pincode': pincode,
                'gst_number': gst, 'fssai_number': fssai,
            },
            'user': {
                'user_id': user_id,
                'first_name': first_name, 'last_name': last_name,
                'phone': phone, 'email': email,
            }
        })
        response.set_cookie(
            key='dukaanos_session',
            value=token,
            httponly=True,
            secure=not _django_settings.DEBUG,
            samesite='Lax',
            max_age=30 * 24 * 60 * 60
        )
        return response

    except IntegrityError as e:
        traceback.print_exc()
        msg = str(e).lower()
        if 'phone' in msg: return fail('Mobile number already registered.')
        if 'email' in msg: return fail('Email already registered.')
        return fail(f'Database error: {str(e)}', 500)
    except Exception as e:
        traceback.print_exc()
        return fail(f'Server error: {str(e)}', 500)


# ─────────────────────────────────────────────────────────────
#  LOGIN
# ─────────────────────────────────────────────────────────────

def login_check(request):
    """Step 1: verify phone + password against user_credentials."""
    if request.method != 'POST':
        return fail('Method not allowed', 405)
    try:
        d        = body(request)
        phone    = str(d.get('phone', '')).strip()
        password = str(d.get('password', '')).strip()
        ip       = get_ip(request)

        if len(phone) != 10 or not phone.isdigit():
            return fail('Enter a valid 10-digit mobile number.')
        if not password:
            return fail('Password is required.')

        # ── Brute-force guard ─────────────────────────────────────
        blocked, block_msg = _check_login_blocked(phone, ip)
        if blocked:
            return fail(block_msg, 429)
        # ─────────────────────────────────────────────────────────

        with connection.cursor() as c:
            c.execute("""
                SELECT uc.password_hash
                FROM user_credentials uc
                JOIN users u ON u.user_id = uc.user_id
                WHERE uc.phone_number=%s AND u.is_active=1
            """, [phone])
            row = c.fetchone()

        if not row:
            _log_attempt(phone, ip, success=False)
            return fail('No account found with this mobile number.', 401)

        if not check_password(password, row[0]):
            _log_attempt(phone, ip, success=False)
            return fail('Incorrect password.', 401)

        _log_attempt(phone, ip, success=True)
        return ok({'message': 'Credentials verified.', 'phone': phone})

    except Exception as e:
        traceback.print_exc()
        return fail(f'Server error: {str(e)}', 500)


def otp_verify_login(request):
    """Step 2: verify OTP → create session → return token + store info."""
    if request.method != 'POST':
        return fail('Method not allowed', 405)
    try:
        ensure_session_tokens_table()
        d         = body(request)
        phone     = str(d.get('phone', '')).strip()
        phone_otp = str(d.get('phone_otp', '')).strip()
        now       = timezone.now()
        ip        = get_ip(request)
        device_info = get_device_info(request)

        # Fetch user + store via user_credentials
        with connection.cursor() as c:
            c.execute("""
                SELECT u.user_id, u.first_name, u.last_name,
                       uc.email,
                       s.store_id, s.store_name, s.location,
                       s.pincode, s.gst_number, s.fssai_number
                FROM user_credentials uc
                JOIN users u  ON u.user_id  = uc.user_id
                JOIN stores s ON s.user_id  = u.user_id AND s.is_active = 1
                WHERE uc.phone_number=%s AND u.is_active=1
                LIMIT 1
            """, [phone])
            row = c.fetchone()

        if not row:
            return fail('Account not found.', 404)

        user_id, first, last, email, store_id, store_name, \
            location, pincode, gst, fssai = row

        # ── OTP attempt limiting ──────────────────────────────────
        max_otp_attempts = getattr(_django_settings, 'OTP_MAX_ATTEMPTS', 5)
        ensure_otp_attempt_log()
        with connection.cursor() as c:
            c.execute("""
                SELECT COUNT(*) FROM otp_attempt_log
                WHERE user_id=%s AND otp_type='login_phone' AND success=0
                  AND attempted_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)
            """, [user_id])
            otp_fails = c.fetchone()[0]
        if otp_fails >= max_otp_attempts:
            # Invalidate any outstanding OTP so attacker can't keep trying
            with connection.cursor() as c:
                c.execute("""
                    UPDATE user_contact_verification SET is_verified=1
                    WHERE user_id=%s AND type='phone' AND is_verified=0
                """, [user_id])
            return fail('Too many incorrect OTP attempts. Please request a new OTP.', 429)
        # ─────────────────────────────────────────────────────────

        # Verify OTP from user_contact_verification
        with connection.cursor() as c:
            c.execute("""
                SELECT verification_id FROM user_contact_verification
                WHERE user_id=%s AND type='phone' AND is_verified=0
                  AND otp_hash=%s AND expires_at > %s
                ORDER BY verification_id DESC LIMIT 1
            """, [user_id, otp_hash(phone_otp), now])
            otp_row = c.fetchone()

        if not otp_row:
            _log_otp_attempt(user_id, 'login_phone', success=False)
            return fail('OTP is incorrect or has expired.')

        token   = make_token()
        expires = now + timedelta(days=30)

        _log_otp_attempt(user_id, 'login_phone', success=True)

        with connection.cursor() as c:
            # Mark OTP as verified
            c.execute("""
                UPDATE user_contact_verification
                SET is_verified=1 WHERE verification_id=%s
            """, [otp_row[0]])

            # Create login_session
            c.execute("""
                INSERT INTO login_sessions
                    (user_id, login_time, ip_address, device_info, status)
                VALUES (%s, NOW(), %s, %s, 'SUCCESS')
            """, [user_id, ip, device_info])
            session_id = c.lastrowid

            # Create session token
            c.execute("""
                INSERT INTO session_tokens
                    (session_id, user_id, token, is_active, expires_at, created_at)
                VALUES (%s, %s, %s, 1, %s, NOW())
            """, [session_id, user_id, token, expires])

            # Audit
            c.execute("""
                INSERT INTO audit_login
                    (user_id, phone_number, status, ip_address, device_info, created_at)
                VALUES (%s, %s, 'SUCCESS', %s, %s, NOW())
            """, [user_id, phone, ip, device_info])

        print(f'\n  Login: {phone} | {store_name}\n', flush=True)

        response = ok({
            'message': 'Logged in successfully.',
            'session_token': 'PROTECTED',
            'store': {
                'store_id': store_id, 'store_name': store_name,
                'owner_name': f'{first} {last}',
                'phone': phone, 'email': email,
                'location': location, 'pincode': pincode,
                'gst_number': gst, 'fssai_number': fssai,
            },
            'user': {
                'user_id': user_id,
                'first_name': first, 'last_name': last,
                'phone': phone, 'email': email,
            }
        })
        response.set_cookie(
            key='dukaanos_session',
            value=token,
            httponly=True,
            secure=not _django_settings.DEBUG,
            samesite='Lax',
            max_age=30 * 24 * 60 * 60
        )
        return response

    except Exception as e:
        traceback.print_exc()
        return fail(f'Server error: {str(e)}', 500)


def logout(request):
    if request.method != 'POST':
        return fail('Method not allowed', 405)
    try:
        ensure_session_tokens_table()
        token = get_bearer_token(request)
        if token:
            with connection.cursor() as c:
                # Deactivate token
                c.execute("""
                    UPDATE session_tokens SET is_active=0 WHERE token=%s
                """, [token])
                # Record logout in login_sessions
                c.execute("""
                    UPDATE login_sessions ls
                    JOIN session_tokens st ON st.session_id = ls.session_id
                    SET ls.logout_time = NOW()
                    WHERE st.token=%s
                """, [token])
        response = ok({'message': 'Logged out.'})
        response.delete_cookie('dukaanos_session')
        return response
    except Exception as e:
        traceback.print_exc()
        return fail(f'Server error: {str(e)}', 500)


def sessions_list(request):
    if request.method != 'GET':
        return fail('Method not allowed', 405)
    try:
        row = get_session_user(request)
        user_id = row[0] if row else None
        if not user_id:
            return fail('Not authenticated.', 401)

        current_token = get_bearer_token(request)
        now = timezone.now()

        with connection.cursor() as c:
            c.execute("""
                SELECT st.session_id, st.token, st.created_at, st.expires_at,
                       ls.login_time, ls.ip_address, ls.device_info
                FROM session_tokens st
                LEFT JOIN login_sessions ls ON ls.session_id = st.session_id
                WHERE st.user_id=%s
                  AND st.is_active=1
                  AND st.expires_at > %s
                ORDER BY COALESCE(ls.login_time, st.created_at) DESC
            """, [user_id, now])
            rows = c.fetchall()

        return ok({
            'sessions': [
                {
                    'session_id': r[0],
                    'created_at': r[2],
                    'expires_at': r[3],
                    'login_time': r[4],
                    'ip_address': r[5] or '',
                    'device_info': r[6] or 'Web Browser',
                    'current': bool(current_token and r[1] == current_token),
                }
                for r in rows
            ],
            'active_count': len(rows),
        })
    except Exception as e:
        traceback.print_exc()
        return fail(f'Server error: {str(e)}', 500)


def logout_all_devices(request):
    if request.method != 'POST':
        return fail('Method not allowed', 405)
    try:
        row = get_session_user(request)
        user_id = row[0] if row else None
        if not user_id:
            return fail('Not authenticated.', 401)

        with connection.cursor() as c:
            c.execute("""
                UPDATE session_tokens
                SET is_active=0
                WHERE user_id=%s AND is_active=1
            """, [user_id])
            revoked_sessions = c.rowcount

            c.execute("""
                UPDATE login_sessions ls
                JOIN session_tokens st ON st.session_id = ls.session_id
                SET ls.logout_time = NOW()
                WHERE st.user_id=%s
                  AND st.is_active=0
                  AND ls.logout_time IS NULL
            """, [user_id])

        return ok({
            'message': 'Logged out from all devices.',
            'revoked_sessions': revoked_sessions,
        })
    except Exception as e:
        traceback.print_exc()
        return fail(f'Server error: {str(e)}', 500)


def me(request):
    if request.method == 'GET':
        try:
            row = get_session_user(request)
            user_id, store_id, first, last, phone, email = row
            if not user_id:
                return fail('Not authenticated.', 401)

            with connection.cursor() as c:
                c.execute("""
                    SELECT store_name, location, pincode, gst_number, fssai_number
                    FROM stores WHERE store_id=%s
                """, [store_id])
                s = c.fetchone()

            if not s:
                return fail('Store not found.', 404)

            return ok({
                'store': {
                    'store_id': store_id, 'store_name': s[0],
                    'owner_name': f'{first} {last}',
                    'phone': phone, 'email': email,
                    'location': s[1], 'pincode': s[2],
                    'gst_number': s[3], 'fssai_number': s[4],
                },
                'user': {
                    'user_id': user_id,
                    'first_name': first, 'last_name': last,
                    'phone': phone, 'email': email,
                },
            })
        except Exception as e:
            traceback.print_exc()
            return fail(f'Server error: {str(e)}', 500)

    if request.method == 'PUT':
        try:
            row = get_session_user(request)
            user_id, store_id, first, last, phone, email = row
            if not user_id:
                return fail('Not authenticated.', 401)

            d          = body(request)
            first_name = str(d.get('first_name', '') or '').strip() or None
            last_name  = str(d.get('last_name',  '') or '').strip() or None
            store_name = str(d.get('store_name', '') or '').strip() or None
            location   = str(d.get('location',   '') or '').strip() or None
            pincode    = str(d.get('pincode',     '') or '').strip() or None
            gst_number = str(d.get('gst_number',  '') or '').strip() or None
            fssai      = str(d.get('fssai_number','') or '').strip() or None
            new_phone  = str(d.get('phone',       '') or '').strip() or None
            new_email  = str(d.get('email',       '') or '').strip().lower() or None

            # ── Fetch current values for audit diff ──────────────────
            with connection.cursor() as c:
                c.execute("""
                    SELECT u.first_name, u.last_name,
                           uc.phone_number, uc.email,
                           s.store_name, s.location, s.pincode,
                           s.gst_number, s.fssai_number
                    FROM users u
                    JOIN user_credentials uc ON uc.user_id = u.user_id
                    JOIN stores s ON s.store_id = %s
                    WHERE u.user_id = %s
                """, [store_id, user_id])
                cur = c.fetchone()
            cur_first, cur_last, cur_phone, cur_email,             cur_store, cur_loc, cur_pin, cur_gst, cur_fssai = cur

            # ── Update users table ───────────────────────────────────
            if first_name or last_name:
                with connection.cursor() as c:
                    c.execute("""
                        UPDATE users SET
                            first_name = COALESCE(%s, first_name),
                            last_name  = COALESCE(%s, last_name),
                            updated_at = NOW()
                        WHERE user_id = %s
                    """, [first_name, last_name, user_id])

            # ── Update stores table ──────────────────────────────────
            with connection.cursor() as c:
                c.execute("""
                    UPDATE stores SET
                        store_name   = COALESCE(%s, store_name),
                        location     = COALESCE(%s, location),
                        pincode      = COALESCE(%s, pincode),
                        gst_number   = COALESCE(%s, gst_number),
                        fssai_number = COALESCE(%s, fssai_number),
                        updated_at   = NOW()
                    WHERE store_id = %s
                """, [store_name, location, pincode, gst_number, fssai, store_id])

            # ── Check OTP verification for sensitive contact changes ─────
            phone_changed = new_phone and new_phone != str(cur_phone or '')
            email_changed = new_email and new_email != str(cur_email or '')

            if phone_changed:
                with connection.cursor() as c:
                    c.execute("""
                        SELECT id FROM user_contact_verification
                        WHERE user_id=%s AND type='phone' AND is_verified=1
                          AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)
                        LIMIT 1
                    """, [user_id])
                    if not c.fetchone():
                        return fail('OTP verification required to change mobile number.', 403)

            if email_changed:
                with connection.cursor() as c:
                    c.execute("""
                        SELECT id FROM user_contact_verification
                        WHERE user_id=%s AND type='email' AND is_verified=1
                          AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)
                        LIMIT 1
                    """, [user_id])
                    if not c.fetchone():
                        return fail('OTP verification required to change email address.', 403)

            # ── Update user_credentials (phone/email) ────────────────
            if new_phone or new_email:
                with connection.cursor() as c:
                    c.execute("""
                        UPDATE user_credentials SET
                            phone_number = COALESCE(%s, phone_number),
                            email        = COALESCE(%s, email),
                            updated_at   = NOW()
                        WHERE user_id = %s
                    """, [new_phone, new_email, user_id])

            # ── audit_profile_changes — one row per changed field ────
            profile_fields = [
                ('first_name',   cur_first,  first_name),
                ('last_name',    cur_last,   last_name),
                ('store_name',   cur_store,  store_name),
                ('location',     cur_loc,    location),
                ('pincode',      cur_pin,    pincode),
                ('gst_number',   cur_gst,    gst_number),
                ('fssai_number', cur_fssai,  fssai),
            ]
            audit_rows = [
                (user_id, field, str(old_val or ''), str(new_val or ''))
                for field, old_val, new_val in profile_fields
                if new_val is not None and str(new_val) != str(old_val or '')
            ]
            if audit_rows:
                with connection.cursor() as c:
                    c.executemany("""
                        INSERT INTO audit_profile_changes
                            (user_id, field_changed, old_value, new_value, changed_at)
                        VALUES (%s, %s, %s, %s, NOW())
                    """, audit_rows)

            # ── audit_contact_changes — when phone or email changes ──
            phone_changed = new_phone and new_phone != str(cur_phone or '')
            email_changed = new_email and new_email != str(cur_email or '')
            if phone_changed or email_changed:
                with connection.cursor() as c:
                    c.execute("""
                        INSERT INTO audit_contact_changes
                            (user_id, old_phone, new_phone,
                             old_email, new_email, verified, changed_at)
                        VALUES (%s, %s, %s, %s, %s, %s, NOW())
                    """, [
                        user_id,
                        cur_phone if phone_changed else None,
                        new_phone if phone_changed else None,
                        cur_email if email_changed else None,
                        new_email if email_changed else None,
                        True,  # OTP was verified before reaching this point
                    ])

            print(f'\n  [PROFILE UPDATE] user_id={user_id} store_id={store_id}')
            print(f'  Changed fields: {[r[1] for r in audit_rows]}')
            print(f'==========================================\n', flush=True)

            return ok({'message': 'Profile updated successfully.'})
        except Exception as e:
            traceback.print_exc()
            return fail(f'Server error: {str(e)}', 500)

    return fail('Method not allowed', 405)


# ─────────────────────────────────────────────────────────────
#  CHANGE PASSWORD
# ─────────────────────────────────────────────────────────────

def change_password(request):
    if request.method != 'POST':
        return fail('Method not allowed', 405)
    try:
        row = get_session_user(request)
        user_id, store_id, first, last, phone, email = row
        if not user_id:
            return fail('Not authenticated.', 401)

        d = body(request)
        current_password = str(d.get('current_password', '')).strip()
        new_password     = str(d.get('new_password', '')).strip()
        otp_input        = str(d.get('otp', '')).strip()

        if not current_password or not new_password or not otp_input:
            return fail('Current password, new password, and OTP are required.')
        is_strong, msg = validate_password_strength(new_password)
        if not is_strong: return fail(msg)
        if current_password == new_password:
            return fail('New password must be different from the current password.')

        with connection.cursor() as c:
            c.execute(
                "SELECT password_hash FROM user_credentials WHERE user_id=%s",
                [user_id]
            )
            r = c.fetchone()

        if not r or not check_password(current_password, r[0]):
            return fail('Current password is incorrect.', 401)

        # Enforce server-side OTP verification.
        now = timezone.now()
        hashed_otp = otp_hash(otp_input)

        max_otp_attempts = getattr(_django_settings, 'OTP_MAX_ATTEMPTS', 5)
        ensure_otp_attempt_log()
        with connection.cursor() as c:
            c.execute("""
                SELECT COUNT(*) FROM otp_attempt_log
                WHERE user_id=%s AND otp_type='change_password_phone' AND success=0
                  AND attempted_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)
            """, [user_id])
            otp_fails = c.fetchone()[0]
        if otp_fails >= max_otp_attempts:
            with connection.cursor() as c:
                c.execute("""
                    UPDATE user_contact_verification
                    SET is_verified=1
                    WHERE user_id=%s AND type='phone' AND is_verified=0
                """, [user_id])
            return fail('Too many incorrect OTP attempts. Please request a new OTP.', 429)

        with connection.cursor() as c:
            c.execute("""
                SELECT verification_id
                FROM user_contact_verification
                WHERE user_id=%s AND type='phone'
                  AND otp_hash=%s AND is_verified=0 AND expires_at > %s
                ORDER BY created_at DESC
                LIMIT 1
            """, [user_id, hashed_otp, now])
            otp_row = c.fetchone()

        if not otp_row:
            _log_otp_attempt(user_id, 'change_password_phone', success=False)
            return fail('Invalid or expired OTP.', 400)

        _log_otp_attempt(user_id, 'change_password_phone', success=True)

        new_hash = make_password(new_password)
        # Identify the current session token so we can keep it alive
        current_token = get_bearer_token(request)

        with connection.cursor() as c:
            c.execute("""
                UPDATE user_contact_verification
                SET is_verified=1
                WHERE verification_id=%s
            """, [otp_row[0]])

            c.execute(
                "UPDATE user_credentials SET password_hash=%s, updated_at=NOW() WHERE user_id=%s",
                [new_hash, user_id]
            )
            # ── Invalidate all OTHER active sessions for this user ──
            # This kicks any attacker (or old device) that was already logged in.
            c.execute("""
                UPDATE session_tokens
                SET is_active=0
                WHERE user_id=%s AND token != %s AND is_active=1
            """, [user_id, current_token])
            # Record logout timestamp for the invalidated sessions
            c.execute("""
                UPDATE login_sessions ls
                JOIN session_tokens st ON st.session_id = ls.session_id
                SET ls.logout_time = NOW()
                WHERE st.user_id=%s AND st.token != %s
                  AND st.is_active=0 AND ls.logout_time IS NULL
            """, [user_id, current_token])

        print(f'\n  [PASSWORD CHANGE] user_id={user_id} — password updated, other sessions revoked\n', flush=True)
        return ok({'success': True, 'message': 'Password changed successfully. Other devices have been logged out.'})

    except Exception as e:
        traceback.print_exc()
        return fail(f'Server error: {str(e)}', 500)


# ─────────────────────────────────────────────────────────────

import csv
import io

def bulk_upload(request):
    """
    POST: upload a CSV file to bulk-add categories and items.
    Format: category_name, category_description, item_name, brand, gst_percentage
    """
    if request.method != 'POST':
        return fail('Method not allowed', 405)

    store_id = get_store_id(request)
    if not store_id:
        return fail('Not authenticated.', 401)

    if 'file' not in request.FILES:
        return fail('No file uploaded.')

    csv_file = request.FILES['file']
    if not csv_file.name.endswith('.csv'):
        return fail('Please upload a valid CSV file.')

    try:
        decoded_file = csv_file.read().decode('utf-8')
        io_string = io.StringIO(decoded_file)
        reader = csv.DictReader(io_string)

        added_categories = 0
        added_items = 0
        
        # Cache existing categories to avoid redundant DB calls
        with connection.cursor() as c:
            c.execute("SELECT category_id, name FROM categories WHERE store_id=%s", [store_id])
            cat_map = {row[1].lower(): row[0] for row in c.fetchall()}

        with connection.cursor() as c:
            for row in reader:
                cat_name = str(row.get('category_name', '')).strip()
                cat_desc = str(row.get('category_description', '')).strip()
                item_name = str(row.get('item_name', '')).strip()
                brand = str(row.get('brand', '')).strip()
                gst = float(row.get('gst_percentage', 0) or 0)

                if not cat_name or not item_name:
                    continue

                # 1. Handle Category
                cat_key = cat_name.lower()
                if cat_key not in cat_map:
                    c.execute("INSERT INTO categories (name, description, store_id) VALUES (%s,%s,%s)", 
                              [cat_name, cat_desc, store_id])
                    cat_id = c.lastrowid
                    cat_map[cat_key] = cat_id
                    added_categories += 1
                else:
                    cat_id = cat_map[cat_key]

                # 2. Check for Item Duplicate in this Category
                c.execute("SELECT item_id FROM items WHERE item_name=%s AND category_id=%s AND store_id=%s", 
                          [item_name, cat_id, store_id])
                if c.fetchone():
                    continue

                # 3. Add Item
                c.execute("""
                    INSERT INTO items (store_id, category_id, item_name, brand, gst_percentage, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
                """, [store_id, cat_id, item_name, brand, gst])
                item_id = c.lastrowid
                
                # 4. Initialize Stock row
                c.execute("""
                    INSERT INTO stock (category_id, item_id, current_quantity, wholesale_price, selling_price, created_at, updated_at)
                    VALUES (%s, %s, 0, 0, 0, NOW(), NOW())
                """, [cat_id, item_id])
                added_items += 1

        return ok({
            'message': f'Successfully imported {added_items} items across {added_categories} new categories!',
            'added_categories': added_categories,
            'added_items': added_items
        })

    except Exception as e:
        traceback.print_exc()
        return fail(f'CSV Process Error: {str(e)}', 500)

def categories(request):
    store_id = get_store_id(request)
    if not store_id:
        return fail('Not authenticated.', 401)

    if request.method == 'GET':
        with connection.cursor() as c:
            c.execute("""
                SELECT cat.category_id, cat.name, cat.description,
                       COUNT(i.item_id) AS item_count
                FROM categories cat
                LEFT JOIN items i ON i.category_id = cat.category_id
                WHERE cat.store_id=%s
                GROUP BY cat.category_id
                ORDER BY cat.name
            """, [store_id])
            rows = c.fetchall()
        return ok({'categories': [
            {'id': r[0], 'name': r[1], 'desc': r[2] or '', 'item_count': r[3]}
            for r in rows
        ]})

    if request.method == 'POST':
        d    = body(request)
        name = str(d.get('name', '')).strip()
        desc = str(d.get('desc', '')).strip() or None
        if not name:
            return fail('Category name is required.')
        try:
            with connection.cursor() as c:
                c.execute("""
                    INSERT INTO categories (store_id, name, description, created_at, updated_at)
                    VALUES (%s, %s, %s, NOW(), NOW())
                """, [store_id, name, desc])
                cat_id = c.lastrowid
        except Exception as e:
            if 'Duplicate' in str(e):
                return fail('Category already exists.')
            raise
        return ok({'id': cat_id, 'name': name, 'desc': desc or ''})

    return fail('Method not allowed.', 405)


def category_delete(request, cat_id):
    store_id = get_store_id(request)
    if not store_id:
        return fail('Not authenticated.', 401)
    if request.method != 'DELETE':
        return fail('Method not allowed.', 405)
    with connection.cursor() as c:
        c.execute("""
            DELETE FROM categories WHERE category_id=%s AND store_id=%s
        """, [cat_id, store_id])
    return ok({'message': 'Deleted.'})


# ─────────────────────────────────────────────────────────────
#  ITEMS — list, create, update, delete
#  v2: items table has item_name, brand, gst_percentage.
#      Pricing/qty lives in the stock table.
# ─────────────────────────────────────────────────────────────

def items_list(request):
    store_id = get_store_id(request)
    if not store_id:
        return fail('Not authenticated.', 401)

    if request.method == 'GET':
        with connection.cursor() as c:
            c.execute("""
                SELECT i.item_id, i.item_name, i.brand, i.gst_percentage,
                       i.category_id, cat.name AS category_name,
                       st.stock_id, st.current_quantity,
                       st.wholesale_price, st.selling_price
                FROM items i
                LEFT JOIN categories cat ON cat.category_id = i.category_id
                LEFT JOIN stock st       ON st.item_id      = i.item_id
                WHERE i.store_id=%s
                ORDER BY cat.name, i.item_name
            """, [store_id])
            rows = c.fetchall()
        return ok({'items': [
            {
                'id':          r[0],
                'item_name':   r[1],
                'brand':       r[2] or '',
                'gst':         float(r[3]),
                'category_id': r[4],
                'category':    r[5] or 'Uncategorized',
                'stock_id':    r[6],
                'quantity':    float(r[7]) if r[7] is not None else 0,
                'wholesale':   float(r[8]) if r[8] is not None else 0,
                'price':       float(r[9]) if r[9] is not None else 0,
            }
            for r in rows
        ]})

    if request.method == 'POST':
        d          = body(request)
        item_name  = str(d.get('item_name', '')).strip()
        brand      = str(d.get('brand', '')).strip()
        gst        = float(d.get('gst', 0))
        cat_id     = d.get('category_id')
        wholesale  = float(d.get('wholesale', 0))
        price      = float(d.get('price', 0))
        quantity   = float(d.get('quantity', 0))

        if not item_name: return fail('Item name is required.')
        if not brand:     return fail('Brand is required.')
        if not cat_id:    return fail('Category is required.')

        with connection.cursor() as c:
            # Insert into items
            c.execute("""
                INSERT INTO items
                    (store_id, category_id, item_name, brand, gst_percentage, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
            """, [store_id, cat_id, item_name, brand, gst])
            item_id = c.lastrowid

            # Insert into stock (one row per item)
            c.execute("""
                INSERT INTO stock
                    (category_id, item_id, current_quantity,
                     wholesale_price, selling_price, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
            """, [cat_id, item_id, quantity, wholesale, price])
            stock_id = c.lastrowid

            # If initial quantity > 0, log a stock entry
            if quantity > 0:
                c.execute("""
                    INSERT INTO stock_entries
                        (stock_id, quantity_added, purchase_price, selling_price, created_at)
                    VALUES (%s, %s, %s, %s, NOW())
                """, [stock_id, quantity, wholesale, price])

        return ok({'id': item_id, 'stock_id': stock_id, 'message': 'Item added.'})

    return fail('Method not allowed.', 405)


def item_detail(request, item_id):
    store_id = get_store_id(request)
    if not store_id:
        return fail('Not authenticated.', 401)

    if request.method == 'PUT':
        d = body(request)

        # Update items table fields
        item_fields, item_vals = [], []
        for key in ['item_name', 'brand', 'gst_percentage', 'category_id']:
            if key in d:
                item_fields.append(f'{key}=%s')
                item_vals.append(d[key])

        # Update stock table fields
        stock_fields, stock_vals = [], []
        for key in ['wholesale_price', 'selling_price', 'current_quantity']:
            if key in d:
                stock_fields.append(f'{key}=%s')
                stock_vals.append(d[key])

        if not item_fields and not stock_fields:
            return fail('Nothing to update.')

        with connection.cursor() as c:
            if item_fields:
                item_vals += [item_id, store_id]
                c.execute(
                    f"UPDATE items SET {','.join(item_fields)}, updated_at=NOW() "
                    f"WHERE item_id=%s AND store_id=%s",
                    item_vals
                )
            if stock_fields:
                stock_vals += [item_id]
                c.execute(
                    f"UPDATE stock SET {','.join(stock_fields)}, updated_at=NOW() "
                    f"WHERE item_id=%s",
                    stock_vals
                )

        return ok({'message': 'Updated.'})

    if request.method == 'DELETE':
        with connection.cursor() as c:
            # bill_items has a bare FK (no CASCADE) so we must remove those
            # rows first; the bill itself keeps all financial data intact.
            c.execute("""
                DELETE bi FROM bill_items bi
                JOIN bills b ON b.bill_id = bi.bill_id
                WHERE bi.item_id=%s AND b.store_id=%s
            """, [item_id, store_id])
            # stock and stock_entries cascade automatically
            c.execute("""
                DELETE FROM items WHERE item_id=%s AND store_id=%s
            """, [item_id, store_id])
        return ok({'message': 'Deleted.'})

    return fail('Method not allowed.', 405)


# ─────────────────────────────────────────────────────────────
#  STOCK ENTRIES — add stock (godown / Add Stock page)
# ─────────────────────────────────────────────────────────────

def add_stock(request, item_id):
    """
    POST: add stock for an item.
    Updates stock.current_quantity (weighted avg prices) and logs in stock_entries.
    """
    store_id = get_store_id(request)
    if not store_id:
        return fail('Not authenticated.', 401)
    if request.method != 'POST':
        return fail('Method not allowed.', 405)

    d              = body(request)
    qty_added      = float(d.get('quantity', 0))
    purchase_price = float(d.get('wholesale_price', 0))
    selling_price  = float(d.get('selling_price', 0))
    supplier       = str(d.get('supplier', '')).strip() or None
    notes          = str(d.get('notes', '')).strip() or None

    if qty_added <= 0:
        return fail('Quantity must be greater than 0.')

    with connection.cursor() as c:
        # Get current stock row
        c.execute("""
            SELECT st.stock_id, st.current_quantity,
                   st.wholesale_price, st.selling_price
            FROM stock st
            JOIN items i ON i.item_id = st.item_id
            WHERE st.item_id=%s AND i.store_id=%s
        """, [item_id, store_id])
        row = c.fetchone()

    # ── AUTO-CREATE STOCK ROW IF MISSING ──────────────────────────
    # Items created via the Categories page may not have a stock row
    # if the initial insert failed. Create it now so the user can
    # always add stock without hitting an error.
    if not row:
        with connection.cursor() as c:
            c.execute("""
                SELECT category_id FROM items
                WHERE item_id=%s AND store_id=%s
            """, [item_id, store_id])
            item_row = c.fetchone()

        if not item_row:
            return fail('Item not found.', 404)

        with connection.cursor() as c:
            c.execute("""
                INSERT INTO stock
                    (category_id, item_id, current_quantity,
                     wholesale_price, selling_price,
                     created_at, updated_at)
                VALUES (%s, %s, 0, 0, 0, NOW(), NOW())
            """, [item_row[0], item_id])
            new_stock_id = c.lastrowid

        row = (new_stock_id, 0.0, 0.0, 0.0)

    stock_id, cur_qty, cur_wholesale, _ = row
    cur_qty       = float(cur_qty)
    cur_wholesale = float(cur_wholesale)

    # Wholesale: weighted average. Selling price: always use the latest value entered.
    total_qty     = cur_qty + qty_added
    new_wholesale = round(((cur_wholesale * cur_qty) + (purchase_price * qty_added)) / total_qty, 2)
    new_selling   = round(selling_price, 2)

    with connection.cursor() as c:
        c.execute("""
            UPDATE stock
            SET current_quantity=%s, wholesale_price=%s,
                selling_price=%s, updated_at=NOW()
            WHERE stock_id=%s
        """, [total_qty, new_wholesale, new_selling, stock_id])

        c.execute("""
            INSERT INTO stock_entries
                (stock_id, quantity_added, purchase_price, selling_price,
                 supplier, notes, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
        """, [stock_id, qty_added, purchase_price, selling_price, supplier, notes])

        # Audit
        c.execute("""
            INSERT INTO audit_stock_changes
                (item_id, old_quantity, new_quantity, change_type, created_at)
            VALUES (%s, %s, %s, 'ADD', NOW())
        """, [item_id, cur_qty, total_qty])

    return ok({
        'message': 'Stock updated.',
        'new_quantity': total_qty,
        'new_wholesale': round(new_wholesale, 2),
        'new_selling': round(new_selling, 2),
    })


# ─────────────────────────────────────────────────────────────
#  BILLS — save & list
#  v2 schema: bills / bill_items / payments (no auto-create needed)
# ─────────────────────────────────────────────────────────────

def bills(request):
    store_id = get_store_id(request)
    if not store_id:
        return fail('Not authenticated.', 401)

    if request.method == 'GET':
        with connection.cursor() as c:
            c.execute("""
                SELECT b.bill_id, b.bill_number, b.total_amount,
                       b.total_gst, b.discount_amount, b.final_amount,
                       b.status, b.created_at
                FROM bills b
                WHERE b.store_id=%s
                ORDER BY b.bill_id DESC
                LIMIT 200
            """, [store_id])
            bill_rows = c.fetchall()

        bill_ids = [r[0] for r in bill_rows]
        items_by_bill = {}
        payments_by_bill = {}

        if bill_ids:
            fmt = ','.join(['%s'] * len(bill_ids))
            with connection.cursor() as c:
                c.execute(f"""
                    SELECT bi.bill_id, bi.item_id, i.item_name, i.brand,
                           bi.quantity, bi.price_at_sale,
                           bi.gst_percentage, bi.gst_amount, bi.total_price,
                           bi.category_id
                    FROM bill_items bi
                    JOIN items i ON i.item_id = bi.item_id
                    WHERE bi.bill_id IN ({fmt})
                """, bill_ids)
                for row in c.fetchall():
                    bid = row[0]
                    items_by_bill.setdefault(bid, []).append({
                        'item_id':    row[1],
                        'name':       row[2],
                        'brand':      row[3] or '',
                        'qty':        float(row[4]),
                        'price':      float(row[5]),
                        'gst_pct':    float(row[6]) if row[6] else 0,
                        'gst_amount': float(row[7]) if row[7] else 0,
                        'total':      float(row[8]),
                        'category_id': row[9],
                    })

                c.execute(f"""
                    SELECT bill_id, method, amount, upi_reference,
                           cash_received, change_returned, note
                    FROM payments WHERE bill_id IN ({fmt})
                """, bill_ids)
                for row in c.fetchall():
                    bid = row[0]
                    payments_by_bill.setdefault(bid, []).append({
                        'method':          row[1],
                        'amount':          float(row[2]),
                        'upi_reference':   row[3],
                        'cash_received':   float(row[4]) if row[4] else None,
                        'change_returned': float(row[5]) if row[5] else None,
                        'note':            row[6],
                    })

        result = []
        for r in bill_rows:
            bid = r[0]
            result.append({
                'bill_id':      bid,
                'bill_number':  r[1],
                'total_amount': float(r[2]),
                'total_gst':    float(r[3]),
                'discount':     float(r[4]),
                'final_amount': float(r[5]),
                'status':       r[6],
                'ts':           int(to_local(r[7]).timestamp() * 1000) if r[7] else 0,
                'items':        items_by_bill.get(bid, []),
                'payments':     payments_by_bill.get(bid, []),
            })
        return ok({'bills': result})

    if request.method == 'POST':
        d               = body(request)
        bill_number     = str(d.get('bill_number', '')).strip()
        bill_items_data = d.get('items', [])
        payments_data   = d.get('payments', [])

        if not bill_number:
            return fail('bill_number is required.')
        if not bill_items_data:
            return fail('Bill must have at least one item.')

        # ── Input sanity: reject negative / absurd amounts ───────
        MAX_BILL_AMOUNT = 10_000_000  # ₹1 crore ceiling
        try:
            total_amount    = float(d.get('total_amount', 0))
            total_gst       = float(d.get('total_gst', 0))
            discount_amount = float(d.get('discount_amount', 0))
            final_amount    = float(d.get('final_amount', total_amount + total_gst - discount_amount))
        except (TypeError, ValueError):
            return fail('Invalid numeric value in bill amounts.')

        if total_amount < 0 or total_gst < 0 or discount_amount < 0 or final_amount < 0:
            return fail('Bill amounts cannot be negative.')
        if total_amount > MAX_BILL_AMOUNT or final_amount > MAX_BILL_AMOUNT:
            return fail('Bill amount exceeds maximum allowed value.')
        if not isinstance(bill_items_data, list) or len(bill_items_data) > 500:
            return fail('Invalid items list.')

        try:
            with connection.cursor() as c:
                # ── Insert bill header ────────────────────────────────
                now = timezone.now()
                c.execute("""
                    INSERT INTO bills
                        (store_id, bill_number, total_amount, total_gst,
                         discount_amount, final_amount, status, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, 'COMPLETED', %s)
                """, [store_id, bill_number, total_amount, total_gst,
                      discount_amount, final_amount, now])
                bill_id = c.lastrowid

                # ── Insert bill line items ────────────────────────────
                for item in bill_items_data:
                    item_id = item.get('item_id')
                    cat_id  = item.get('category_id')
                    try:
                        qty     = float(item.get('qty', 1))
                        price   = float(item.get('price', 0))
                        gst_pct = float(item.get('gst_pct', 0))
                        gst_amt = float(item.get('gst_amount', 0))
                        total   = float(item.get('total', price * qty))
                    except (TypeError, ValueError):
                        return fail(f'Invalid numeric value in item {item_id}.')
                    if qty <= 0 or qty > 100_000:
                        return fail(f'Item quantity out of valid range (item_id={item_id}).')
                    if price < 0 or price > MAX_BILL_AMOUNT:
                        return fail(f'Item price out of valid range (item_id={item_id}).')
                    if gst_pct < 0 or gst_pct > 100:
                        return fail(f'Invalid GST percentage (item_id={item_id}).')

                    # Resolve category_id from item if not supplied by frontend
                    if not cat_id:
                        c.execute(
                            "SELECT category_id FROM items WHERE item_id=%s AND store_id=%s",
                            [item_id, store_id]
                        )
                        row = c.fetchone()
                        cat_id = row[0] if row else None

                    c.execute("""
                        INSERT INTO bill_items
                            (bill_id, category_id, item_id, quantity,
                             price_at_sale, gst_percentage, gst_amount, total_price)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """, [bill_id, cat_id, item_id, qty, price, gst_pct, gst_amt, total])

                    # ── Deduct stock ──────────────────────────────────
                    c.execute("""
                        UPDATE stock SET current_quantity = current_quantity - %s,
                               updated_at = NOW()
                        WHERE item_id=%s AND current_quantity >= %s
                    """, [qty, item_id, qty])

                    # ── Audit stock change (optional table — skip if missing) ──
                    try:
                        c.execute("""
                            INSERT INTO audit_stock_changes
                                (item_id, change_type, reference_id, created_at)
                            VALUES (%s, 'SALE', %s, NOW())
                        """, [item_id, bill_id])
                    except Exception:
                        pass  # table may not exist on older installs

                # ── Insert payments ───────────────────────────────────
                for pay in payments_data:
                    c.execute("""
                        INSERT INTO payments
                            (bill_id, method, amount, upi_reference,
                             cash_received, change_returned, note, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                    """, [
                        bill_id,
                        str(pay.get('method', 'CASH')).upper(),
                        float(pay.get('amount', 0)),
                        pay.get('upi_reference') or None,
                        float(pay.get('cash_received')) if pay.get('cash_received') else None,
                        float(pay.get('change_returned')) if pay.get('change_returned') else None,
                        pay.get('note') or None,
                    ])

                # ── Update daily_metrics (upsert) ─────────────────────
                # Schema: store_id, date, total_sales, total_profit, total_transactions, top_item_id
                try:
                    c.execute("""
                        INSERT INTO daily_metrics
                            (store_id, date, total_sales, total_profit, total_transactions)
                        VALUES (%s, CURDATE(), %s, %s, 1)
                        ON DUPLICATE KEY UPDATE
                            total_sales        = total_sales        + %s,
                            total_profit       = total_profit       + %s,
                            total_transactions = total_transactions + 1
                    """, [
                        store_id,
                        final_amount,
                        final_amount - total_amount,
                        final_amount,
                        final_amount - total_amount,
                    ])
                except Exception:
                    pass  # daily_metrics may not exist on older installs

        except Exception as e:
            import traceback
            return fail(f'Failed to save bill: {str(e)}', 500)

        return ok({'message': 'Bill saved.', 'bill_id': bill_id})

    return fail('Method not allowed.', 405)


def export_report_data(request):
    """Fetch all data needed for the PDF export based on a date range."""
    if request.method != 'GET':
        return fail('Method not allowed.', 405)

    store_id = get_store_id(request)
    if not store_id:
        return fail('Not authenticated.', 401)

    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    if not start_date or not end_date:
        return fail('Start date and end date are required.')

    # Ensure end_date includes the full day
    end_date_full = f"{end_date} 23:59:59"

    try:
        results = {}

        with connection.cursor() as c:
            # 1. Low Stock Report
            c.execute("""
                SELECT i.item_name, i.brand, st.current_quantity, cat.name
                FROM items i
                JOIN stock st ON st.item_id = i.item_id
                LEFT JOIN categories cat ON cat.category_id = i.category_id
                WHERE i.store_id=%s AND st.current_quantity <= 5
                ORDER BY st.current_quantity ASC
            """, [store_id])
            results['low_stock'] = [
                {'name': r[0], 'brand': r[1], 'qty': float(r[2]), 'category': r[3]}
                for r in c.fetchall()
            ]

            # 2. Recent Transactions (Bills Generated)
            c.execute("""
                SELECT b.bill_number, b.final_amount, b.created_at, b.status
                FROM bills b
                WHERE b.store_id=%s AND b.created_at BETWEEN %s AND %s
                ORDER BY b.created_at DESC
            """, [store_id, start_date, end_date_full])
            results['transactions'] = [
                {'bill_no': r[0], 'amount': float(r[1]), 'date': to_local(r[2]).strftime('%d %b %Y, %I:%M %p') if r[2] else '', 'status': r[3]}
                for r in c.fetchall()
            ]

            # 3. Top Selling Items
            c.execute("""
                SELECT i.item_name, SUM(bi.quantity) as total_qty, SUM(bi.total_price) as total_rev
                FROM bill_items bi
                JOIN bills b ON b.bill_id = bi.bill_id
                JOIN items i ON i.item_id = bi.item_id
                WHERE b.store_id=%s AND b.status='COMPLETED' AND b.created_at BETWEEN %s AND %s
                GROUP BY i.item_id, i.item_name
                ORDER BY total_qty DESC
                LIMIT 10
            """, [store_id, start_date, end_date_full])
            results['top_selling'] = [
                {'name': r[0], 'qty': float(r[1]), 'revenue': float(r[2])}
                for r in c.fetchall()
            ]

            # 4. Profit Snapshot
            c.execute("""
                SELECT 
                    SUM(bi.total_price) as total_revenue,
                    SUM(bi.quantity * st.wholesale_price) as total_cost
                FROM bill_items bi
                JOIN bills b ON b.bill_id = bi.bill_id
                JOIN stock st ON st.item_id = bi.item_id
                WHERE b.store_id=%s AND b.status='COMPLETED' AND b.created_at BETWEEN %s AND %s
            """, [store_id, start_date, end_date_full])
            row = c.fetchone()
            rev = float(row[0] or 0)
            cost = float(row[1] or 0)
            results['profit'] = {
                'revenue': rev,
                'cost': cost,
                'profit': rev - cost
            }

            # 5. Daily Summary (Last 10 Days)
            c.execute("""
                SELECT DATE(b.created_at) as d, SUM(b.final_amount) as revenue
                FROM bills b
                WHERE b.store_id=%s AND b.status='COMPLETED'
                GROUP BY DATE(b.created_at)
                ORDER BY d DESC
                LIMIT 10
            """, [store_id])
            results['daily_summary'] = [
                {'date': (r[0].strftime('%d %b') if hasattr(r[0], 'strftime') else str(r[0])), 'revenue': float(r[1])}
                for r in c.fetchall()
            ]

            # 6. Inventory Snapshot
            c.execute("""
                SELECT COUNT(*) as skus, SUM(st.current_quantity) as total_qty, SUM(st.current_quantity * st.wholesale_price) as total_value
                FROM items i
                JOIN stock st ON st.item_id = i.item_id
                WHERE i.store_id=%s
            """, [store_id])
            row = c.fetchone()
            results['inventory_snapshot'] = {
                'skus': int(row[0] or 0),
                'total_qty': float(row[1] or 0),
                'total_value': float(row[2] or 0)
            }

        return ok(results)

    except Exception as e:
        traceback.print_exc()
        return fail(f'Server error: {str(e)}', 500)


def low_stock_alerts(request):
    """Fetch items with quantity <= 5 for notifications."""
    if request.method != 'GET':
        return fail('Method not allowed.', 405)

    store_id = get_store_id(request)
    if not store_id:
        return fail('Not authenticated.', 401)

    try:
        with connection.cursor() as c:
            c.execute("""
                SELECT i.item_id, i.item_name, i.brand, st.current_quantity, cat.name
                FROM items i
                JOIN stock st ON st.item_id = i.item_id
                LEFT JOIN categories cat ON cat.category_id = i.category_id
                WHERE i.store_id=%s AND st.current_quantity <= 5
                ORDER BY st.current_quantity ASC
            """, [store_id])
            rows = c.fetchall()
            
        alerts = [
            {
                'id': r[0],
                'name': r[1],
                'brand': r[2] or '',
                'qty': float(r[3]),
                'category': r[4] or 'General'
            }
            for r in rows
        ]
        return ok({'alerts': alerts, 'count': len(alerts)})

    except Exception as e:
        traceback.print_exc()
        return fail(f'Server error: {str(e)}', 500)


# ─────────────────────────────────────────────────────────────
#  PRODUCTS COMPATIBILITY SHIM
#  The frontend still calls /products/ and /products/<id>/
#  with the old field names (name, stock, price, wholesale, gst).
#  These views translate old field names → new schema and
#  delegate to the real items/stock tables.
#  This lets the existing index.html work without any HTML edits.
# ─────────────────────────────────────────────────────────────




def products_compat(request):
    """
    GET  /products/  → returns items in old 'products' shape so the
                       frontend renders categories and billing correctly.
    POST /products/  → accepts old field names, writes to items + stock.
    """
    store_id = get_store_id(request)
    if not store_id:
        return fail('Not authenticated.', 401)

    if request.method == 'GET':
        # Optional ?category_id=X filter — used by Add Stock page to load
        # only items belonging to the selected category, and to auto-populate
        # the current selling price when an item is selected.
        cat_id_filter = request.GET.get('category_id')

        with connection.cursor() as c:
            if cat_id_filter:
                c.execute("""
                    SELECT i.item_id, i.item_name, i.brand, i.gst_percentage,
                           i.category_id, cat.name AS category_name,
                           COALESCE(st.current_quantity, 0)  AS stock,
                           COALESCE(st.wholesale_price, 0)   AS wholesale,
                           COALESCE(st.selling_price, 0)     AS price
                    FROM items i
                    LEFT JOIN categories cat ON cat.category_id = i.category_id
                    LEFT JOIN stock st       ON st.item_id      = i.item_id
                    WHERE i.store_id=%s AND i.category_id=%s
                    ORDER BY i.item_name
                """, [store_id, cat_id_filter])
            else:
                c.execute("""
                    SELECT i.item_id, i.item_name, i.brand, i.gst_percentage,
                           i.category_id, cat.name AS category_name,
                           COALESCE(st.current_quantity, 0)  AS stock,
                           COALESCE(st.wholesale_price, 0)   AS wholesale,
                           COALESCE(st.selling_price, 0)     AS price
                    FROM items i
                    LEFT JOIN categories cat ON cat.category_id = i.category_id
                    LEFT JOIN stock st       ON st.item_id      = i.item_id
                    WHERE i.store_id=%s
                    ORDER BY cat.name, i.item_name
                """, [store_id])
            rows = c.fetchall()

        # Return in the exact shape the frontend expects from the old /products/ API
        return ok({'products': [
            {
                'id':          r[0],
                'name':        r[1],           # frontend uses 'name'
                'brand':       r[2] or '',
                'size':        '',              # v2 schema has no size; keep key so JS doesn't break
                'gst':         float(r[3]),
                'category_id': r[4],
                'category':    r[5] or 'Uncategorized',
                'stock':       float(r[6]),     # frontend uses 'stock'
                'wholesale':   float(r[7]),
                'price':       float(r[8]),
            }
            for r in rows
        ]})

    if request.method == 'POST':
        d         = body(request)
        # Frontend sends 'name', backend v2 schema needs 'item_name'
        item_name = str(d.get('name', d.get('item_name', ''))).strip()
        brand     = str(d.get('brand', '')).strip()
        gst       = float(d.get('gst', 0))
        cat_id    = d.get('category_id')
        wholesale = float(d.get('wholesale', 0))
        price     = float(d.get('price', 0))
        quantity  = float(d.get('stock', d.get('quantity', 0)))

        if not item_name: return fail('Item name is required.')
        if not cat_id:    return fail('Category is required.')
        if not brand:
            # Frontend sometimes omits brand; fall back to category name
            with connection.cursor() as c:
                c.execute("SELECT name FROM categories WHERE category_id=%s", [cat_id])
                r = c.fetchone()
                brand = r[0] if r else 'General'

        with connection.cursor() as c:
            c.execute("""
                INSERT INTO items
                    (store_id, category_id, item_name, brand,
                     gst_percentage, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
            """, [store_id, cat_id, item_name, brand, gst])
            item_id = c.lastrowid

            # Always create the stock row immediately after creating the item.
            # Use INSERT IGNORE so if a row somehow already exists (e.g. a
            # previous partial insert), we don't crash — the add_stock handler
            # will update it correctly when the user adds stock later.
            c.execute("""
                INSERT IGNORE INTO stock
                    (category_id, item_id, current_quantity,
                     wholesale_price, selling_price, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
            """, [cat_id, item_id, quantity, wholesale, price])
            stock_id = c.lastrowid or 0

            if quantity > 0:
                c.execute("""
                    INSERT INTO stock_entries
                        (stock_id, quantity_added, purchase_price,
                         selling_price, created_at)
                    VALUES (%s, %s, %s, %s, NOW())
                """, [stock_id, quantity, wholesale, price])

        # Return 'id' so the frontend can push the new product into allProducts
        return ok({'id': item_id, 'message': 'Item added.'})

    return fail('Method not allowed.', 405)


def product_detail_compat(request, prod_id):
    """
    PUT  /products/<id>/  → update item + stock using old field names
    DELETE /products/<id>/ → delete item (cascade removes stock)
    """
    store_id = get_store_id(request)
    if not store_id:
        return fail('Not authenticated.', 401)

    if request.method == 'PUT':
        d = body(request)

        # ── Stock-add detection ──────────────────────────────────────
        # The "Add Stock" page sends {stock: newTotalStock, wholesale, price}
        # with NO name/brand/gst fields. That means it's a stock-add call,
        # NOT a plain edit. We must:
        #   1. Figure out qty_added  = newTotalStock - current_quantity
        #   2. Recompute weighted-average wholesale (and selling) price
        #   3. Update stock table with correct totals
        #   4. Insert a row in stock_entries (audit log)
        #
        # The frontend pre-calculates newTotalStock = prod.stock + qty,
        # so qty_added = newTotalStock - current DB quantity.
        is_stock_add = ('stock' in d) and ('wholesale' in d) and ('name' not in d)

        if is_stock_add:
            new_total_stock = float(d.get('stock', 0))
            new_wholesale   = float(d.get('wholesale', 0))
            new_selling     = float(d.get('price', 0))
            supplier        = str(d.get('supplier', '')).strip() or None
            notes           = str(d.get('notes', '')).strip() or None

            # Fetch current stock row
            with connection.cursor() as c:
                c.execute("""
                    SELECT st.stock_id, st.current_quantity,
                           st.wholesale_price, st.selling_price
                    FROM stock st
                    JOIN items i ON i.item_id = st.item_id
                    WHERE st.item_id=%s AND i.store_id=%s
                """, [prod_id, store_id])
                row = c.fetchone()

            # ── AUTO-CREATE STOCK ROW IF MISSING ──────────────────────
            # This happens when an item was added via the Categories page
            # but the stock row failed to insert (e.g. due to a DB
            # constraint issue), or when items were seeded directly via SQL.
            # Instead of returning a 404, we create the stock row now so
            # the user can always add stock without hitting an error.
            if not row:
                with connection.cursor() as c:
                    # Get the category_id for this item (needed by stock table)
                    c.execute("""
                        SELECT category_id FROM items
                        WHERE item_id=%s AND store_id=%s
                    """, [prod_id, store_id])
                    item_row = c.fetchone()

                if not item_row:
                    return fail('Item not found.', 404)

                cat_id_for_stock = item_row[0]

                with connection.cursor() as c:
                    c.execute("""
                        INSERT INTO stock
                            (category_id, item_id, current_quantity,
                             wholesale_price, selling_price,
                             created_at, updated_at)
                        VALUES (%s, %s, 0, 0, 0, NOW(), NOW())
                    """, [cat_id_for_stock, prod_id])
                    new_stock_id = c.lastrowid

                # Re-fetch so the rest of the logic runs normally
                row = (new_stock_id, 0.0, 0.0, 0.0)

            stock_id, cur_qty, cur_wholesale, _ = row
            cur_qty       = float(cur_qty)
            cur_wholesale = float(cur_wholesale)

            # qty_added is what the user actually typed in the form
            qty_added = new_total_stock - cur_qty
            if qty_added <= 0:
                return fail('Quantity added must be greater than 0.')

            # Wholesale: weighted average. Selling price: always use latest value entered.
            avg_wholesale = round(
                ((cur_wholesale * cur_qty) + (new_wholesale * qty_added)) / new_total_stock, 2
            )
            final_selling = round(new_selling, 2)

            with connection.cursor() as c:
                # 1. Update stock table — weighted avg wholesale, direct selling price
                c.execute("""
                    UPDATE stock
                    SET current_quantity=%s,
                        wholesale_price=%s,
                        selling_price=%s,
                        updated_at=NOW()
                    WHERE stock_id=%s
                """, [new_total_stock, avg_wholesale, final_selling, stock_id])

                # 2. Log every stock addition in stock_entries
                c.execute("""
                    INSERT INTO stock_entries
                        (stock_id, quantity_added, purchase_price,
                         selling_price, supplier, notes, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW())
                """, [stock_id, qty_added, new_wholesale, new_selling,
                      supplier, notes])

                # 3. Audit
                c.execute("""
                    INSERT INTO audit_stock_changes
                        (item_id, old_quantity, new_quantity, change_type, created_at)
                    VALUES (%s, %s, %s, 'ADD', NOW())
                """, [prod_id, cur_qty, new_total_stock])

            return ok({
                'message': 'Stock updated.',
                'new_quantity':  new_total_stock,
                'new_wholesale': avg_wholesale,
                'new_selling':   final_selling,
            })

        # ── Plain item edit (name / brand / gst / price changes) ────
        item_fields, item_vals = [], []
        field_map = {
            'name':        'item_name',
            'brand':       'brand',
            'gst':         'gst_percentage',
            'category_id': 'category_id',
        }
        for old, new in field_map.items():
            if old in d:
                item_fields.append(f'{new}=%s')
                item_vals.append(d[old])

        stock_fields, stock_vals = [], []
        stock_map = {
            'price':     'selling_price',
            'wholesale': 'wholesale_price',
        }
        for old, new in stock_map.items():
            if old in d:
                stock_fields.append(f'{new}=%s')
                stock_vals.append(d[old])

        if not item_fields and not stock_fields:
            return fail('Nothing to update.')

        with connection.cursor() as c:
            if item_fields:
                item_vals += [prod_id, store_id]
                c.execute(
                    f"UPDATE items SET {','.join(item_fields)}, updated_at=NOW() "
                    f"WHERE item_id=%s AND store_id=%s",
                    item_vals
                )
            if stock_fields:
                stock_vals += [prod_id]
                c.execute(
                    f"UPDATE stock SET {','.join(stock_fields)}, updated_at=NOW() "
                    f"WHERE item_id=%s",
                    stock_vals
                )
        return ok({'message': 'Updated.'})

    if request.method == 'DELETE':
        with connection.cursor() as c:
            # bill_items has a bare FK (no CASCADE) so we must remove those
            # rows first; the bill itself keeps all financial data intact.
            c.execute("""
                DELETE bi FROM bill_items bi
                JOIN bills b ON b.bill_id = bi.bill_id
                WHERE bi.item_id=%s AND b.store_id=%s
            """, [prod_id, store_id])
            # stock and stock_entries cascade automatically
            c.execute("""
                DELETE FROM items WHERE item_id=%s AND store_id=%s
            """, [prod_id, store_id])
        return ok({'message': 'Deleted.'})

    return fail('Method not allowed.', 405)


# ─────────────────────────────────────────────────────────────
#  STOCK ENTRIES — history log for Add Stock page
# ─────────────────────────────────────────────────────────────

def stock_entries_list(request):
    """
    GET /stock-entries/  → return all stock_entries for this store,
    joined with item name and category name, newest first.
    """
    store_id = get_store_id(request)
    if not store_id:
        return fail('Not authenticated.', 401)
    if request.method != 'GET':
        return fail('Method not allowed.', 405)

    with connection.cursor() as c:
        c.execute("""
            SELECT
                se.entry_id,
                i.item_name,
                cat.name        AS category_name,
                se.quantity_added,
                se.purchase_price,
                se.selling_price,
                se.supplier,
                se.notes,
                se.created_at
            FROM stock_entries se
            JOIN stock       st  ON st.stock_id   = se.stock_id
            JOIN items       i   ON i.item_id      = st.item_id
            JOIN categories  cat ON cat.category_id = st.category_id
            WHERE i.store_id = %s
            ORDER BY se.created_at DESC
            LIMIT 200
        """, [store_id])
        rows = c.fetchall()

    entries = [
        {
            'entry_id':      r[0],
            'item':          r[1],
            'cat':           r[2],
            'qty':           float(r[3]),
            'wholesale':     float(r[4]) if r[4] is not None else 0,
            'sell':          float(r[5]) if r[5] is not None else 0,
            'supplier':      r[6] or '',
            'notes':         r[7] or '',
            'time':          to_local(r[8]).strftime('%d %b %Y, %I:%M %p') if r[8] else '',
        }
        for r in rows
    ]
    return ok({'entries': entries})


# ─────────────────────────────────────────────────────────────
#  FORGOT PASSWORD FLOW
# ─────────────────────────────────────────────────────────────

def forgot_password_init(request):
    """Step 1: Check phone exists and send OTP."""
    if request.method != 'POST': return fail('Method not allowed', 405)
    try:
        ensure_otp_attempt_log()
        d     = body(request)
        phone = str(d.get('phone', '')).strip()
        if len(phone) != 10: return fail('Enter valid 10-digit phone.')
        
        # Verify phone exists
        with connection.cursor() as c:
            c.execute("SELECT user_id FROM user_credentials WHERE phone_number=%s", [phone])
            user = c.fetchone()
        if not user:
            return fail('No account found with this phone number.')
            
        # Send OTP logic
        otp    = make_otp()
        hashed = otp_hash(otp)
        expiry = timezone.now() + timedelta(minutes=15)
        
        # Save OTP (using otp_type='forgot_phone')
        with connection.cursor() as c:
            c.execute("""
                INSERT INTO user_contact_verification
                    (user_id, type, otp_hash, expires_at)
                VALUES (%s, 'phone', %s, %s)
            """, [user[0], hashed, expiry])
            
        print(f'\n  FORGOT OTP for +91{phone}  =>  {otp}')
        send_phone_otp(phone, otp)
        return ok({'message': 'OTP sent successfully.'})
    except Exception as e:
        traceback.print_exc()
        return fail(str(e), 500)

def forgot_password_verify(request):
    """Step 2: Verify OTP and return reset token."""
    if request.method != 'POST': return fail('Method not allowed', 405)
    try:
        ensure_forgot_tokens_table()
        d     = body(request)
        phone = str(d.get('phone', '')).strip()
        otp   = str(d.get('otp', '')).strip()
        
        with connection.cursor() as c:
            c.execute("SELECT user_id FROM user_credentials WHERE phone_number=%s", [phone])
            user = c.fetchone()
        if not user: return fail('Internal error')
        
        # ── OTP attempt limiting ──
        max_otp_attempts = getattr(_django_settings, 'OTP_MAX_ATTEMPTS', 5)
        ensure_otp_attempt_log()
        with connection.cursor() as c:
            c.execute("""
                SELECT COUNT(*) FROM otp_attempt_log
                WHERE user_id=%s AND otp_type='forgot_phone' AND success=0
                  AND attempted_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)
            """, [user[0]])
            otp_fails = c.fetchone()[0]
        if otp_fails >= max_otp_attempts:
            # Invalidate any outstanding OTP
            with connection.cursor() as c:
                c.execute("""
                    UPDATE user_contact_verification SET is_verified=1
                    WHERE user_id=%s AND type='phone' AND is_verified=0
                """, [user[0]])
            return fail('Too many incorrect attempts. Request a new OTP.', 429)
        # ──────────────────────────

        # Check OTP
        with connection.cursor() as c:
            c.execute("""
                SELECT verification_id FROM user_contact_verification
                WHERE user_id=%s AND type='phone' AND is_verified=0
                  AND otp_hash=%s AND expires_at > %s
                ORDER BY verification_id DESC LIMIT 1
            """, [user[0], otp_hash(otp), timezone.now()])
            row = c.fetchone()
            
        if not row:
            _log_otp_attempt(user[0], 'forgot_phone', False)
            return fail('Incorrect or expired OTP.')
            
        _log_otp_attempt(user[0], 'forgot_phone', True)
        
        # Mark verified
        with connection.cursor() as c:
            c.execute("UPDATE user_contact_verification SET is_verified=1 WHERE verification_id=%s", [row[0]])
            
        # Issue Reset Token
        reset_token = make_token()
        with connection.cursor() as c:
            c.execute("""
                INSERT INTO forgot_password_tokens (phone, token, expires_at)
                VALUES (%s, %s, %s)
            """, [phone, reset_token, timezone.now() + timedelta(minutes=10)])
            
        return ok({'message': 'OTP verified.', 'reset_token': reset_token})
    except Exception as e:
        traceback.print_exc()
        return fail(str(e), 500)

def forgot_password_reset(request):
    """Step 3: Reset password using token."""
    if request.method != 'POST': return fail('Method not allowed', 405)
    try:
        d           = body(request)
        phone       = str(d.get('phone', '')).strip()
        reset_token = str(d.get('reset_token', '')).strip()
        new_pass    = str(d.get('password', '')).strip()
        
        # Validate complexity
        is_strong, msg = validate_password_strength(new_pass)
        if not is_strong: return fail(msg)

        # Validate token
        with connection.cursor() as c:
            c.execute("""
                SELECT id FROM forgot_password_tokens
                WHERE phone=%s AND token=%s AND is_used=0 AND expires_at > %s
            """, [phone, reset_token, timezone.now()])
            row = c.fetchone()
            
        if not row: return fail('Invalid or expired reset session. Start over.')
        
        # Check against existing password to prevent reuse
        with connection.cursor() as c:
            c.execute("SELECT password_hash FROM user_credentials WHERE phone_number=%s", [phone])
            old_hash_row = c.fetchone()
        
        if old_hash_row and check_password(new_pass, old_hash_row[0]):
            return fail('New password cannot be the same as your current password.')
        
        # Update Password
        hashed_pass = make_password(new_pass)
        with connection.cursor() as c:
            c.execute("UPDATE user_credentials SET password_hash=%s WHERE phone_number=%s", [hashed_pass, phone])
            c.execute("UPDATE forgot_password_tokens SET is_used=1 WHERE id=%s", [row[0]])
            
        return ok({'message': 'Password has been reset successfully.'})
    except Exception as e:
        traceback.print_exc()
        return fail(str(e), 500)
