from pathlib import Path
from decouple import config, Csv

BASE_DIR = Path(__file__).resolve().parent.parent

# ── SECURITY ─────────────────────────────────────────────────────
SECRET_KEY = config('DJANGO_SECRET_KEY')

DEBUG = str(config('DEBUG', default='False')).strip().lower() in ('1', 'true', 'yes', 'on')

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1', cast=Csv())

# ── APPS ──────────────────────────────────────────────────────────
INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.staticfiles',
    'auth_app',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'dukaanos.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
            ],
        },
    },
]

WSGI_APPLICATION = 'dukaanos.wsgi.application'

# ── DATABASE ─────────────────────────────────────────────────────
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME':     config('DB_NAME',     default='dukaanos'),
        'USER':     config('DB_USER',     default='root'),
        'PASSWORD': config('DB_PASSWORD'),
        'HOST':     config('DB_HOST',     default='localhost'),
        'PORT':     config('DB_PORT',     default='3306'),
        'OPTIONS': {
            'charset': 'utf8mb4',
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES', time_zone='+00:00'",
        },
    }
}

# ── AUTH CONFIG ───────────────────────────────────────────────────
OTP_EXPIRY_MINUTES    = 10
OTP_MAX_ATTEMPTS      = 5     # lock OTP after this many wrong guesses
LOGIN_MAX_ATTEMPTS    = 5     # lock password login after this many failures
LOGIN_LOCKOUT_MINUTES = 15    # rolling window for counting failures
SESSION_EXPIRY_DAYS   = 30

# ── EMAIL ─────────────────────────────────────────────────────────
EMAIL_BACKEND       = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST          = 'smtp.gmail.com'
EMAIL_PORT          = 587
EMAIL_USE_TLS       = True
EMAIL_HOST_USER     = config('EMAIL_HOST_USER',     default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
DEFAULT_FROM_EMAIL  = f'DukaanOS <{config("EMAIL_HOST_USER", default="")}>'

# ── SMS ───────────────────────────────────────────────────────────
FAST2SMS_API_KEY = config('FAST2SMS_API_KEY', default='')

# ── INTERNATIONALISATION ──────────────────────────────────────────
LANGUAGE_CODE = 'en-us'
TIME_ZONE     = 'Asia/Kolkata'
USE_I18N      = True
USE_TZ        = True
STATIC_URL    = '/static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
