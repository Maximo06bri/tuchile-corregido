"""
Configuración de Django para el proyecto TUCHILE PMS.

Este módulo define los ajustes de seguridad, base de datos, middleware
y demás parámetros del framework, alineados con los controles de la
norma ISO/IEC 27001:2022 (Anexo A) y las buenas prácticas PEP 8 / PEP 257.

Controles aplicados:
    - A.8.9  : Gestión de la configuración (secretos vía variables de entorno).
    - A.8.12 : Prevención de fuga de datos (DEBUG = False en producción).
    - A.8.20 : Seguridad en redes (ALLOWED_HOSTS y CORS restrictivos).
    - A.8.24 : Uso de criptografía (BCrypt + PBKDF2, eliminación de MD5).
    - A.8.28 : Codificación segura (timeout de conexión, Fail-Fast).
    - A.8.31 : Separación de entornos (dev / staging / production).
    - A.8.5  : Autenticación segura (cookies seguras, expiración de sesión).
"""

import os
from pathlib import Path


# ---------------------------------------------------------------------------
# Directorio base del proyecto
# ---------------------------------------------------------------------------
BASE_DIR: Path = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Constantes normativas ISO/IEC 27001:2022  (Guía de Estandarización)
# ---------------------------------------------------------------------------
BCRYPT_ROUNDS_COST: int = 12
"""Costo computacional de BCrypt (Control A.8.24)."""

MIN_LONGITUD_PASSWORD: int = 12
"""Longitud mínima de contraseña aceptada (Control A.8.24)."""

DIAS_EXPIRACION_LLAVE_AES: int = 90
"""Días máximos de vigencia de llaves simétricas AES (Control A.8.24)."""

TIMEOUT_CONEXION_SERVICIOS_SEGUNDOS: int = 5
"""Timeout de conexión a servicios externos y base de datos (Control A.8.9 / A.8.28)."""

LIMITE_INACTIVIDAD_SESION_SEGUNDOS: int = 1800
"""Segundos de inactividad antes de expirar la sesión – 30 min (Control A.8.5)."""

# ---------------------------------------------------------------------------
# Entorno y seguridad  (Controles A.8.12 / A.8.31)
# ---------------------------------------------------------------------------
ENVIRONMENT: str = os.environ.get("ENVIRONMENT", "production")

SECRET_KEY: str = os.environ["DJANGO_SECRET_KEY"]
"""Fail-Fast: la aplicación NO arranca si la clave no está definida (A.8.9)."""

DEBUG: bool = (
    os.environ.get("DJANGO_DEBUG", "False").lower() == "true"
    and ENVIRONMENT != "production"
)

ALLOWED_HOSTS: list[str] = os.environ.get(
    "DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1"
).split(",")

# ---------------------------------------------------------------------------
# Aplicaciones instaladas
# ---------------------------------------------------------------------------
INSTALLED_APPS: list[str] = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "corsheaders",
    "portal",
]

# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------
MIDDLEWARE: list[str] = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF: str = "tuchile_pms.urls"

# ---------------------------------------------------------------------------
# Plantillas
# ---------------------------------------------------------------------------
TEMPLATES: list[dict] = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION: str = "tuchile_pms.wsgi.application"

# ---------------------------------------------------------------------------
# Base de datos  (Controles A.8.9 / A.8.24 / A.8.28)
# ---------------------------------------------------------------------------
DATABASES: dict = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": os.environ.get("DB_NAME", "tuchile_db"),
        "USER": os.environ.get("DB_USER", "tuchile_app"),
        "PASSWORD": os.environ["DB_PASSWORD"],
        "HOST": os.environ.get("DB_HOST", "127.0.0.1"),
        "PORT": os.environ.get("DB_PORT", "3306"),
        "CONN_MAX_AGE": 600,
        "OPTIONS": {
            "init_command": "SET sql_mode='STRICT_TRANS_TABLES'",
            "charset": "utf8mb4",
            "connect_timeout": TIMEOUT_CONEXION_SERVICIOS_SEGUNDOS,
        },
    }
}

# ---------------------------------------------------------------------------
# Hashers de contraseña  (Control A.8.24) – BCrypt prioritario, sin MD5
# ---------------------------------------------------------------------------
PASSWORD_HASHERS: list[str] = [
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

# ---------------------------------------------------------------------------
# Validación de contraseña  (Control A.8.24)
# ---------------------------------------------------------------------------
AUTH_PASSWORD_VALIDATORS: list[dict] = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
     "OPTIONS": {"min_length": MIN_LONGITUD_PASSWORD}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# ---------------------------------------------------------------------------
# Internacionalización
# ---------------------------------------------------------------------------
LANGUAGE_CODE: str = "es-cl"
TIME_ZONE: str = "America/Santiago"
USE_I18N: bool = True
USE_TZ: bool = True

# ---------------------------------------------------------------------------
# Archivos estáticos
# ---------------------------------------------------------------------------
STATIC_URL: str = "/static/"
STATICFILES_DIRS: list[Path] = [BASE_DIR / "static"]
DEFAULT_AUTO_FIELD: str = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# Cookies y sesiones seguras  (Control A.8.5)
# ---------------------------------------------------------------------------
SESSION_COOKIE_SECURE: bool = True
SESSION_COOKIE_HTTPONLY: bool = True
SESSION_COOKIE_SAMESITE: str = "Lax"
CSRF_COOKIE_SECURE: bool = True
CSRF_COOKIE_HTTPONLY: bool = True
SESSION_COOKIE_AGE: int = LIMITE_INACTIVIDAD_SESION_SEGUNDOS
SESSION_EXPIRE_AT_BROWSER_CLOSE: bool = True

# ---------------------------------------------------------------------------
# CORS  (Control A.8.9 / A.8.20)
# ---------------------------------------------------------------------------
CORS_ALLOW_ALL_ORIGINS: bool = False
CORS_ALLOWED_ORIGINS: list[str] = os.environ.get(
    "CORS_ALLOWED_ORIGINS", "https://tuchile.cl"
).split(",")

# ---------------------------------------------------------------------------
# Cabeceras de seguridad adicionales  (Control A.8.9)
# ---------------------------------------------------------------------------
SECURE_BROWSER_XSS_FILTER: bool = True
SECURE_CONTENT_TYPE_NOSNIFF: bool = True
X_FRAME_OPTIONS: str = "DENY"

# ---------------------------------------------------------------------------
# Pasarela de pagos y Login URL  (Control A.8.9 / A.8.24)
# ---------------------------------------------------------------------------
PAYMENT_GATEWAY_API_KEY: str = os.environ["PAYMENT_GATEWAY_API_KEY"]
"""Fail-Fast: clave de pasarela cargada exclusivamente desde entorno."""

LOGIN_URL: str = "/login/"
