"""
Vistas del portal de Turismo TUCHILE.

Módulo refactorizado conforme a los controles del Anexo A de la norma
ISO/IEC 27001:2022 y a los umbrales cuantificables de la Guía de
Estandarización PEP 8 / PEP 257 del curso.

Controles aplicados:
    - A.8.2  : Gestión de accesos privilegiados (RBAC con ``@login_required``).
    - A.8.5  : Autenticación segura (bloqueo anti-fuerza bruta).
    - A.8.11 : Enmascaramiento de datos PII (RUT y tarjeta).
    - A.8.12 : Prevención de fuga de datos (mensajes genéricos < 100 chars).
    - A.8.15 : Registro de eventos (log seguro, anti Log-Injection).
    - A.8.28 : Codificación segura (ORM parametrizado, Decimal, signing).
"""

from __future__ import annotations

import logging
from decimal import Decimal, InvalidOperation

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core import signing
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .models import Cabaña, PagoReserva, Reserva

# ---------------------------------------------------------------------------
# Constantes normativas ISO/IEC 27001:2022  (Guía de Estandarización)
# ---------------------------------------------------------------------------

MAX_INTENTOS_LOGIN_FALLIDOS: int = 5
"""Intentos de inicio de sesión antes de bloquear la cuenta (Control A.8.5)."""

TIEMPO_BLOQUEO_CUENTA_SEGUNDOS: int = 900
"""Duración del bloqueo tras superar los intentos máximos – 15 min (Control A.8.5)."""

LIMITE_INACTIVIDAD_SESION_SEGUNDOS: int = 1800
"""Tiempo máximo de inactividad de sesión – 30 min (Control A.8.5)."""

EXPIRACION_TOKEN_JWT_SEGUNDOS: int = 28800
"""Vigencia máxima de tokens de recuperación – 8 h (Control A.8.5)."""

CARACTERES_VISIBLES_RUT_FINAL: int = 4
"""Dígitos visibles al enmascarar un RUT (Control A.8.11)."""

CARACTERES_VISIBLES_TARJETA_FINAL: int = 4
"""Dígitos visibles al enmascarar una tarjeta (Control A.8.11)."""

MAX_LONGITUD_MENSAJE_LOG: int = 4096
"""Tamaño máximo de un mensaje de log – 4 KB (Control A.8.15)."""

DIAS_RETENCION_LOGS_AUDITORIA: int = 365
"""Días mínimos de retención de registros de auditoría (Control A.8.15)."""

MAX_CARACTERES_ERROR_USUARIO: int = 100
"""Longitud máxima de mensajes de error expuestos al usuario (Control A.8.12)."""

logger = logging.getLogger("portal.seguridad")

# ---------------------------------------------------------------------------
# Almacén en memoria de intentos fallidos (en producción usar caché/Redis)
# ---------------------------------------------------------------------------
_intentos_fallidos: dict[str, list] = {}

# ---------------------------------------------------------------------------
# Funciones utilitarias de seguridad
# ---------------------------------------------------------------------------


def registrar_log_seguro(mensaje: str) -> None:
    """Registra un evento de seguridad sanitizando caracteres de inyección.

    Elimina ``\\n`` y ``\\r`` para prevenir *Log Injection* y trunca el
    mensaje a ``MAX_LONGITUD_MENSAJE_LOG`` caracteres (Control A.8.15).
    """
    mensaje_limpio: str = (
        mensaje.replace("\n", " ").replace("\r", " ")[:MAX_LONGITUD_MENSAJE_LOG]
    )
    logger.info(mensaje_limpio)


def enmascarar_rut_normativo(rut: str) -> str:
    """Devuelve el RUT con solo los últimos 4 caracteres visibles.

    Ejemplo: ``12345678-9`` → ``*******8-9`` (Control A.8.11).
    """
    if len(rut) <= CARACTERES_VISIBLES_RUT_FINAL:
        return rut
    visible: str = rut[-CARACTERES_VISIBLES_RUT_FINAL:]
    oculto: str = "*" * (len(rut) - CARACTERES_VISIBLES_RUT_FINAL)
    return oculto + visible


def enmascarar_tarjeta_normativa(numero: str) -> str:
    """Devuelve la tarjeta con solo los últimos 4 dígitos visibles.

    Ejemplo: ``4111111111111111`` → ``****1111`` (Control A.8.11).
    """
    if len(numero) <= CARACTERES_VISIBLES_TARJETA_FINAL:
        return numero
    visible: str = numero[-CARACTERES_VISIBLES_TARJETA_FINAL:]
    return "****" + visible


# ---------------------------------------------------------------------------
# Vistas públicas
# ---------------------------------------------------------------------------


def registro_cliente(request: HttpRequest) -> HttpResponse:
    """Vista de registro de nuevos clientes."""
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")
        email = request.POST.get("email", "").strip()

        if not username or not password or not email:
            return render(
                request,
                "portal/registro.html",
                {"error": "Todos los campos son obligatorios."},
            )

        if User.objects.filter(username=username).exists():
            return render(
                request,
                "portal/registro.html",
                {"error": "El nombre de usuario ya está en uso."},
            )

        user = User.objects.create_user(
            username=username, password=password, email=email
        )
        login(request, user)
        registrar_log_seguro(f"Registro exitoso: usuario={username}")
        return redirect("dashboard")

    return render(request, "portal/registro.html")


def login_cliente(request: HttpRequest) -> HttpResponse:
    """Vista de inicio de sesión con control anti-fuerza bruta.

    Bloquea la cuenta durante ``TIEMPO_BLOQUEO_CUENTA_SEGUNDOS`` (900 s)
    tras ``MAX_INTENTOS_LOGIN_FALLIDOS`` (5) intentos fallidos consecutivos
    (Control A.8.5).  El mensaje de error es genérico y menor a
    ``MAX_CARACTERES_ERROR_USUARIO`` (100) caracteres (Control A.8.12).
    """
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")

        # --- Control A.8.5: verificar bloqueo temporal ---
        intentos = _intentos_fallidos.get(username, [])
        ahora = timezone.now()

        # Limpiar intentos fuera de ventana
        intentos = [
            ts for ts in intentos
            if (ahora - ts).total_seconds() < TIEMPO_BLOQUEO_CUENTA_SEGUNDOS
        ]
        _intentos_fallidos[username] = intentos

        if len(intentos) >= MAX_INTENTOS_LOGIN_FALLIDOS:
            registrar_log_seguro(
                f"Cuenta bloqueada temporalmente: usuario={username}"
            )
            error_msg = "Cuenta bloqueada. Intente de nuevo más tarde."
            return render(
                request,
                "portal/login.html",
                {"error": error_msg[:MAX_CARACTERES_ERROR_USUARIO]},
            )

        user = authenticate(username=username, password=password)

        if user is not None:
            login(request, user)
            _intentos_fallidos.pop(username, None)
            registrar_log_seguro(f"Login exitoso: usuario={username}")
            return redirect("dashboard")

        # Registrar intento fallido
        intentos.append(ahora)
        _intentos_fallidos[username] = intentos
        registrar_log_seguro(
            f"Login fallido ({len(intentos)}/{MAX_INTENTOS_LOGIN_FALLIDOS}): "
            f"usuario={username}"
        )

        # Control A.8.12: mensaje genérico – no revelar si el usuario existe
        error_msg = "Credenciales inválidas. Verifique sus datos."
        return render(
            request,
            "portal/login.html",
            {"error": error_msg[:MAX_CARACTERES_ERROR_USUARIO]},
        )

    return render(request, "portal/login.html")


def logout_cliente(request: HttpRequest) -> HttpResponse:
    """Cierra la sesión del usuario autenticado."""
    if request.user.is_authenticated:
        registrar_log_seguro(
            f"Logout: usuario={request.user.username}"
        )
    logout(request)
    return redirect("login")


# ---------------------------------------------------------------------------
# Vistas protegidas  (Control A.8.2 – RBAC con @login_required)
# ---------------------------------------------------------------------------


@login_required
def dashboard(request: HttpRequest) -> HttpResponse:
    """Panel principal del usuario autenticado.

    Filtra las reservas por ``usuario=request.user`` para evitar IDOR
    (Control A.8.2).
    """
    cabañas = Cabaña.objects.all()
    reservas = Reserva.objects.filter(usuario=request.user)
    return render(
        request,
        "portal/dashboard.html",
        {"cabañas": cabañas, "reservas": reservas},
    )


@login_required
def crear_reserva(request: HttpRequest) -> HttpResponse:
    """Crea una reserva utilizando el ORM parametrizado de Django.

    Correcciones:
        - B608 eliminado: se sustituye la consulta SQL concatenada por
          ``get_object_or_404(Cabaña, pk=...)`` (Control A.8.28).
        - IDOR eliminado: la reserva se asocia siempre a ``request.user``
          (Control A.8.2).
    """
    if request.method == "POST":
        cabaña_id = request.POST.get("cabana_id", "")
        checkin = request.POST.get("checkin")
        checkout = request.POST.get("checkout")

        # Control A.8.28: ORM parametrizado, sin SQL concatenado
        cabaña = get_object_or_404(Cabaña, pk=int(cabaña_id))

        reserva = Reserva.objects.create(
            usuario=request.user,
            cabaña=cabaña,
            fecha_checkin=checkin,
            fecha_checkout=checkout,
            total_pago=cabaña.precio_noche * 3,
            pagado=False,
        )
        registrar_log_seguro(
            f"Reserva creada: id={reserva.pk} usuario={request.user.username}"
        )
        return redirect("pago_reserva", reserva_id=reserva.pk)

    return render(
        request,
        "portal/crear_reserva.html",
        {"cabañas": Cabaña.objects.all()},
    )


@login_required
def pago_reserva(request: HttpRequest, reserva_id: int) -> HttpResponse:
    """Procesa el pago de una reserva.

    Correcciones:
        - B307 eliminado: ``eval()`` reemplazado por ``Decimal``
          (Control A.8.28).
        - B110 eliminado: ``except Exception: pass`` reemplazado por
          registro seguro con ``registrar_log_seguro`` (Control A.8.15).
        - IDOR corregido: se filtra por ``usuario=request.user``
          (Control A.8.2).
        - A.8.11: la tarjeta se enmascara antes de persistir.
    """
    reserva = get_object_or_404(
        Reserva, pk=reserva_id, usuario=request.user
    )

    if request.method == "POST":
        tarjeta = request.POST.get("tarjeta", "")
        exp = request.POST.get("exp", "")

        try:
            # Control A.8.28: cálculo seguro con Decimal en lugar de eval()
            monto_calculado = Decimal(str(reserva.total_pago)) * Decimal("1.0")

            # Control A.8.11: enmascarar tarjeta antes de almacenar
            tarjeta_masked = enmascarar_tarjeta_normativa(tarjeta)

            PagoReserva.objects.create(
                reserva=reserva,
                monto=monto_calculado,
                numero_tarjeta_masked=tarjeta_masked,
                fecha_expiracion=exp,
            )
            reserva.pagado = True
            reserva.save()

            registrar_log_seguro(
                f"Pago exitoso: reserva={reserva.pk} "
                f"tarjeta={tarjeta_masked} monto={monto_calculado}"
            )

            return render(
                request,
                "portal/pago_exitoso.html",
                {"reserva": reserva, "monto": monto_calculado},
            )

        except (InvalidOperation, ValueError, TypeError) as exc:
            # Control A.8.15: registrar excepción de forma segura
            registrar_log_seguro(
                f"Error en pago reserva={reserva_id}: {exc}"
            )
            error_msg = "Error al procesar el pago. Intente nuevamente."
            return render(
                request,
                "portal/pago.html",
                {"reserva": reserva, "error": error_msg[:MAX_CARACTERES_ERROR_USUARIO]},
            )

    return render(request, "portal/pago.html", {"reserva": reserva})


def recuperar_password(request: HttpRequest) -> HttpResponse:
    """Recuperación de contraseña mediante token firmado de Django.

    Correcciones:
        - B403 / B301 eliminados: ``import pickle`` y ``pickle.loads()``
          reemplazados por ``django.core.signing.loads()`` con
          ``max_age=EXPIRACION_TOKEN_JWT_SEGUNDOS`` (Control A.8.28 / A.8.5).
    """
    if request.method == "POST":
        token_b64 = request.POST.get("token", "")
        if token_b64:
            try:
                data = signing.loads(
                    token_b64,
                    max_age=EXPIRACION_TOKEN_JWT_SEGUNDOS,
                )
                registrar_log_seguro(
                    f"Token de recuperación validado correctamente."
                )
                return HttpResponse("Token procesado correctamente.")
            except signing.BadSignature:
                registrar_log_seguro(
                    "Intento de recuperación con token inválido o expirado."
                )
                error_msg = "Token inválido o expirado."
                return render(
                    request,
                    "portal/recuperar.html",
                    {"error": error_msg[:MAX_CARACTERES_ERROR_USUARIO]},
                )

    return render(request, "portal/recuperar.html")
