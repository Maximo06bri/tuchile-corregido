"""
Modelos de datos del portal de Turismo TUCHILE.

Controles ISO/IEC 27001:2022 aplicados:
    - A.8.11 : Enmascaramiento de datos – ``numero_tarjeta_masked`` almacena
               únicamente los últimos 4 dígitos de la tarjeta de crédito.
               Se elimina por completo el campo ``codigo_cvv`` (PCI-DSS).
    - A.8.33 : Información de prueba – se evita almacenar datos sensibles
               reales en la base de datos.
"""

from django.db import models
from django.contrib.auth.models import User


class Cabaña(models.Model):
    """Modelo que representa una cabaña disponible para reserva."""

    nombre = models.CharField(max_length=100)
    zona = models.CharField(max_length=50)  # 'Costera' o 'Sur'
    precio_noche = models.DecimalField(max_digits=10, decimal_places=2)
    capacidad = models.IntegerField()

    class Meta:
        verbose_name = "Cabaña"
        verbose_name_plural = "Cabañas"

    def __str__(self) -> str:
        return self.nombre


class Reserva(models.Model):
    """Modelo que representa una reserva de cabaña."""

    usuario = models.ForeignKey(User, on_delete=models.CASCADE)
    cabaña = models.ForeignKey(Cabaña, on_delete=models.CASCADE)
    fecha_checkin = models.DateField()
    fecha_checkout = models.DateField()
    total_pago = models.DecimalField(max_digits=10, decimal_places=2)
    pagado = models.BooleanField(default=False)
    comentario_cliente = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = "Reserva"
        verbose_name_plural = "Reservas"

    def __str__(self) -> str:
        return f"Reserva #{self.pk} – {self.usuario.username}"


class PagoReserva(models.Model):
    """Modelo de pago asociado a una reserva.

    Cumplimiento:
        - Control A.8.11: ``numero_tarjeta_masked`` almacena solo los
          últimos 4 dígitos (p. ej. ``****1234``).
        - PCI-DSS: se elimina el campo ``codigo_cvv``; el CVV **nunca**
          debe persistirse en base de datos.
    """

    reserva = models.ForeignKey(Reserva, on_delete=models.CASCADE)
    monto = models.DecimalField(max_digits=10, decimal_places=2)
    numero_tarjeta_masked = models.CharField(
        max_length=8,
        help_text="Últimos 4 dígitos enmascarados, p. ej. ****1234",
    )
    fecha_expiracion = models.CharField(max_length=7)
    fecha_transaccion = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Pago de Reserva"
        verbose_name_plural = "Pagos de Reservas"

    def __str__(self) -> str:
        return f"Pago #{self.pk} – {self.numero_tarjeta_masked}"
