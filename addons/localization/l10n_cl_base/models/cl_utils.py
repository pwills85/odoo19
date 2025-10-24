# -*- coding: utf-8 -*-
from odoo import models, api


class ClUtils(models.AbstractModel):
    """
    Utilidades comunes para localización chilena.

    Proporciona métodos helper compartidos entre módulos chilenos.
    """
    _name = 'cl.utils'
    _description = 'Chilean Utilities'

    @api.model
    def format_rut(self, rut):
        """
        Formatea RUT chileno a formato estándar XX.XXX.XXX-X

        Args:
            rut (str): RUT sin formato (ej: "123456789")

        Returns:
            str: RUT formateado (ej: "12.345.678-9")
        """
        if not rut:
            return ''

        # Limpiar RUT
        rut = str(rut).replace('.', '').replace('-', '').upper()

        if len(rut) < 2:
            return rut

        # Separar dígito verificador
        rut_num = rut[:-1]
        dv = rut[-1]

        # Formatear con puntos
        formatted = ''
        for i, digit in enumerate(reversed(rut_num)):
            if i > 0 and i % 3 == 0:
                formatted = '.' + formatted
            formatted = digit + formatted

        return f"{formatted}-{dv}"

    @api.model
    def validate_rut(self, rut):
        """
        Valida RUT chileno.

        Args:
            rut (str): RUT a validar

        Returns:
            bool: True si es válido, False en caso contrario
        """
        if not rut:
            return False

        # Limpiar RUT
        rut = str(rut).replace('.', '').replace('-', '').upper()

        if len(rut) < 2:
            return False

        # Separar dígito verificador
        rut_num = rut[:-1]
        dv = rut[-1]

        # Calcular dígito verificador
        try:
            rut_int = int(rut_num)
        except ValueError:
            return False

        multiplicador = 2
        suma = 0

        for digit in reversed(str(rut_int)):
            suma += int(digit) * multiplicador
            multiplicador += 1
            if multiplicador > 7:
                multiplicador = 2

        resto = 11 - (suma % 11)

        if resto == 11:
            dv_calculado = '0'
        elif resto == 10:
            dv_calculado = 'K'
        else:
            dv_calculado = str(resto)

        return dv == dv_calculado

    @api.model
    def clean_rut(self, rut):
        """
        Limpia RUT eliminando puntos y guión.

        Args:
            rut (str): RUT a limpiar

        Returns:
            str: RUT limpio (solo números y K)
        """
        if not rut:
            return ''

        return str(rut).replace('.', '').replace('-', '').upper()
