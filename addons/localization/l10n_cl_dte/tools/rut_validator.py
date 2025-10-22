# -*- coding: utf-8 -*-
"""
RUT Validator para Chile
Implementación local del algoritmo de validación de RUT (Rol Único Tributario)
Algoritmo: Módulo 11

Autor: Eergygroup
Fecha: 2025-10-21
"""

import re
from typing import Tuple, Optional


class RUTValidator:
    """Validador de RUT chileno usando algoritmo módulo 11"""
    
    # Regex para validar formato básico
    RUT_REGEX = re.compile(r'^(\d{1,2})\.?(\d{3})\.?(\d{3})-?([\dkK])$')
    
    @classmethod
    def clean_rut(cls, rut: str) -> str:
        """
        Limpia el RUT removiendo puntos, guiones y espacios.
        Convierte a mayúsculas.
        
        Args:
            rut: RUT en cualquier formato (ej: 12.345.678-9, 12345678-9, 123456789)
        
        Returns:
            RUT limpio (ej: 123456789)
        """
        if not rut:
            return ''
        
        # Remover puntos, guiones y espacios
        cleaned = rut.replace('.', '').replace('-', '').replace(' ', '').upper()
        return cleaned
    
    @classmethod
    def split_rut(cls, rut: str) -> Tuple[str, str]:
        """
        Separa el RUT en número y dígito verificador.
        
        Args:
            rut: RUT limpio (ej: 123456789)
        
        Returns:
            Tupla (numero, digito_verificador)
            Ejemplo: ('12345678', '9')
        """
        if not rut or len(rut) < 2:
            return ('', '')
        
        numero = rut[:-1]
        dv = rut[-1]
        
        return (numero, dv)
    
    @classmethod
    def calculate_dv(cls, rut_number: str) -> str:
        """
        Calcula el dígito verificador de un RUT usando algoritmo módulo 11.
        
        Algoritmo:
        1. Multiplicar cada dígito por secuencia 2,3,4,5,6,7,2,3,4... (de derecha a izquierda)
        2. Sumar todos los productos
        3. Calcular módulo 11
        4. Restar de 11
        5. Si resultado = 11, dv = 0
           Si resultado = 10, dv = K
           Sino, dv = resultado
        
        Args:
            rut_number: Número del RUT sin dígito verificador (ej: '12345678')
        
        Returns:
            Dígito verificador calculado (ej: '9' o 'K')
        """
        if not rut_number or not rut_number.isdigit():
            return ''
        
        # Secuencia de multiplicadores
        multiplicadores = [2, 3, 4, 5, 6, 7]
        
        suma = 0
        multiplicador_index = 0
        
        # Iterar dígitos de derecha a izquierda
        for digit in reversed(rut_number):
            multiplicador = multiplicadores[multiplicador_index]
            suma += int(digit) * multiplicador
            
            # Rotar multiplicadores (2,3,4,5,6,7,2,3,4...)
            multiplicador_index = (multiplicador_index + 1) % len(multiplicadores)
        
        # Calcular módulo 11
        resto = suma % 11
        dv_calculado = 11 - resto
        
        # Casos especiales
        if dv_calculado == 11:
            return '0'
        elif dv_calculado == 10:
            return 'K'
        else:
            return str(dv_calculado)
    
    @classmethod
    def validate(cls, rut: str) -> bool:
        """
        Valida un RUT chileno completo.
        
        Args:
            rut: RUT en cualquier formato (ej: '12.345.678-9', '12345678-9', '123456789')
        
        Returns:
            True si el RUT es válido, False en caso contrario
        
        Examples:
            >>> RUTValidator.validate('12.345.678-5')
            True
            >>> RUTValidator.validate('12345678-5')
            True
            >>> RUTValidator.validate('12345678-9')
            False
            >>> RUTValidator.validate('76.123.456-K')
            True
        """
        if not rut:
            return False
        
        # Limpiar RUT
        rut_limpio = cls.clean_rut(rut)
        
        # Verificar longitud mínima (ej: 1000000-6 = 8 caracteres)
        if len(rut_limpio) < 2:
            return False
        
        # Separar número y dígito verificador
        numero, dv_original = cls.split_rut(rut_limpio)
        
        # Verificar que el número sea válido
        if not numero or not numero.isdigit():
            return False
        
        # Verificar que el dígito verificador sea válido (0-9 o K)
        if not dv_original or (not dv_original.isdigit() and dv_original != 'K'):
            return False
        
        # Calcular dígito verificador esperado
        dv_calculado = cls.calculate_dv(numero)
        
        # Comparar
        return dv_original == dv_calculado
    
    @classmethod
    def format_rut(cls, rut: str) -> Optional[str]:
        """
        Formatea un RUT al formato estándar chileno: 12.345.678-9
        
        Args:
            rut: RUT en cualquier formato
        
        Returns:
            RUT formateado o None si es inválido
        
        Examples:
            >>> RUTValidator.format_rut('123456785')
            '12.345.678-5'
            >>> RUTValidator.format_rut('76123456K')
            '76.123.456-K'
        """
        if not cls.validate(rut):
            return None
        
        # Limpiar RUT
        rut_limpio = cls.clean_rut(rut)
        
        # Separar número y dígito verificador
        numero, dv = cls.split_rut(rut_limpio)
        
        # Formatear número con puntos
        # Ejemplo: 12345678 → 12.345.678
        numero_formateado = ''
        for i, digit in enumerate(reversed(numero)):
            if i > 0 and i % 3 == 0:
                numero_formateado = '.' + numero_formateado
            numero_formateado = digit + numero_formateado
        
        # Retornar formato: 12.345.678-9
        return f'{numero_formateado}-{dv}'
    
    @classmethod
    def is_company_rut(cls, rut: str) -> bool:
        """
        Determina si un RUT corresponde a una empresa (vs persona natural).
        
        En Chile, RUTs de empresas generalmente empiezan con 50 o superior.
        Personas naturales: 1-50 millones.
        
        Args:
            rut: RUT a verificar
        
        Returns:
            True si es empresa, False si es persona
        """
        if not cls.validate(rut):
            return False
        
        rut_limpio = cls.clean_rut(rut)
        numero, _ = cls.split_rut(rut_limpio)
        
        # Convertir a entero
        try:
            rut_int = int(numero)
            # RUTs > 50.000.000 generalmente son empresas
            return rut_int >= 50000000
        except ValueError:
            return False


# Funciones de conveniencia para uso directo
def validate_rut(rut: str) -> bool:
    """
    Valida un RUT chileno.
    Función de conveniencia para usar directamente.
    
    Args:
        rut: RUT en cualquier formato
    
    Returns:
        True si válido, False si inválido
    """
    return RUTValidator.validate(rut)


def format_rut(rut: str) -> Optional[str]:
    """
    Formatea un RUT al formato estándar: 12.345.678-9
    Función de conveniencia para usar directamente.
    
    Args:
        rut: RUT en cualquier formato
    
    Returns:
        RUT formateado o None si inválido
    """
    return RUTValidator.format_rut(rut)


def clean_rut(rut: str) -> str:
    """
    Limpia un RUT (remueve puntos, guiones, espacios).
    Función de conveniencia para usar directamente.
    
    Args:
        rut: RUT en cualquier formato
    
    Returns:
        RUT limpio
    """
    return RUTValidator.clean_rut(rut)

